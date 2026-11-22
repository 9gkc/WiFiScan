"""Passive Wi-Fi beacon discovery for networks you are authorized to assess.

The scanner observes beacon frames only. It does not deauthenticate clients,
crack credentials, inject traffic, or change the interface mode automatically.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from threading import Event, Lock, Thread
from typing import Any, Iterable

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff

DEFAULT_INTERFACE = "wlan0mon"
DEFAULT_CHANNELS = tuple(range(1, 15))


@dataclass(frozen=True)
class NetworkRecord:
    bssid: str
    ssid: str
    channel: str
    signal_dbm: str
    encryption: str


class NetworkStore:
    """Thread-safe in-memory store for the latest beacon observation per BSSID."""

    def __init__(self) -> None:
        self._records: dict[str, NetworkRecord] = {}
        self._lock = Lock()

    def upsert(self, record: NetworkRecord) -> None:
        with self._lock:
            self._records[record.bssid] = record

    def snapshot(self) -> list[NetworkRecord]:
        with self._lock:
            return sorted(self._records.values(), key=lambda item: (item.ssid.casefold(), item.bssid))

    def encryption_summary(self) -> dict[str, int]:
        with self._lock:
            return dict(Counter(record.encryption for record in self._records.values()))


def decode_ssid(value: Any) -> str:
    """Decode an SSID without allowing malformed bytes to stop the sniffer."""

    if not value:
        return "<Hidden SSID>"
    if isinstance(value, bytes):
        decoded = value.decode("utf-8", errors="replace").strip()
    else:
        decoded = str(value).strip()
    return decoded or "<Hidden SSID>"


def format_signal(packet: Any) -> str:
    value = getattr(packet, "dBm_AntSignal", None)
    return str(value) if isinstance(value, (int, float)) else "N/A"


def classify_encryption(crypto: Iterable[Any] | None) -> str:
    values = {str(value).upper() for value in (crypto or set())}

    if "WPA3" in values or any("SAE" in value for value in values):
        return "WPA3"
    if "WPA2" in values and ("PSK" in values or "ENTERPRISE" in values or "802.1X" in values):
        if "PSK" in values:
            return "WPA2-PSK"
        return "WPA2-Enterprise"
    if "WPA" in values and "PSK" in values:
        return "WPA-PSK"
    if "WEP" in values:
        return "WEP (Insecure)"
    if "OPN" in values or "NONE" in values:
        return "Open (No Encryption)"
    if not values:
        return "Unknown"
    return ", ".join(sorted(values))


def beacon_record(packet: Any) -> NetworkRecord | None:
    if not packet.haslayer(Dot11Beacon) or not packet.haslayer(Dot11):
        return None

    bssid = str(packet[Dot11].addr2 or "").upper()
    if not bssid:
        return None

    ssid = decode_ssid(getattr(packet[Dot11Elt], "info", b""))
    try:
        stats = packet[Dot11Beacon].network_stats()
    except Exception:
        stats = {}

    channel = stats.get("channel", "N/A")
    crypto = stats.get("crypto", set())
    return NetworkRecord(
        bssid=bssid,
        ssid=ssid,
        channel=str(channel),
        signal_dbm=format_signal(packet),
        encryption=classify_encryption(crypto),
    )


def callback(packet: Any, store: NetworkStore) -> None:
    record = beacon_record(packet)
    if record is not None:
        store.upsert(record)


def change_channel(
    interface: str,
    channels: tuple[int, ...],
    stop_event: Event,
    interval: float,
) -> None:
    """Hop channels with fixed subprocess arguments; never invoke a shell."""

    if shutil.which("iwconfig") is None:
        print("[!] iwconfig was not found; channel hopping is disabled.", file=sys.stderr)
        return

    index = 0
    while not stop_event.is_set():
        channel = channels[index % len(channels)]
        try:
            subprocess.run(
                ["iwconfig", interface, "channel", str(channel)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            print(f"[!] Could not change to channel {channel}: {error}", file=sys.stderr)
            return
        index += 1
        stop_event.wait(interval)


def print_networks(store: NetworkStore, stop_event: Event, interval: float) -> None:
    """Render a stable, readable table without shelling out to clear(1)."""

    while not stop_event.is_set():
        records = store.snapshot()
        print("\033[2J\033[H", end="")
        print("[*] Scanning for Wi-Fi beacon networks (Ctrl+C to stop)\n")
        print(f"{'BSSID':<19} {'SSID':<32} {'Channel':<8} {'Signal':<8} Encryption")
        print("-" * 90)
        if records:
            for item in records:
                print(
                    f"{item.bssid:<19} {item.ssid[:31]:<32} "
                    f"{item.channel:<8} {item.signal_dbm:<8} {item.encryption}"
                )
        else:
            print("No beacon networks observed yet.")
        stop_event.wait(interval)


def print_summary(store: NetworkStore) -> None:
    records = store.snapshot()
    summary = store.encryption_summary()
    print("\n[*] Scan summary")
    print(f"    Networks observed: {len(records)}")
    if summary:
        print("    Encryption breakdown:")
        for name, count in sorted(summary.items(), key=lambda item: (-item[1], item[0])):
            print(f"      - {name}: {count}")


def parse_channels(value: str) -> tuple[int, ...]:
    channels: list[int] = []
    for raw_channel in value.split(","):
        try:
            channel = int(raw_channel.strip())
        except ValueError as error:
            raise argparse.ArgumentTypeError("Channels must be comma-separated integers.") from error
        if not 1 <= channel <= 196:
            raise argparse.ArgumentTypeError("Each channel must be between 1 and 196.")
        channels.append(channel)
    if not channels:
        raise argparse.ArgumentTypeError("At least one channel is required.")
    return tuple(dict.fromkeys(channels))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Passively list nearby Wi-Fi beacon networks.")
    parser.add_argument("--interface", default=DEFAULT_INTERFACE, help="Monitor-mode interface to observe.")
    parser.add_argument("--channels", type=parse_channels, default=DEFAULT_CHANNELS, help="Channels, e.g. 1,6,11.")
    parser.add_argument("--channel-interval", type=float, default=0.5, help="Seconds between channel changes.")
    parser.add_argument("--refresh-interval", type=float, default=1.0, help="Seconds between table refreshes.")
    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.channel_interval <= 0 or args.refresh_interval <= 0:
        parser.error("Intervals must be greater than zero.")
    try:
        socket.if_nametoindex(args.interface)
    except OSError as error:
        parser.error(f"Interface '{args.interface}' is not available: {error}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(args, parser)

    if os.geteuid() != 0:
        print("[!] Root privileges are required for passive monitor-mode capture.", file=sys.stderr)
        return 1

    stop_event = Event()
    store = NetworkStore()

    def stop(_signal: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    print(f"[*] Interface: {args.interface}")
    print("[*] Use this tool only on networks you own or are authorized to assess.")
    print("[*] Monitor mode must be configured separately; no interface mode changes are performed.")

    channel_thread = Thread(
        target=change_channel,
        args=(args.interface, args.channels, stop_event, args.channel_interval),
        name="channel-hopper",
        daemon=True,
    )
    display_thread = Thread(
        target=print_networks,
        args=(store, stop_event, args.refresh_interval),
        name="network-display",
        daemon=True,
    )
    channel_thread.start()
    display_thread.start()

    try:
        while not stop_event.is_set():
            sniff(
                prn=lambda packet: callback(packet, store),
                iface=args.interface,
                store=False,
                timeout=1,
            )
    except OSError as error:
        print(f"[!] Packet capture failed: {error}", file=sys.stderr)
        return 1
    finally:
        stop_event.set()
        channel_thread.join(timeout=2)
        display_thread.join(timeout=2)
        print_summary(store)
        print("[*] Scanning stopped.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

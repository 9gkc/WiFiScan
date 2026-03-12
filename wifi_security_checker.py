#!/usr/bin/env python3

from scapy.all import *
from threading import Thread
import pandas
import time
import os

# Set up the network interface for monitor mode
# This part needs to be run manually before the script or included in the script with root privileges
# sudo ifconfig wlan0 down
# sudo iwconfig wlan0 mode monitor
# sudo ifconfig wlan0 up

# Wireless interface name (you might need to change it to wlan0mon or similar)
interface = "wlan0mon"

# DataFrame to store network information
networks = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "Signal (dBm)", "Encryption"]) # Add Encryption column
networks.set_index("BSSID", inplace=True)

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "<Hidden SSID>"
        
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")

        # More detailed encryption type analysis
        encryption_type = "Unknown"
        if crypto:
            if "WPA3" in crypto:
                encryption_type = "WPA3"
            elif "WPA2" in crypto and "PSK" in crypto:
                encryption_type = "WPA2/PSK"
            elif "WPA" in crypto and "PSK" in crypto:
                encryption_type = "WPA/PSK"
            elif "WEP" in crypto:
                encryption_type = "WEP"
            elif "OPN" in crypto or "None" in crypto:
                encryption_type = "Open (No Encryption)"
            else:
                encryption_type = ", ".join(crypto) # Display all detected encryption types

        networks.loc[bssid] = (ssid, channel, dbm_signal, encryption_type)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # Switch between channels 1 to 14 every 0.5 seconds
        ch = ch % 14 + 1
        time.sleep(0.5)

def print_networks():
    while True:
        os.system("clear")
        print("\n[*] Scanning for Wi-Fi Networks...")
        print(networks)
        time.sleep(1) # Update screen every second

if __name__ == "__main__":
    # Ensure the user has root privileges
    if os.geteuid() != 0:
        print("Please run the script with root privileges (sudo python3 wifi_security_checker.py)")
        exit(1)

    print("\n[!] Please ensure your wireless network interface (e.g., wlan0) is in Monitor Mode.")
    print(f"[!] Interface used: {interface}")
    print("[!] You can use the following commands to set monitor mode (replace wlan0 with your interface name):")
    print("    sudo ifconfig wlan0 down")
    print("    sudo iwconfig wlan0 mode monitor")
    print("    sudo ifconfig wlan0 up")
    print("\n[!] Press Ctrl+C to stop scanning.")
    time.sleep(5)

    # Start channel hopping in a separate thread
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # Start displaying networks in a separate thread
    network_printer = Thread(target=print_networks)
    network_printer.daemon = True
    network_printer.start()

    # Start sniffing process
    try:
        sniff(prn=callback, iface=interface, store=False)
    except KeyboardInterrupt:
        print("\n[*] Scanning stopped.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
    finally:
        # You can add code here to revert the interface to Managed Mode
        print("[*] Program finished.")

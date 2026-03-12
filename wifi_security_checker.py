#!/usr/bin/env python3

from scapy.all import *
from threading import Thread
import pandas
import time
import os

# إعداد واجهة الشبكة لوضع المراقبة (Monitor Mode)
# يجب تشغيل هذا الجزء يدوياً قبل تشغيل السكريبت أو تضمينه في السكريبت مع صلاحيات الجذر
# sudo ifconfig wlan0 down
# sudo iwconfig wlan0 mode monitor
# sudo ifconfig wlan0 up

# اسم الواجهة اللاسلكية (قد تحتاج إلى تغييرها إلى wlan0mon أو ما شابه)
interface = "wlan0mon"

# DataFrame لتخزين معلومات الشبكات
networks = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "Signal (dBm)", "Encryption"]) # إضافة عمود التشفير
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

        # تحليل نوع التشفير بشكل أكثر تفصيلاً
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
                encryption_type = ", ".join(crypto) # لعرض جميع أنواع التشفير المكتشفة

        networks.loc[bssid] = (ssid, channel, dbm_signal, encryption_type)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # التبديل بين القنوات من 1 إلى 14 كل 0.5 ثانية
        ch = ch % 14 + 1
        time.sleep(0.5)

def print_networks():
    while True:
        os.system("clear")
        print("\n[*] Scanning for Wi-Fi Networks...")
        print(networks)
        time.sleep(1) # تحديث الشاشة كل ثانية

if __name__ == "__main__":
    # التأكد من أن المستخدم لديه صلاحيات الجذر
    if os.geteuid() != 0:
        print("يرجى تشغيل السكريبت بصلاحيات الجذر (sudo python3 wifi_security_checker.py)")
        exit(1)

    print("\n[!] يرجى التأكد من أن واجهة الشبكة اللاسلكية (مثل wlan0) في وضع المراقبة (Monitor Mode).")
    print(f"[!] الواجهة المستخدمة: {interface}")
    print("[!] يمكنك استخدام الأوامر التالية لضبط وضع المراقبة (استبدل wlan0 باسم واجهتك):")
    print("    sudo ifconfig wlan0 down")
    print("    sudo iwconfig wlan0 mode monitor")
    print("    sudo ifconfig wlan0 up")
    print("\n[!] اضغط Ctrl+C لإيقاف الفحص.")
    time.sleep(5)

    # بدء تبديل القنوات في خلفية منفصلة
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # بدء عرض الشبكات في خلفية منفصلة
    network_printer = Thread(target=print_networks)
    network_printer.daemon = True
    network_printer.start()

    # بدء عملية الشم (sniffing)
    try:
        sniff(prn=callback, iface=interface, store=False)
    except KeyboardInterrupt:
        print("\n[*] تم إيقاف الفحص.")
    except Exception as e:
        print(f"\n[!] حدث خطأ: {e}")
    finally:
        # يمكنك إضافة كود لإعادة الواجهة إلى الوضع المدار (Managed Mode) هنا
        print("[*] انتهى البرنامج.")

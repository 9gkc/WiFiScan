# Wi-Fi Security Checker

<div align="center">
  <img src="https://img.shields.io/badge/Language-Python-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT">
  <img src="https://img.shields.io/github/last-commit/9gkc/WiFiScan?style=for-the-badge&label=Last%20Update&color=58A6FF" alt="Last Update">
  <img src="https://img.shields.io/github/stars/9gkc/WiFiScan?style=for-the-badge&color=58A6FF" alt="GitHub Stars">
  <img src="https://img.shields.io/github/forks/9gkc/WiFiScan?style=for-the-badge&color=58A6FF" alt="GitHub Forks">
</div>


## Overview

This tool is a simple yet effective Python script that utilizes the `Scapy` library to scan nearby Wi-Fi networks and identify their essential information, including the encryption type used. The tool is designed to help cybersecurity students and security enthusiasts understand different encryption types, their strengths and weaknesses, and to raise security awareness about the importance of securing wireless networks.

## Features

*   **Wi-Fi Network Scanning:** Discovers nearby wireless Access Points.
*   **Network Information Display:** Shows the Network ID (SSID), MAC address (BSSID), Channel, and Signal Strength (dBm).
*   **Encryption Type Identification:** Analyzes and identifies the encryption type used for each network (e.g., WPA3, WPA2/PSK, WPA/PSK, WEP, or Open networks).
*   **Monitor Mode Requirement:** Requires the wireless network interface to be placed in monitor mode separately before capture.
*   **Automatic Channel Hopping:** Switches between selected channels without invoking a shell.
*   **Defensive Scope:** Observes beacon frames only; it does not deauthenticate clients, inject traffic, crack credentials, or change interface mode.

## Requirements

*   **Unix-based OS:** Such as Kali Linux or Ubuntu (recommended).
*   **Python 3.x**
*   **Scapy Library:** Used for passive beacon capture.
*   **`iwconfig` tool:** Optional; used only for channel hopping when available.
*   **Root Privileges:** Required by the operating system for monitor-mode packet capture.

Install the Python dependency with:

```bash
python3 -m pip install -r requirements.txt
```

## How to Use

1.  **Set Wireless Interface to Monitor Mode:**

    Before running the script, you must put your wireless network interface into monitor mode. Replace `wlan0` with your wireless interface name (you can find it using `iwconfig`):

    ```bash
    sudo ifconfig wlan0 down
    sudo iwconfig wlan0 mode monitor
    sudo ifconfig wlan0 up
    ```

    *(Note: You might need to change `wlan0` to `wlan0mon` or another name depending on your system.)*

2.  **Run the Tool:**

    Execute the script with root privileges:

    ```bash
    sudo python3 wifi_security_checker.py --interface wlan0mon --channels 1,6,11
```

The interface must already be in monitor mode. The tool will display beacon networks in a continuously updated table. Press `Ctrl+C` to stop the scan. You can tune the refresh and hopping intervals with `--refresh-interval` and `--channel-interval`. The tool validates that the interface exists and never changes monitor mode automatically.

## Encryption Type Analysis

This tool helps you identify the encryption type for each network, allowing you to assess its security level:

| Encryption Type | Description | Security Level | Notes |
| :-------------- | :---------- | :------------- | :---- |
| **Open (No Encryption)** | No encryption at all. Data is transmitted in plain text. | **Very Weak** | Avoid connecting to these networks for sensitive data. |
| **WEP** | (Wired Equivalent Privacy) An old and very weak protocol, easily crackable. | **Very Weak** | Never recommended for use. |
| **WPA/PSK** | (Wi-Fi Protected Access / Pre-Shared Key) An improvement over WEP, but still vulnerable to some attacks. | **Medium** | Better than WEP, but WPA2/WPA3 are significantly better. |
| **WPA2/PSK** | (Wi-Fi Protected Access II / Pre-Shared Key) The most common standard, provides strong encryption (AES). | **Good** | Secure for most home and small business uses. |
| **WPA3** | (Wi-Fi Protected Access III) The latest and strongest encryption standard, offering enhanced protection against brute-force attacks. | **Excellent** | Highly recommended if your router supports it. |

## Contribution

Contributions to improve this tool are welcome! If you have any suggestions or enhancements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Disclaimer

This tool is intended for educational and defensive research on networks you own or are explicitly authorized to assess. It observes public beacon frames only and must not be used for disruption, credential capture, unauthorized access, or traffic injection. The author is not responsible for misuse.

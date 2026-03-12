# Wi-Fi Security Checker

## Overview

This tool is a simple yet effective Python script that utilizes the `Scapy` library to scan nearby Wi-Fi networks and identify their essential information, including the encryption type used. The tool is designed to help cybersecurity students and security enthusiasts understand different encryption types, their strengths and weaknesses, and to raise security awareness about the importance of securing wireless networks.

## Features

*   **Wi-Fi Network Scanning:** Discovers nearby wireless Access Points.
*   **Network Information Display:** Shows the Network ID (SSID), MAC address (BSSID), Channel, and Signal Strength (dBm).
*   **Encryption Type Identification:** Analyzes and identifies the encryption type used for each network (e.g., WPA3, WPA2/PSK, WPA/PSK, WEP, or Open networks).
*   **Monitor Mode Requirement:** Requires the wireless network interface to be in monitor mode to capture data packets.
*   **Automatic Channel Hopping:** Automatically switches between different Wi-Fi channels to ensure broader network discovery.

## Requirements

*   **Unix-based OS:** Such as Kali Linux or Ubuntu (recommended).
*   **Python 3.x**
*   **Scapy Library:** A powerful library for network packet manipulation.
*   **Pandas Library:** Used for organized data display.
*   **`iwconfig` and `ifconfig` tools:** For managing the wireless network interface and monitor mode.
*   **Root Privileges:** Required to run the script and change the network interface mode.

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
    sudo python3 wifi_security_checker.py
    ```

    The tool will start scanning for networks and display them in a continuously updated table. Press `Ctrl+C` to stop the scan.

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

This tool is intended for educational and research purposes only. Its use for any illegal or harmful activities is solely at the user's own risk. The author is not responsible for any misuse of this tool.

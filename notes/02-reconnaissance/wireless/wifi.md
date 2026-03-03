% Filename: 02-reconnaissance/wireless/wifi.md
% Display name: WiFi Reconnaissance
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance), TA0006 (Credential Access), TA0007 (Discovery)
% ATT&CK Techniques: T1595 (Active Scanning), T1040 (Network Sniffing)
% Authors: @TristanInSec

# WiFi Reconnaissance

## Overview

WiFi reconnaissance discovers and maps 802.11 wireless networks within range — access points, clients, encryption types, channels, and signal strength. It is the first step before any wireless attack: rogue AP deployment, WPA handshake capture, or client deauthentication.

WiFi recon operates in two modes. Passive monitoring captures beacon frames and probe responses without transmitting — completely undetectable by the target. Active scanning sends probe requests to solicit responses from hidden networks. Both require a wireless adapter that supports monitor mode.

## ATT&CK Mapping

- **Tactics:** TA0043 - Reconnaissance, TA0006 - Credential Access, TA0007 - Discovery
- **Technique:** T1595 - Active Scanning
- **Technique:** T1040 - Network Sniffing

## Prerequisites

- Linux system (Kali recommended)
- Wireless adapter with monitor mode support (chipsets: Atheros AR9271, Realtek RTL8812AU/RTL8814AU)
- Root/sudo access (wireless tools require elevated privileges)
- `aircrack-ng` suite installed (`sudo apt install aircrack-ng`)

## Interface Preparation

Before scanning, the wireless adapter must be configured for monitor mode.

### Check Wireless Interfaces

```bash
# List wireless interfaces
iw dev
```

Output shows interface name (`wlan0`), type (`managed` for normal, `monitor` for capture), channel, and MAC address.

```bash
# Show wireless interface details
iwconfig
```

`iwconfig` shows ESSID (if connected), mode, frequency, and link quality.

### Enable Monitor Mode

```bash
# Aircrack-ng
# https://www.aircrack-ng.org/
# Kill processes that may interfere with monitor mode
airmon-ng check kill

# Enable monitor mode
airmon-ng start wlan0
```

This creates a new monitor interface, typically named `wlan0mon`. The `check kill` step stops NetworkManager and wpa_supplicant which would otherwise interfere with raw frame capture.

```bash
# Verify monitor mode is active
iw dev
```

The interface type should now show `monitor` instead of `managed`.

```bash
# Aircrack-ng
# https://www.aircrack-ng.org/
# Restore managed mode when done
airmon-ng stop wlan0mon
```

### Manual Monitor Mode (Without airmon-ng)

```bash
# Alternative: set monitor mode manually with iw
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up
```

```bash
# Restore managed mode
ip link set wlan0 down
iw dev wlan0 set type managed
ip link set wlan0 up
```

## Network Discovery

### Airodump-ng

Airodump-ng is the primary WiFi reconnaissance tool. It captures 802.11 frames in monitor mode and displays all detected access points and associated clients in real time.

```bash
# Aircrack-ng
# https://www.aircrack-ng.org/
# Scan all 2.4GHz channels (default)
airodump-ng wlan0mon
```

### Airodump-ng Output Columns

The upper section displays access points:

| Column | Description |
|--------|-------------|
| BSSID | MAC address of the access point |
| PWR | Signal strength (higher negative = weaker: -30 is strong, -80 is weak) |
| Beacons | Number of beacon frames received |
| #Data | Number of data frames captured |
| CH | Channel the AP operates on |
| MB | Maximum speed supported (e.g., 54e for 802.11g, 270 for 802.11n) |
| ENC | Encryption type: OPN (open), WEP, WPA, WPA2, WPA3 |
| CIPHER | Cipher in use: CCMP, TKIP, WEP |
| AUTH | Authentication method: PSK (pre-shared key), MGT (802.1X/enterprise), OPN |
| ESSID | Network name (blank if hidden/cloaked) |

The lower section shows detected clients and which AP they are associated with.

### Targeted Scanning

```bash
# Aircrack-ng
# https://www.aircrack-ng.org/
# Target a specific AP on a specific channel
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon

# Scan both 2.4GHz and 5GHz bands
airodump-ng --band abg wlan0mon

# Save capture to file (creates .cap packet capture and .csv summary)
airodump-ng -w capture_output wlan0mon

# Target specific AP and save capture
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w target_capture wlan0mon
```

The `--band` flag accepts: `a` (5GHz), `b` (2.4GHz), `g` (2.4GHz). Use `abg` to scan all supported bands. The `-w` flag specifies the output file prefix.

### WPS Detection

WiFi Protected Setup (WPS) is a common weakness. APs with WPS enabled are vulnerable to brute-force PIN attacks.

```bash
# Reaver
# https://github.com/t6x/reaver-wps-fork-t6x
wash -i wlan0mon
```

Wash output shows WPS-enabled APs with their BSSID, channel, RSSI, WPS version, and lock status. A "Lck" (locked) column of "No" means the AP has not locked out WPS PIN attempts.

### iw Scanning (Without Monitor Mode)

For quick enumeration without entering monitor mode, `iw` can perform basic active scans from managed mode. Note: this transmits probe requests and is detectable.

```bash
# Active scan — sends probe requests
iw dev wlan0 scan | grep -E "BSS|SSID|freq|signal|RSN|WPA|WPS"
```

Filter the output with `grep` to focus on relevant fields. For structured parsing, `airodump-ng` in monitor mode provides cleaner output.

## Hidden Network Detection

Hidden SSIDs do not broadcast their name in beacon frames. Airodump-ng shows them as blank or `<length: N>` entries.

Hidden networks are revealed when:
- A client sends a probe request for the hidden SSID (passive — wait for traffic)
- A deauthentication forces a client to reconnect and re-probe (active — crosses into attack territory)

```bash
# Aircrack-ng
# https://www.aircrack-ng.org/
# Monitor for probe requests revealing hidden SSIDs
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon
```

Wait for a client to associate. When a client connects or reconnects, airodump-ng captures the SSID from the probe request/response exchange.

## Client Enumeration

Airodump-ng's lower output section shows wireless clients (stations). Key fields:

| Column | Description |
|--------|-------------|
| STATION | Client MAC address |
| BSSID | AP the client is associated with (or `(not associated)` for probing clients) |
| PWR | Client signal strength |
| Frames | Number of frames from this client |
| Probes | SSIDs the client is probing for |

The "Probes" column is valuable. Unassociated clients broadcast probe requests for networks they previously connected to — revealing their WiFi history (home networks, corporate SSIDs, hotel WiFi names). This information enables evil twin attacks.

## Encryption Identification

Quick reference for identifying encryption from airodump-ng output:

| ENC | CIPHER | AUTH | Meaning |
|-----|--------|------|---------|
| OPN | — | — | No encryption (open network) |
| WEP | WEP | — | WEP encryption (trivially breakable) |
| WPA | TKIP | PSK | WPA with TKIP (weak, deprecated) |
| WPA2 | CCMP | PSK | WPA2-Personal with AES (current standard) |
| WPA2 | CCMP | MGT | WPA2-Enterprise with 802.1X (RADIUS) |
| WPA3 | CCMP | SAE | WPA3 with Simultaneous Authentication of Equals |

Priority targets: OPN and WEP networks are immediately exploitable. WPA/WPA2-PSK networks require handshake capture and offline cracking. WPA2-Enterprise requires different attack vectors (evil twin with RADIUS impersonation). WPA3-SAE is resistant to offline dictionary attacks — however, WPA3 Transition Mode (mixed WPA2/WPA3) networks can be attacked via downgrade to WPA2-PSK.

## Post-Enumeration

With wireless network mapping complete:
- Identify weak encryption targets (OPN, WEP, WPA-TKIP)
- Note WPS-enabled APs for PIN brute-force
- Record client probe lists for evil twin targeting
- Map channel usage for rogue AP placement (choose uncrowded channels)
- Correlate BSSIDs with organizational MAC address prefixes (`macchanger -l` or OUI lookup)
- Feed target APs into handshake capture and cracking workflows

## References

### Official Documentation

- [Aircrack-ng Official Documentation](https://www.aircrack-ng.org/doku.php?id=Main)
- [Aircrack-ng airodump-ng Usage](https://www.aircrack-ng.org/doku.php?id=airodump-ng)
- [Aircrack-ng airmon-ng Usage](https://www.aircrack-ng.org/doku.php?id=airmon-ng)
- [Reaver WPS Fork (wash)](https://github.com/t6x/reaver-wps-fork-t6x)

### MITRE ATT&CK

- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)

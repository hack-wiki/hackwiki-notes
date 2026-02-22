% Filename: 02-reconnaissance/wireless/bluetooth.md
% Display name: Bluetooth Reconnaissance
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# Bluetooth Reconnaissance

## Overview

Bluetooth reconnaissance discovers devices within radio range, identifies their services, and maps the Bluetooth attack surface. Bluetooth operates in the 2.4 GHz ISM band and comes in two main variants: Bluetooth Classic (BR/EDR) for streaming, peripherals, and file transfer, and Bluetooth Low Energy (BLE) for IoT sensors, fitness trackers, smart locks, and beacons.

Discovery range depends on the device class: Class 1 devices reach up to 100 meters, Class 2 (most common — phones, laptops) reach roughly 10 meters, and Class 3 is limited to about 1 meter. BLE range varies from a few meters to 50+ meters depending on the device.

Bluetooth recon is relevant in physical security assessments, IoT engagements, and red team operations where proximity to the target is available.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Linux system with a Bluetooth adapter (most built-in laptop adapters work for basic scans)
- BlueZ stack installed (`sudo apt install bluez`)
- Root/sudo access
- For advanced BLE sniffing: Ubertooth One hardware

## Adapter Preparation

### Check Bluetooth Adapter

```bash
# Check if Bluetooth adapter is recognized
hciconfig -a
```

Output shows adapter address, type, bus, features, and current state (UP/DOWN). If no adapter appears, the driver may not be loaded.

```bash
# Bring adapter up if it's down
hciconfig hci0 up
```

### Using bluetoothctl

`bluetoothctl` is the current standard interface for BlueZ 5.x and is the recommended tool for Bluetooth interaction on modern Linux.

```bash
bluetoothctl
```

Inside the interactive shell:

```bash
# Show adapter information
show

# Power on the adapter
power on

# Set agent for pairing
agent on
default-agent
```

## Bluetooth Classic Discovery

### Device Scanning

Bluetooth Classic discovery sends inquiry packets and listens for responses. Devices must be in "discoverable" mode to respond — many are not, but some default to discoverable.

```bash
# bluetoothctl — scan for all device types
bluetoothctl
scan on
```

Discovered devices appear in real time with their MAC address, name, and device type. Press Ctrl+C or type `scan off` to stop.

```bash
# hcitool — inquiry scan for BR/EDR devices
# (legacy BlueZ tool, still available in Kali)
hcitool scan
```

Output shows MAC address and device name for each discovered device. The scan runs for approximately 10 seconds by default.

```bash
# Extended inquiry with device class information
hcitool inq
```

`inq` returns MAC address, clock offset, and device class. The class field encodes the device type (phone, computer, audio, peripheral, etc.).

### Ping a Bluetooth Device

```bash
# l2ping — verify a device is in range and responding
l2ping -c 3 AA:BB:CC:DD:EE:FF
```

The `-c` flag sets the number of pings. A response confirms the device is within range and has Bluetooth active, even if it is not in discoverable mode.

### Device Information

```bash
# bluetoothctl — get detailed device information
bluetoothctl
info AA:BB:CC:DD:EE:FF
```

Shows device name, alias, device class, paired/trusted/connected status, and advertised UUIDs (services).

```bash
# Resolve device name from MAC
hcitool name AA:BB:CC:DD:EE:FF
```

## Service Enumeration

### SDP (Service Discovery Protocol)

Once a device is discovered, SDP enumeration reveals which services it exposes — file transfer (OBEX), serial ports (SPP), audio streaming (A2DP), hands-free profiles, and more.

```bash
# sdptool — enumerate services on a remote device
sdptool browse AA:BB:CC:DD:EE:FF
```

Output lists each service with its name, protocol, channel, and service class UUID. Key services to note:

| Service | Security Relevance |
|---------|-------------------|
| OBEX Object Push | File transfer — may accept files without authentication |
| OBEX File Transfer | Directory browsing and file retrieval |
| Serial Port (SPP) | Raw serial access — common in IoT and embedded devices |
| Network Access Point (NAP) | Bluetooth networking — potential pivot point |
| Handsfree / Headset | Audio interception potential |
| Human Interface Device (HID) | Keyboard/mouse emulation — BadBT-style attacks |

```bash
# List services available on the local adapter
sdptool browse local
```

## BLE (Bluetooth Low Energy) Discovery

BLE devices advertise themselves continuously with advertisement packets. Unlike Classic Bluetooth, BLE devices do not require explicit discovery mode — they broadcast by default.

### BLE Scanning

```bash
# bluetoothctl — scan for BLE devices
bluetoothctl
scan on
```

`bluetoothctl` discovers both Classic and BLE devices. BLE devices typically show shorter names and advertise service UUIDs.

```bash
# hcitool — BLE-specific scan (legacy tool)
hcitool lescan
```

`lescan` shows BLE device MAC addresses and names as they are discovered. Press Ctrl+C to stop. Some devices advertise with a random MAC address that changes periodically — MAC address randomization was introduced in BLE 4.0, with enhanced privacy in BLE 4.2+.

### BLE Device Types

Common BLE devices found during assessments:

| Device Type | Examples | Recon Value |
|-------------|----------|-------------|
| Fitness trackers | Fitbit, Garmin | Employee identification, location tracking |
| Smart locks | August, Kwikset | Physical access control weaknesses |
| Beacons | iBeacon, Eddystone | Indoor positioning, proximity triggers |
| Medical devices | Glucose monitors, pacemaker controllers | Critical infrastructure |
| IoT sensors | Temperature, motion, door sensors | Building layout intelligence |
| Keyboards/mice | Bluetooth peripherals | KeySniffer/MouseJack potential |

### BLE GATT Enumeration

BLE services are organized using GATT (Generic Attribute Profile). Each device exposes services, and each service contains characteristics that hold data.

```bash
# bluetoothctl — connect and explore GATT services
bluetoothctl
connect AA:BB:CC:DD:EE:FF
```

Once connected, `bluetoothctl` can enumerate GATT services and characteristics. Type `help` after connecting to see available GATT commands for your BlueZ version. The GATT menu allows listing services, reading characteristics, and writing values.

Standard GATT service UUIDs (well-known):

| UUID | Service |
|------|---------|
| 0x1800 | Generic Access |
| 0x1801 | Generic Attribute |
| 0x180A | Device Information |
| 0x180F | Battery Service |
| 0x180D | Heart Rate |
| 0x1812 | Human Interface Device |

The Device Information service (0x180A) often exposes manufacturer name, model number, firmware version, and serial number — useful for identifying the exact device and researching known vulnerabilities.

## Advanced: Passive BLE Sniffing

Standard BLE scanning is active — the adapter sends scan requests. Passive BLE sniffing captures all BLE advertisement packets on a channel without transmitting. This requires specialized hardware.

**Ubertooth One** is the standard tool for raw Bluetooth sniffing. It can capture BLE advertisement packets, follow BLE connections, and capture Bluetooth Classic traffic.

> **Note:** Ubertooth commands are hardware-specific. Verify syntax with `ubertooth-btle -h` against your installed firmware version before use. Ubertooth firmware and tools are available at [https://github.com/greatscottgadgets/ubertooth](https://github.com/greatscottgadgets/ubertooth).

## Post-Enumeration

With Bluetooth reconnaissance complete:
- Map all discovered devices by type, name, and MAC address
- Note devices with exposed services (OBEX, SPP, NAP) for further testing
- Identify BLE devices with weak or no authentication on GATT characteristics
- Check for devices accepting connections without pairing
- Correlate device names with employees or departments (e.g., "John's iPhone", "HR-Printer")
- Research discovered device models and firmware versions for known CVEs

## References

### Official Documentation

- [BlueZ — Official Linux Bluetooth Stack (GitHub)](https://github.com/bluez/bluez)
- [Bluetooth SIG — Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/)
- [Ubertooth — Great Scott Gadgets](https://github.com/greatscottgadgets/ubertooth)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)

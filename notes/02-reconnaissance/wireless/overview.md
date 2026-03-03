% Filename: 02-reconnaissance/wireless/overview.md
% Display name: Wireless Reconnaissance
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Wireless Reconnaissance

## Overview

Wireless reconnaissance identifies and maps wireless networks, devices, and access points within range of the engagement area. Unlike wired network recon that queries remote services over the internet, wireless recon requires physical proximity — the attacker must be within radio range of the target infrastructure.

Wireless recon covers three primary domains: WiFi (802.11), Bluetooth (including BLE), and RFID/NFC. Each operates on different frequency bands, uses different protocols, and requires different hardware and tools.

This phase maps the wireless attack surface before any exploitation attempts: which networks exist, what encryption they use, which clients are connected, and what devices are discoverable. Findings from wireless recon feed directly into targeted attacks — rogue access point deployment, WPA handshake capture, Bluetooth impersonation, or RFID badge cloning.

## Topics in This Section

- [WiFi Reconnaissance](wifi.md) — Discovering and mapping 802.11 networks, access points, clients, and encryption types
- [Bluetooth Reconnaissance](bluetooth.md) — Discovering Bluetooth Classic and BLE devices, services, and characteristics
- [RFID/NFC Reconnaissance](rfid-nfc.md) — Identifying RFID/NFC card types, reading tag data, and understanding access control technologies

## General Approach

A typical wireless reconnaissance workflow:

1. **Hardware preparation** — confirm wireless adapters support monitor mode (WiFi) or raw access (Bluetooth/RFID), verify drivers are loaded
2. **Passive discovery** — listen for broadcast frames, beacons, and advertisements without transmitting
3. **Active discovery** — send probe requests, inquiry packets, or read commands to enumerate targets
4. **Mapping** — document SSIDs, BSSIDs, channels, encryption types, connected clients, discoverable devices, and card types
5. **Analysis** — identify weak encryption (WEP, open networks), misconfigured access points, discoverable Bluetooth services, and cloneable RFID cards

## Key Principles

**Physical proximity required.** All wireless recon requires the tester to be within radio range. WiFi range varies from tens to hundreds of meters depending on antenna gain. Bluetooth Classic reaches roughly 10-100 meters. BLE ranges from a few meters to 50+ meters. RFID/NFC requires near-contact (centimeters for NFC, up to a few meters for LF/HF RFID with specialized antennas).

**Hardware matters.** Not all wireless adapters support the required features. WiFi adapters must support monitor mode and packet injection (chipsets like Atheros AR9271 and Realtek RTL8812AU are widely used). Bluetooth sniffing beyond basic discovery requires specialized hardware (Ubertooth One for raw BLE capture). RFID/NFC requires readers like the Proxmark3 or ACR122U.

**Legal scope.** Wireless signals cross physical boundaries. Only enumerate networks and devices explicitly in scope. Capturing wireless traffic from neighboring organizations — even passively — may violate laws and engagement rules.

**Document the RF environment.** Record signal strengths, channel assignments, and device locations. Wireless reports benefit from floor plans or signal maps showing coverage areas and dead zones.

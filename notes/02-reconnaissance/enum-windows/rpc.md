% Filename: 02-reconnaissance/enum-windows/rpc.md
% Display name: MSRPC Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# MSRPC Enumeration

## Overview

MSRPC (Microsoft Remote Procedure Call) runs on TCP 135 (endpoint mapper) with dynamic high ports (49152-65535) for individual RPC services. Enumeration focuses on endpoint mapping to discover available RPC services, and then querying specific interfaces for user, group, domain, and policy information. Many of the techniques in the SMB enumeration guide (enum4linux, RID cycling) work over RPC pipes — this guide covers direct RPC enumeration.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 135 and high ports
- `rpcclient`, `impacket-rpcdump`, or Nmap installed

## Enumeration Techniques

### Endpoint Mapping

The RPC endpoint mapper on TCP 135 lists all registered RPC services and their ports:

```bash
# Impacket rpcdump
# https://github.com/fortra/impacket
impacket-rpcdump <target>
```

Expected output (truncated):
```text
Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol
Provider: samss.dll
UUID    : 12345778-1234-ABCD-EF00-0123456789AC v1.0
Bindings: 
          ncacn_np:\\WORKSTATION01[\pipe\samr]
          ncacn_ip_tcp:10.10.10.1[49664]

Protocol: [MS-LSAT]: Local Security Authority (Translation Methods) Remote Protocol
Provider: lsasrv.dll
UUID    : 12345778-1234-ABCD-EF00-0123456789AB v0.0
Bindings: 
          ncacn_np:\\WORKSTATION01[\pipe\lsarpc]
          ncacn_ip_tcp:10.10.10.1[49664]
```

Each entry reveals a service name, the DLL providing it, its UUID, and the named pipe or TCP port it's accessible on. Key services to look for: SAMR (user enumeration), LSARPC (policy/SID info), SVCCTL (service management), DRSUAPI (AD replication).

```bash
# Nmap
# https://nmap.org/
# Endpoint enumeration via SMB (hostrule — uses port 445, not 135)
nmap -p 445 --script msrpc-enum <target>
```

### rpcclient Enumeration

`rpcclient` provides direct access to RPC interfaces. Null sessions work on misconfigured hosts:

```bash
# rpcclient (Samba)
# https://www.samba.org/
# Null session connection
rpcclient -U '' -N <target>
```

Once connected, enumerate domain information:

```bash
# rpcclient (Samba)
# https://www.samba.org/
# Server info
rpcclient $> srvinfo

# Domain info
rpcclient $> querydominfo

# Enumerate domain users
rpcclient $> enumdomusers

# Get user details by RID
rpcclient $> queryuser 0x1f4

# Enumerate domain groups
rpcclient $> enumdomgroups

# Get group members by RID
rpcclient $> querygroupmem 0x200

# Enumerate alias groups (local groups)
rpcclient $> enumalsgroups builtin

# Get password policy
rpcclient $> getdompwinfo

# Enumerate printers
rpcclient $> enumprinters

# Enumerate shares
rpcclient $> netshareenum

# Lookup SIDs
rpcclient $> lookupnames administrator
rpcclient $> lookupsids S-1-5-21-...-500
```

Common RID values: `0x1f4` = 500 (Administrator), `0x1f5` = 501 (Guest), `0x200` = 512 (Domain Admins), `0x201` = 513 (Domain Users).

### rpcclient One-Liners

```bash
# rpcclient (Samba)
# https://www.samba.org/
# Enumerate users without interactive session
rpcclient -U '' -N <target> -c 'enumdomusers'

# Get password policy
rpcclient -U '' -N <target> -c 'getdompwinfo'

# Get domain info
rpcclient -U '' -N <target> -c 'querydominfo'

# Enumerate groups
rpcclient -U '' -N <target> -c 'enumdomgroups'

# Authenticated
rpcclient -U '<user>%<password>' <target> -c 'enumdomusers'
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Enumerate RPC endpoints (hostrule — requires SMB access on 445)
nmap -p 445 --script msrpc-enum <target>
```

`msrpc-enum` is a hostrule that queries the endpoint mapper through SMB named pipes on port 445, not directly on TCP 135. It works like Microsoft's `rpcdump` utility.

**Note:** The `rpcinfo` NSE script is for ONC/Sun RPC (port 111), not MSRPC. Do not use it for Windows RPC enumeration.

### Impacket RPC Tools

```bash
# Impacket rpcdump — enumerate endpoints
# https://github.com/fortra/impacket
impacket-rpcdump <target>

# Impacket samrdump — enumerate users via SAMR
impacket-samrdump ''@<target>
impacket-samrdump '<domain>/<user>:<password>'@<target>

# Impacket lookupsid — RID cycling
impacket-lookupsid ''@<target>
impacket-lookupsid '<domain>/<user>:<password>'@<target>

# Impacket services — enumerate services via SVCCTL
impacket-services '<domain>/<user>:<password>'@<target> list
```

## Post-Enumeration

With RPC data collected, prioritize:
- Extracted usernames from SAMR for password spraying
- Password policy (lockout threshold, minimum length) to calibrate spraying
- Domain SID for crafting golden/silver tickets later
- Service endpoints for identifying management interfaces on high ports
- Printer information for potential PrintNightmare exploitation

## References

### Nmap NSE Scripts

- [msrpc-enum](https://nmap.org/nsedoc/scripts/msrpc-enum.html)

### Tools

- [Impacket](https://github.com/fortra/impacket)

### Official Documentation

- [Microsoft RPC Protocol Specification (MS-RPCE)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)
- [Microsoft SAMR Protocol Specification (MS-SAMR)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)

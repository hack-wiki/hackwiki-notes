% Filename: 09-mobile-security/ios/04-common-vulns.md
% Display name: Step 4 - iOS Common Vulnerabilities
% Last update: 2026-02-11
% Authors: @TristanInSec

# iOS Common Vulnerabilities

## Overview

Despite iOS's reputation for security, apps regularly contain vulnerabilities
that can be identified during security assessments. Common findings include
insecure data storage in the Keychain or filesystem, weak jailbreak detection,
URL scheme hijacking, and insufficient transport layer security. This file
covers the most frequently found iOS-specific issues.

## Insecure Data Storage

### NSUserDefaults

`NSUserDefaults` stores data in plaintext plist files. It should never be used
for sensitive data.

```bash
# On a jailbroken device, read the NSUserDefaults plist
cat /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.example.app.plist
```

Look for tokens, credentials, session identifiers, or PII stored in the
preferences file.

### Keychain Weaknesses

The Keychain is the secure storage mechanism on iOS, but misconfigurations
reduce its protection:

- **kSecAttrAccessibleAlways** — data accessible even when the device is
  locked (weakest protection)
- **kSecAttrAccessibleAfterFirstUnlock** — data accessible after first
  device unlock (persists across locks)
- **kSecAttrAccessibleWhenUnlocked** — data only accessible when device is
  unlocked (recommended)
- **kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly** — strongest, requires
  passcode and not backed up

```bash
# objection
# https://github.com/sensepost/objection

# Inside objection session:
# Dump Keychain entries and check their accessibility
ios keychain dump
```

Items with `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAfterFirstUnlock`
are accessible on a jailbroken device at any time.

### SQLite and Core Data

```bash
# Find databases in the app's data directory
find /var/mobile/Containers/Data/Application/<UUID>/ \
    -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null

# Inspect the database
sqlite3 /var/mobile/Containers/Data/Application/<UUID>/Documents/app.db
sqlite> .tables
sqlite> .schema users
sqlite> SELECT * FROM users;
```

### Pasteboard Leakage

The iOS pasteboard (clipboard) is shared between apps. Sensitive data copied
to the clipboard can be read by other apps.

```bash
# objection
# https://github.com/sensepost/objection

# Monitor pasteboard contents
ios pasteboard monitor
```

## Jailbreak Detection Bypass

Many apps implement jailbreak detection to prevent running on compromised
devices. Common detection methods:

### File-Based Detection

The app checks for the existence of jailbreak-related files:
- `/Applications/Cydia.app`
- `/usr/sbin/sshd`
- `/bin/bash`
- `/usr/bin/ssh`
- `/etc/apt`
- `/private/var/lib/apt/`

### Fork-Based Detection

On a non-jailbroken device, `fork()` is restricted by the sandbox. A
successful `fork()` indicates a jailbroken device.

### URL Scheme Detection

The app calls `canOpenURL:` with `cydia://` to check if Cydia is installed.

### Bypass Approaches

```bash
# objection
# https://github.com/sensepost/objection

# One-command bypass (hooks common detection methods)
ios jailbreak disable
```

```javascript
// bypass_jailbreak_ios.js — targeted bypass
// Find the detection method with radare2/class-dump first, then hook it
if (ObjC.available) {
    var SecurityManager = ObjC.classes.SecurityManager;
    Interceptor.attach(SecurityManager['- isJailbroken'].implementation, {
        onLeave: function (retval) {
            console.log('[+] isJailbroken bypassed, original: ' + retval);
            retval.replace(0x0);
        }
    });
}
```

## URL Scheme Hijacking

### Custom URL Scheme Vulnerabilities

iOS does not enforce uniqueness of URL schemes. If two apps register the same
scheme, the behavior is undefined — the OS may route the URL to either app.

An attacker can register a malicious app with the same URL scheme to intercept
sensitive data passed via deep links (e.g., OAuth callbacks).

### Testing URL Schemes

```bash
# Find URL schemes in Info.plist
grep -A5 'CFBundleURLSchemes' extracted/Payload/Target.app/Info.plist

# On a jailbroken device, trigger a URL scheme
# (open Safari and navigate to the URL)
# myapp://callback?token=secret_token
```

```javascript
// hook_url_handler.js — monitor incoming URL scheme calls
if (ObjC.available) {
    var AppDelegate = ObjC.classes.AppDelegate;

    // Hook openURL handler (older API)
    try {
        Interceptor.attach(
            AppDelegate['- application:openURL:sourceApplication:annotation:']
                .implementation, {
            onEnter: function (args) {
                var url = ObjC.Object(args[3]).toString();
                console.log('[+] openURL: ' + url);
            }
        });
    } catch (e) {}

    // Hook newer openURL handler
    try {
        Interceptor.attach(
            AppDelegate['- application:openURL:options:'].implementation, {
            onEnter: function (args) {
                var url = ObjC.Object(args[3]).toString();
                console.log('[+] openURL (new): ' + url);
            }
        });
    } catch (e) {}
}
```

## App Transport Security (ATS) Exceptions

ATS enforces HTTPS connections by default. Apps that disable ATS or add
exceptions weaken transport security.

```bash
# Check for ATS exceptions in Info.plist
grep -A10 'NSAppTransportSecurity' extracted/Payload/Target.app/Info.plist
```

Problematic configurations:
- `NSAllowsArbitraryLoads = true` — disables ATS entirely
- `NSExceptionAllowsInsecureHTTPLoads = true` — allows HTTP for specific
  domains
- `NSExceptionMinimumTLSVersion = TLSv1.0` — allows weak TLS versions

## Binary Protections Missing

### No PIE (ASLR)

```bash
# radare2
# https://github.com/radareorg/radare2
rabin2 -I extracted/Payload/Target.app/Target | grep pic
# pic = false means no ASLR — addresses are predictable
```

### No Stack Canaries

```bash
# radare2
# https://github.com/radareorg/radare2
rabin2 -I extracted/Payload/Target.app/Target | grep canary
# canary = false means no stack protection
```

### Debug Symbols Present

```bash
# radare2
# https://github.com/radareorg/radare2
rabin2 -I extracted/Payload/Target.app/Target | grep stripped
# stripped = false means debug symbols are included
```

Debug symbols make reverse engineering significantly easier.

## Snapshot Leakage

iOS takes a screenshot of the app when it enters the background (for the app
switcher). Sensitive data displayed on screen is captured in this snapshot.

```bash
# On a jailbroken device, find snapshots
find /var/mobile/Containers/Data/Application/<UUID>/Library/SplashBoard/Snapshots/ \
    -name "*.ktx" -o -name "*.png" 2>/dev/null
```

Apps should implement `applicationDidEnterBackground:` to obscure sensitive
content before the snapshot is taken.

## Cookie and Session Management

```bash
# objection
# https://github.com/sensepost/objection

# Dump cookies
ios cookies get
```

Check for:
- Session cookies without the `Secure` flag (sent over HTTP)
- Cookies without the `HttpOnly` flag (accessible via JavaScript)
- Long-lived session tokens that do not expire

## Keyboard Cache

The iOS keyboard caches typed text for autocomplete. Sensitive text fields
should disable autocorrection.

```bash
# On a jailbroken device, check the keyboard cache
cat /var/mobile/Library/Keyboard/dynamic-text.dat
```

Look for passwords, credit card numbers, or other sensitive data in the
keyboard cache file.

## References

### Official Documentation

- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [Apple iOS Security Guide](https://support.apple.com/guide/security/welcome/web)

% Filename: 09-mobile-security/android/04-common-vulns.md
% Display name: Step 4 - Android Common Vulnerabilities
% Last update: 2026-02-11
% Authors: @TristanInSec

# Android Common Vulnerabilities

## Overview

Common Android application vulnerabilities fall into categories defined by the
OWASP Mobile Top 10. This file covers the most frequently found issues during
Android security assessments — insecure data storage, exported components,
WebView misconfigurations, improper cryptography, and insufficient transport
layer security.

## Insecure Data Storage

### Shared Preferences in Plaintext

Apps often store sensitive data in SharedPreferences XML files without
encryption.

```bash
# Check shared_prefs on a rooted device
adb shell cat /data/data/com.example.app/shared_prefs/credentials.xml
```

Example of insecure storage:

```xml
<map>
    <string name="username">admin</string>
    <string name="password">P@ssw0rd123</string>
    <string name="auth_token">eyJhbGciOiJIUzI1NiJ9...</string>
</map>
```

### SQLite Databases

```bash
# Pull and inspect app databases
adb pull /data/data/com.example.app/databases/app.db ./
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"
```

Look for passwords, tokens, or PII stored in plaintext.

### External Storage

Files on external storage (`/sdcard/`) are world-readable. Sensitive data
should never be stored there.

```bash
# Check for data written to external storage
adb shell ls /sdcard/Android/data/com.example.app/
adb shell find /sdcard/ -name "*.db" -o -name "*.sqlite" -o -name "*.log" 2>/dev/null
```

### Detecting with Objection

```bash
# objection
# https://github.com/sensepost/objection

# Inside objection session:
# List the app's data directory
env

# Check shared preferences
android hooking search classes SharedPreferences
```

## Exported Components

Components declared with `android:exported="true"` can be accessed by any app
on the device. On apps targeting API 30 and below, a component with an
`<intent-filter>` was exported by default; since Android 12 (API 31),
`android:exported` must be explicitly declared when an intent-filter is present.

### Launching Exported Activities

```bash
# Start an exported activity directly
adb shell am start -n com.example.app/.AdminActivity

# Start with extra data
adb shell am start -n com.example.app/.ResetActivity \
    --es "email" "attacker@evil.com"
```

If an admin activity is exported, it may be accessible without authentication.

### Querying Content Providers

```bash
# Query an exported content provider
adb shell content query --uri content://com.example.app.provider/users

# Insert data
adb shell content insert --uri content://com.example.app.provider/users \
    --bind name:s:admin --bind role:s:superuser

# Read specific columns
adb shell content query --uri content://com.example.app.provider/users \
    --projection "name:password"
```

If the provider does not enforce permissions, any app can read or modify data.

### Sending Broadcasts

```bash
# Send a broadcast to an exported receiver
adb shell am broadcast -a com.example.RESET_PASSWORD \
    --es "new_password" "hacked123"
```

## WebView Vulnerabilities

### JavaScript Enabled in WebView

WebViews that load untrusted content with JavaScript enabled can be exploited.

```java
// Vulnerable WebView configuration
webView.getSettings().setJavaScriptEnabled(true);
webView.loadUrl(userControlledUrl);  // XSS risk
```

### JavaScript Interface Exposure

```java
// addJavascriptInterface exposes Java methods to JavaScript
webView.addJavascriptInterface(new WebAppInterface(), "Android");
```

On Android < 4.2 (API 17), all public methods of the exposed object are
accessible from JavaScript via reflection. On API 17+, only methods annotated
with `@JavascriptInterface` are exposed, but they still represent an attack
surface.

### File Access in WebView

```java
// Insecure — allows file:// URLs in WebView
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
```

`setAllowUniversalAccessFromFileURLs(true)` allows JavaScript loaded from
`file://` to access any origin — effectively disabling the same-origin policy.

### Detecting WebView Issues with Frida

```javascript
// hook_webview.js — monitor WebView URL loading
Java.perform(function () {
    var WebView = Java.use('android.webkit.WebView');

    WebView.loadUrl.overload('java.lang.String').implementation =
        function (url) {
            console.log('[+] WebView loading: ' + url);
            this.loadUrl(url);
        };

    var WebSettings = Java.use('android.webkit.WebSettings');

    WebSettings.setJavaScriptEnabled.implementation = function (flag) {
        console.log('[+] setJavaScriptEnabled: ' + flag);
        this.setJavaScriptEnabled(flag);
    };
});
```

## Improper Cryptography

### Hardcoded Encryption Keys

```bash
# Search decompiled source for hardcoded keys
grep -rni 'SecretKeySpec\|AES\|DES\|Cipher' output_dir/sources/
grep -rni 'getBytes\|Base64' output_dir/sources/ | grep -i key
```

### Weak Algorithms

Look for use of:
- DES or 3DES (weak, replaced by AES)
- ECB mode (does not provide semantic security)
- MD5 or SHA-1 for password hashing (use bcrypt/scrypt/Argon2)
- `Math.random()` or `java.util.Random` for security-sensitive values
  (use `SecureRandom`)

### Insecure Random Number Generation

```javascript
// hook_random.js — detect use of insecure random
Java.perform(function () {
    var Random = Java.use('java.util.Random');
    Random.nextInt.overload('int').implementation = function (bound) {
        console.log('[!] java.util.Random.nextInt called (insecure)');
        console.log(Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new()));
        return this.nextInt(bound);
    };
});
```

## Insufficient Transport Layer Security

### Cleartext Traffic

Apps targeting API 28+ (Android 9) block cleartext HTTP by default. Older
apps or those with `android:usesCleartextTraffic="true"` allow HTTP.

```bash
# Check if cleartext traffic is allowed
grep -r 'usesCleartextTraffic\|cleartextTrafficPermitted' decoded_dir/
```

### Certificate Validation Bypass in Code

Look for custom `TrustManager` implementations that accept all certificates:

```bash
# Search for trust-all patterns
grep -rni 'TrustManager\|X509TrustManager\|checkServerTrusted' output_dir/sources/
grep -rni 'ALLOW_ALL_HOSTNAME_VERIFIER\|setHostnameVerifier' output_dir/sources/
```

An empty `checkServerTrusted` method means the app accepts any certificate,
making it vulnerable to MITM attacks even without SSL pinning bypass.

## Deep Link / URL Scheme Abuse

### Identifying Deep Links

```bash
# Extract intent filters from the manifest
grep -A5 'android:scheme' decoded_dir/AndroidManifest.xml

# Test a deep link
adb shell am start -d "myapp://account/delete?confirm=true" \
    -n com.example.app/.DeepLinkActivity
```

If deep link handlers do not validate the caller or parameters, they can be
triggered by any app or a malicious web page.

## Root Detection Bypass

Many apps check for root and refuse to run on rooted devices. Common checks:

- File existence: `/system/app/Superuser.apk`, `/system/xbin/su`
- Package manager: check for `com.topjohnwu.magisk` or `eu.chainfire.supersu`
- Build tags: `ro.build.tags` containing `test-keys`

### Bypass with Objection

```bash
# objection
# https://github.com/sensepost/objection

# Inside objection session:
android root disable
```

### Bypass with Frida

```javascript
// bypass_root.js — hook common root detection methods
Java.perform(function () {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function () {
        console.log('[+] isRooted() bypassed');
        return false;
    };
});
```

The class and method names vary per app — use jadx to find the root detection
logic first, then write targeted hooks.

## Insecure Logging

```bash
# Monitor logs for sensitive data
adb logcat | grep -iE 'password|token|secret|key|auth'

# Filter to app's PID
adb logcat --pid=$(adb shell pidof com.example.app) | grep -iE 'password|token'
```

Production apps should not log sensitive data. `Log.d()` and `Log.v()` calls
often leak credentials, tokens, and internal state.

## References

### Official Documentation

- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [Android Security Best Practices](https://developer.android.com/privacy-and-security/security-tips)

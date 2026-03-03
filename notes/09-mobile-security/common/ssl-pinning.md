% Filename: 09-mobile-security/common/ssl-pinning.md
% Display name: SSL/TLS Pinning Bypass
% Last update: 2026-02-11
% Authors: @TristanInSec

# SSL/TLS Pinning Bypass

## Overview

SSL/TLS certificate pinning is a security mechanism where mobile apps validate
that the server's certificate matches a known (pinned) certificate or public
key, rather than relying solely on the system trust store. This prevents MITM
attacks even when an attacker has installed a rogue CA certificate on the
device.

During security assessments, pinning must be bypassed to intercept and analyze
the app's API traffic through a proxy like Burp Suite.

## How Certificate Pinning Works

Without pinning, the trust chain is:
1. App makes HTTPS request
2. Server presents its certificate
3. OS validates certificate against the system trust store
4. If the chain is valid, the connection proceeds

With pinning, the app adds an additional check:
1. App makes HTTPS request
2. Server presents its certificate
3. App compares the certificate (or its public key hash) against a pinned value
4. If the pinned value does not match, the connection is rejected —
   regardless of whether the system trusts the certificate

### Pinning Methods

| Method | What's Pinned | Pros | Cons |
|---|---|---|---|
| Certificate pinning | Full certificate | Simple to implement | Must update app when cert rotates |
| Public key pinning | Public key hash (SPKI) | Survives cert renewal (if key unchanged) | Slightly more complex |
| CA pinning | Intermediate/root CA cert | Most flexible | Less restrictive |

## Android SSL Pinning Bypass

### Method 1: Objection (Easiest)

```bash
# objection
# https://github.com/sensepost/objection

# Attach to the app and disable pinning
objection -n com.example.app start

# Inside the REPL:
android sslpinning disable
```

Objection hooks common pinning implementations automatically:
- `TrustManagerImpl.checkServerTrusted`
- OkHttp `CertificatePinner`
- Retrofit `OkHttpClient`
- Apache HTTP client
- `WebViewClient.onReceivedSslError`

### Method 2: Frida Script

```javascript
// bypass_ssl_android.js — disable SSL pinning on Android
Java.perform(function () {
    // Hook TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain,
            trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Bypassed TrustManagerImpl.verifyChain for: ' + host);
            return untrustedChain;
        };
    } catch (e) {
        console.log('[-] TrustManagerImpl not found: ' + e);
    }

    // Hook OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (hostname, peerCertificates) {
            console.log('[+] Bypassed OkHttp3 CertificatePinner for: ' + hostname);
        };
    } catch (e) {
        console.log('[-] OkHttp3 CertificatePinner not found: ' + e);
    }

    // Hook X509TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.bypass.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
    } catch (e) {
        console.log('[-] X509TrustManager hook failed: ' + e);
    }
});
```

```bash
# Frida
# https://github.com/frida/frida

# Load the bypass script
frida -U -f com.example.app -l bypass_ssl_android.js
```

### Method 3: Network Security Config (APK Modification)

Modify the app to trust user-installed certificates:

```bash
# apktool
# https://github.com/iBotPeaches/Apktool

# Decode the APK
apktool d target.apk -o decoded/
```

Create or edit `decoded/res/xml/network_security_config.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

Ensure `AndroidManifest.xml` references the config:

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

Then rebuild and sign:

```bash
# apktool
# https://github.com/iBotPeaches/Apktool
apktool b decoded/ -o modified.apk

# objection
# https://github.com/sensepost/objection
objection signapk modified.apk
```

## iOS SSL Pinning Bypass

### Method 1: Objection (Easiest)

```bash
# objection
# https://github.com/sensepost/objection

# Attach to the app
objection -n com.example.app start

# Inside the REPL:
ios sslpinning disable
```

Objection hooks common iOS pinning implementations:
- `NSURLSession` delegate methods
- `AFNetworking` / `Alamofire` pinning
- `TrustKit` framework
- Custom `SecTrustEvaluate` implementations

### Method 2: Frida Script

```javascript
// bypass_ssl_ios.js — disable SSL pinning on iOS
if (ObjC.available) {
    // Hook SecTrustEvaluateWithError (iOS 12+)
    try {
        var SecTrustEvaluateWithError = new NativeFunction(
            Module.findExportByName('Security', 'SecTrustEvaluateWithError'),
            'bool', ['pointer', 'pointer']
        );

        Interceptor.replace(
            Module.findExportByName('Security', 'SecTrustEvaluateWithError'),
            new NativeCallback(function (trust, error) {
                console.log('[+] Bypassed SecTrustEvaluateWithError');
                return 1;  // Return true (trust is valid)
            }, 'bool', ['pointer', 'pointer'])
        );
    } catch (e) {
        console.log('[-] SecTrustEvaluateWithError hook failed: ' + e);
    }

    // Hook NSURLSession delegate
    try {
        var NSURLSessionDelegate = ObjC.classes.NSURLSession;
        // Many apps implement URLSession:didReceiveChallenge:completionHandler:
        // The specific hook depends on the app's implementation
        console.log('[*] For app-specific pinning, find the delegate class with:');
        console.log('[*] ObjC.classes.ClassName.$ownMethods');
    } catch (e) {}
}
```

```bash
# Frida
# https://github.com/frida/frida

# Load the bypass script
frida -U -f com.example.app -l bypass_ssl_ios.js
```

## Verifying the Bypass

After applying a bypass, verify that traffic flows through your proxy:

1. Start Burp Suite / ZAP with the proxy listener on the correct interface
2. Configure the device proxy settings
3. Open the target app and perform actions that trigger network requests
4. Check the proxy for intercepted HTTPS traffic

If requests still fail:
- The app may use a non-standard HTTP library (e.g., Flutter's Dart HTTP)
- The app may implement custom pinning not covered by the bypass
- The app may use certificate transparency checks in addition to pinning

### Flutter / Dart Apps

Flutter apps use Dart's HTTP library, which does not use the system proxy
settings or the standard SSL stack. Intercepting Flutter traffic requires
hooking at a different level:

```javascript
// bypass_flutter_ssl.js — hook Dart's SSL verification
// The exact function varies by Flutter/Dart version
// Search for the ssl_verify_peer_cert function in the libflutter.so module
var flutter = Process.findModuleByName('libflutter.so');
if (flutter) {
    // Pattern scan for the verification function
    // This is version-dependent — check community scripts for current patterns
    console.log('[*] Flutter module found at: ' + flutter.base);
    console.log('[*] Use reFlutter or community Frida scripts for Flutter pinning bypass');
}
```

For Flutter apps, community tools like **reFlutter** provide automated bypass
scripts.

## Troubleshooting

| Problem | Solution |
|---|---|
| Objection bypass has no effect | App uses custom pinning — write targeted Frida hooks |
| App crashes after bypass | Bypass script may break other SSL calls — scope hooks to specific classes |
| No traffic in proxy | App may not use system proxy — use Frida to hook the HTTP library directly |
| Certificate errors persist | Proxy CA not properly installed as system cert (Android API 24+) |
| App detects Frida | Use Frida in spawn mode (`-f`), or use newer Frida versions with anti-detection |

## References

### Tools

- [Frida](https://github.com/frida/frida)
- [objection](https://github.com/sensepost/objection)
- [Apktool](https://github.com/iBotPeaches/Apktool)

### Official Documentation

- [OWASP MASTG — Network Communication Testing](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/)
- [Android Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)

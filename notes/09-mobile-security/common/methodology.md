% Filename: 09-mobile-security/common/methodology.md
% Display name: Mobile Testing Methodology
% Last update: 2026-02-11
% Authors: @TristanInSec

# Mobile Testing Methodology

## Overview

A structured methodology ensures consistent, thorough mobile security
assessments. The OWASP Mobile Application Security Testing Guide (MASTG) is
the industry-standard framework, providing checklists organized by the Mobile
Application Security Verification Standard (MASVS). This file covers the
overall assessment approach that applies to both Android and iOS.

## OWASP MASVS Categories

The OWASP Mobile Application Security Verification Standard defines security
requirements across these categories:

| Category | Description |
|---|---|
| MASVS-STORAGE | Secure storage of sensitive data |
| MASVS-CRYPTO | Cryptographic best practices |
| MASVS-AUTH | Authentication and session management |
| MASVS-NETWORK | Network communication security |
| MASVS-PLATFORM | Platform interaction security |
| MASVS-CODE | Code quality and build settings |
| MASVS-RESILIENCE | Resilience against reverse engineering |
| MASVS-PRIVACY | User privacy protection |

Each category contains specific test cases with procedures for both Android
and iOS.

## Assessment Phases

### Phase 1: Scoping and Reconnaissance

Gather information about the target application before testing begins:

- **App metadata** — package name, version, target SDK, minimum SDK
- **Permissions** — what system resources the app requests
- **Attack surface** — exported components, URL schemes, content providers
- **Backend** — API endpoints, authentication mechanism, third-party services
- **Distribution** — Play Store, App Store, enterprise sideloading, MDM

```bash
# Android: quick metadata extraction
# aapt (Android Asset Packaging Tool)
aapt dump badging target.apk

# iOS: read Info.plist
python3 -c "
import plistlib, json, sys
with open('Payload/Target.app/Info.plist', 'rb') as f:
    data = plistlib.load(f)
print(json.dumps(data, indent=2, default=str))
"
```

### Phase 2: Static Analysis

Examine the app without executing it:

- Decompile / disassemble the binary
- Review configuration files (manifest, plist, network security config)
- Search for hardcoded secrets, API keys, credentials
- Analyze cryptographic implementations
- Check binary protections (PIE, stack canaries, ARC)
- Review third-party libraries for known vulnerabilities

### Phase 3: Dynamic Analysis

Examine the app during execution:

- Hook methods with Frida to observe runtime behavior
- Intercept and modify network traffic
- Inspect local data storage (databases, preferences, files)
- Test authentication and session management
- Bypass client-side security controls (root/jailbreak detection, SSL pinning)
- Test exported components and deep links

### Phase 4: Network Testing

Test the communication between app and backend:

- Intercept API traffic with Burp Suite or ZAP
- Test for IDOR, broken access control, authentication bypass
- Check for cleartext communication
- Verify certificate validation
- Test API rate limiting and input validation

### Phase 5: Reporting

Document findings with:

- Clear description of the vulnerability
- Steps to reproduce
- Evidence (screenshots, HTTP requests/responses, Frida output)
- Risk rating (CVSS or custom scale)
- Remediation guidance
- References to OWASP MASVS/MASTG test cases

## Common Testing Checklist

### Data Storage

| Check | Android | iOS |
|---|---|---|
| Sensitive data in logs | `adb logcat` | `idevicesyslog` / Console.app |
| Plaintext credentials | SharedPreferences | NSUserDefaults |
| Database encryption | SQLite in `/data/data/` | SQLite/CoreData in sandbox |
| External storage | `/sdcard/` world-readable | N/A (sandboxed) |
| Clipboard data | `ClipboardManager` | `UIPasteboard` |
| Backup extraction | `adb backup` | iTunes backup |
| Keystore/Keychain | Android Keystore | iOS Keychain |

### Network Security

| Check | What to Test |
|---|---|
| HTTPS enforcement | All traffic uses TLS |
| Certificate validation | No trust-all TrustManagers or delegates |
| Certificate pinning | Pins present and effective |
| Cleartext traffic | No HTTP connections for sensitive data |
| API authentication | Token-based, proper expiration |

### Authentication

| Check | What to Test |
|---|---|
| Local authentication | Biometric bypass, PIN bruteforce |
| Session management | Token storage, expiration, invalidation |
| Login rate limiting | Account lockout, request throttling |
| Password policy | Minimum complexity enforced server-side |

### Platform Security

| Check | Android | iOS |
|---|---|---|
| Exported components | Activities, providers, receivers | N/A |
| URL schemes | Intent filters, deep links | CFBundleURLTypes |
| WebView security | JavaScript, file access | JavaScript, universal links |
| IPC mechanisms | Intents, content providers | URL schemes, Universal Links |
| Root/jailbreak detection | Detection + bypass test | Detection + bypass test |

## Testing Without a Jailbroken/Rooted Device

Some testing is possible on non-jailbroken/non-rooted devices:

### Android (No Root)

- **objection patchapk** — patches the APK with Frida gadget, allowing
  instrumentation without root
- **Static analysis** — jadx, apktool, and string analysis work on APK files
  directly
- **Proxy interception** — configure the device proxy for traffic analysis
  (apps targeting API 24+ need additional setup)

```bash
# objection
# https://github.com/sensepost/objection

# Patch APK with Frida gadget
objection patchapk -s target.apk

# Install the patched APK
adb install target.objection.apk

# Connect
objection -n com.example.app start
```

### iOS (No Jailbreak)

- **Static analysis** — extract and analyze the IPA (limited if encrypted)
- **objection patchipa** — patches the IPA with Frida gadget (requires
  code signing)
- **Proxy interception** — configure Wi-Fi proxy settings

```bash
# objection
# https://github.com/sensepost/objection

# Patch IPA with Frida gadget (requires valid provisioning profile)
objection patchipa -s target.ipa
```

## Tool Selection Guide

| Task | Primary Tool | Alternative |
|---|---|---|
| APK decompilation | jadx | apktool + dex2jar |
| iOS binary analysis | radare2 | Ghidra |
| Runtime hooking | Frida | objection (pre-built hooks) |
| Traffic interception | Burp Suite | mitmproxy, ZAP |
| Automated scanning | MobSF | — |
| SSL pinning bypass | objection | Custom Frida scripts |

## References

### Official Documentation

- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)

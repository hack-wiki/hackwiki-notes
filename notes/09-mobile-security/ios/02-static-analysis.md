% Filename: 09-mobile-security/ios/02-static-analysis.md
% Display name: Step 2 - iOS Static Analysis
% Last update: 2026-02-11
% Authors: @TristanInSec

# iOS Static Analysis

## Overview

iOS static analysis examines an IPA file or extracted app bundle without
executing it — reviewing the binary for security flags, extracting embedded
strings and resources, analyzing entitlements and Info.plist, and inspecting
Objective-C/Swift class structures. Since iOS apps are compiled to native ARM
code (not bytecode like Android), decompilation produces assembly rather than
source code.

## IPA Structure

An IPA is a ZIP archive containing:

| File/Directory | Purpose |
|---|---|
| `Payload/AppName.app/` | The application bundle |
| `Payload/AppName.app/AppName` | The main Mach-O binary |
| `Payload/AppName.app/Info.plist` | App configuration and metadata |
| `Payload/AppName.app/*.plist` | Additional property lists |
| `Payload/AppName.app/embedded.mobileprovision` | Provisioning profile |
| `Payload/AppName.app/Frameworks/` | Embedded frameworks |
| `Payload/AppName.app/*.storyboardc` | Compiled storyboards |
| `Payload/AppName.app/Assets.car` | Compiled asset catalog |

### Extracting an IPA

```bash
# Unzip the IPA
unzip target.ipa -d extracted/

# The app bundle is in Payload/
ls extracted/Payload/*.app/
```

## Info.plist Analysis

The `Info.plist` contains app configuration. Convert binary plist to XML for
reading:

```bash
# plistutil — install on Kali if missing: sudo apt install -y libplist-utils
# Convert binary plist to XML
plistutil -i extracted/Payload/Target.app/Info.plist -o Info_readable.plist

# Or use Python (no extra packages required)
python3 -c "
import plistlib, json, sys
with open('extracted/Payload/Target.app/Info.plist', 'rb') as f:
    data = plistlib.load(f)
print(json.dumps(data, indent=2, default=str))
"
```

### Key Fields to Review

| Key | What to Look For |
|---|---|
| `CFBundleIdentifier` | App bundle ID |
| `CFBundleVersion` | Build version number |
| `NSAppTransportSecurity` | ATS exceptions (HTTP allowed?) |
| `CFBundleURLTypes` | Custom URL schemes (deep links) |
| `LSApplicationQueriesSchemes` | Other apps this app can query |
| `UIBackgroundModes` | Background execution capabilities |
| `NSCameraUsageDescription` | Camera access justification |
| `NSLocationWhenInUseUsageDescription` | Location access justification |

### App Transport Security (ATS)

```xml
<!-- Insecure — disables ATS entirely -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

`NSAllowsArbitraryLoads = true` disables all transport security requirements,
allowing HTTP connections to any domain.

### URL Schemes

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
            <string>myapp-debug</string>
        </array>
    </dict>
</array>
```

Custom URL schemes can be invoked by any app or web page via
`myapp://path?param=value`.

## Binary Analysis

### File Type Identification

```bash
# Check the binary type
file extracted/Payload/Target.app/Target

# Expected output for a real device IPA (arm64 only):
# Target: Mach-O 64-bit executable arm64
#
# Note: x86_64 slices appear only in simulator builds.
# Since the iPhone 5s (A7 chip, 2013), all real device IPAs are arm64 only.
```

### Security Flags with rabin2

```bash
# radare2
# https://github.com/radareorg/radare2

# Check binary info and security flags
rabin2 -I extracted/Payload/Target.app/Target
```

Key flags to check:

| Flag | Secure Value | Meaning |
|---|---|---|
| `canary` | true | Stack canaries enabled |
| `crypto` | true | Binary is encrypted (FairPlay) |
| `nx` | true | Non-executable stack |
| `pic` | true | Position Independent Code (ASLR) |
| `stripped` | true | Debug symbols removed |

### Checking for PIE and ARC

```bash
# Check for PIE flag (Position Independent Executable)
# otool is macOS-only; on Linux use rabin2
rabin2 -I extracted/Payload/Target.app/Target | grep -E 'pic|canary|nx'
```

- **PIE** — enables ASLR. Non-PIE binaries load at fixed addresses.
- **ARC** — Automatic Reference Counting. Apps without ARC are more
  susceptible to memory corruption bugs.

## String Extraction

```bash
# Extract readable strings from the binary
strings extracted/Payload/Target.app/Target | head -100

# Search for URLs
strings extracted/Payload/Target.app/Target | grep -iE 'https?://'

# Search for API keys and secrets
strings extracted/Payload/Target.app/Target | grep -iE 'api.key|secret|token|password'

# Search for hardcoded IPs
strings extracted/Payload/Target.app/Target | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

# Search for Firebase or cloud service URLs
strings extracted/Payload/Target.app/Target | grep -iE 'firebase|amazonaws|azure'
```

## Entitlements

Entitlements define what system resources and capabilities the app can access.

```bash
# Extract entitlements from the provisioning profile
# The embedded.mobileprovision contains entitlements in a CMS envelope
openssl smime -inform DER -verify -noverify \
    -in extracted/Payload/Target.app/embedded.mobileprovision \
    2>/dev/null | python3 -c "
import plistlib, json, sys
data = plistlib.loads(sys.stdin.buffer.read())
print(json.dumps(data.get('Entitlements', {}), indent=2, default=str))
"
```

### Sensitive Entitlements

| Entitlement | Risk |
|---|---|
| `com.apple.security.get-task-allow` | Allows debugger attachment (should be false in production) |
| `keychain-access-groups` | Lists Keychain groups the app can access |
| `com.apple.developer.associated-domains` | Universal Links / App Clips domains |
| `aps-environment` | Push notification environment (development/production) |

`get-task-allow = true` in production means the app was built with a
development profile — it can be debugged on a jailbroken device.

## Embedded Files and Resources

```bash
# List all files in the app bundle
find extracted/Payload/Target.app/ -type f | head -50

# Look for embedded databases
find extracted/Payload/Target.app/ -name "*.db" -o -name "*.sqlite" -o -name "*.realm"

# Look for configuration files
find extracted/Payload/Target.app/ -name "*.json" -o -name "*.plist" -o -name "*.xml"

# Look for certificates or keys
find extracted/Payload/Target.app/ -name "*.p12" -o -name "*.cer" -o -name "*.pem" -o -name "*.key"
```

## Analyzing with radare2

```bash
# radare2
# https://github.com/radareorg/radare2

# Open the binary for analysis
r2 -A extracted/Payload/Target.app/Target

# Inside r2:
# List functions
afl

# Search for functions by name
afl~login
afl~password
afl~jailbreak

# List imported symbols
ii

# List strings
iz

# Search for specific strings
iz~password
iz~http://

# Disassemble a function
pdf @ sym.func_name

# List Objective-C classes
ic

# List methods of a class
ic ClassName
```

## References

### Tools

- [radare2](https://github.com/radareorg/radare2)
- [Frida](https://github.com/frida/frida)

### Official Documentation

- [OWASP MASTG — iOS Static Analysis](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/)
- [Apple App Transport Security](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity)

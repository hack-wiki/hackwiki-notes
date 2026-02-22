% Filename: 09-mobile-security/android/02-static-analysis.md
% Display name: Step 2 - Android Static Analysis
% Last update: 2026-02-11
% Authors: @TristanInSec

# Android Static Analysis

## Overview

Android static analysis examines an APK without executing it — decompiling
Dalvik bytecode to Java source, decoding resources and the manifest, and
searching for hardcoded secrets, insecure configurations, and vulnerable code
patterns. Static analysis is the first step in any Android assessment.

## APK Structure

An APK is a ZIP archive containing:

| File/Directory | Purpose |
|---|---|
| `AndroidManifest.xml` | App permissions, components, SDK versions (binary XML) |
| `classes.dex` | Compiled Dalvik bytecode (app code) |
| `classes2.dex` ... | Additional DEX files (multidex apps) |
| `res/` | Compiled resources (layouts, drawables) |
| `assets/` | Raw assets bundled with the app |
| `lib/` | Native shared libraries (`.so` files) per architecture |
| `META-INF/` | Signing certificate and manifest digests |
| `resources.arsc` | Compiled resource table |

## Decompilation with jadx

jadx decompiles APK/DEX files directly to Java source code.

```bash
# jadx
# https://github.com/skylot/jadx

# Decompile APK to Java source
jadx -d output_dir target.apk

# Decompile without resources (faster, source-only)
jadx -r -d output_dir target.apk

# Decompile without source code (resources only)
jadx -s -d output_dir target.apk

# Decompile a single class
jadx --single-class com.example.app.MainActivity -d output_dir target.apk

# Export as Gradle project (importable in Android Studio)
jadx -e -d output_dir target.apk

# Use multiple threads for large APKs
jadx -j 4 -d output_dir target.apk

# Show deobfuscation (rename short/obfuscated names)
jadx --deobf -d output_dir target.apk

# Use fallback mode for badly decompiled code
jadx -m fallback -d output_dir target.apk
```

After decompilation, the output directory contains readable Java source and
decoded resources. Open in any text editor or IDE for review.

## Decoding with apktool

apktool decodes the APK to smali (Dalvik assembly) and decoded XML resources.
Unlike jadx, apktool can rebuild a modified APK.

```bash
# apktool
# https://github.com/iBotPeaches/Apktool

# Decode APK
apktool d target.apk -o decoded_dir

# Decode without source (smali)
apktool d -s target.apk -o decoded_dir

# Decode without resources
apktool d -r target.apk -o decoded_dir

# Force overwrite existing output directory
apktool d -f target.apk -o decoded_dir

# Rebuild modified APK
apktool b decoded_dir -o modified.apk
```

### Signing a Rebuilt APK

Rebuilt APKs must be signed before installation:

```bash
# Generate a signing key
keytool -genkey -v -keystore test.keystore -alias testkey \
    -keyalg RSA -keysize 2048 -validity 10000

# Sign the APK
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
    -keystore test.keystore modified.apk testkey

# Or use objection's built-in signing
# objection
# https://github.com/sensepost/objection
objection signapk modified.apk
```

## DEX to JAR Conversion

```bash
# dex2jar
# https://github.com/pxb1988/dex2jar

# Convert DEX to JAR
d2j-dex2jar target.apk -o target.jar

# Force overwrite
d2j-dex2jar -f target.apk -o target.jar
```

The resulting JAR can be opened in JD-GUI or other Java decompilers. jadx is
generally preferred over the dex2jar + JD-GUI workflow as it handles DEX
directly with better results.

## AndroidManifest.xml Analysis

The manifest reveals the app's attack surface. Key items to review:

### Permissions

```xml
<!-- Dangerous permissions that the app requests -->
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
```

Look for overly broad permissions — does the app really need camera, location,
or storage access?

### Exported Components

```xml
<!-- Exported activity — accessible from other apps -->
<activity android:name=".AdminActivity"
    android:exported="true" />

<!-- Exported content provider — data accessible to other apps -->
<provider android:name=".DataProvider"
    android:exported="true"
    android:authorities="com.example.app.provider" />

<!-- Exported broadcast receiver -->
<receiver android:name=".DebugReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.example.DEBUG" />
    </intent-filter>
</receiver>
```

Exported components (`android:exported="true"`) are accessible from any other
app on the device and are a common source of vulnerabilities.

### Security Flags

```xml
<!-- App-level flags -->
<application
    android:debuggable="true"         <!-- VULN: debug mode enabled -->
    android:allowBackup="true"        <!-- VULN: data backup allowed -->
    android:usesCleartextTraffic="true"  <!-- VULN: HTTP allowed -->
    android:networkSecurityConfig="@xml/network_security_config">
```

- `debuggable="true"` — allows attaching a debugger (should be false in
  production)
- `allowBackup="true"` — allows `adb backup` to extract app data
- `usesCleartextTraffic="true"` — allows unencrypted HTTP connections

### Target SDK and Minimum SDK

```xml
<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" />
```

Lower `minSdkVersion` means the app must support older Android versions that
lack security features. `targetSdkVersion` determines which security behaviors
the OS enforces.

## Quick Metadata with aapt

```bash
# aapt (Android Asset Packaging Tool)
# Included in Android SDK build-tools

# Dump package info (name, version, permissions, SDK versions)
aapt dump badging target.apk

# Dump permissions only
aapt dump permissions target.apk

# Dump the string pool
aapt dump strings target.apk

# Dump the XML tree of AndroidManifest.xml
aapt dump xmltree target.apk AndroidManifest.xml
```

## androguard Analysis

```bash
# androguard
# https://github.com/androguard/androguard

# Print package name, version code, version name
androguard apkid target.apk

# Parse and display AndroidManifest.xml
androguard axml target.apk

# Decode resources.arsc
androguard arsc target.apk

# Show signing certificate fingerprints
androguard sign target.apk

# Interactive analysis (IPython shell)
androguard analyze target.apk
```

In the interactive shell, the `a` (APK), `d` (DEX), and `dx` (Analysis)
objects are available for programmatic inspection.

## Searching for Secrets and Sensitive Data

After decompilation, search the source code for common sensitive patterns:

```bash
# Search for hardcoded URLs
grep -rn 'http://' output_dir/sources/
grep -rn 'https://' output_dir/sources/

# Search for API keys and tokens
grep -rni 'api.key\|apikey\|api_key\|secret\|token\|password' output_dir/sources/

# Search for AWS credentials
grep -rn 'AKIA[0-9A-Z]\{16\}' output_dir/sources/

# Search for Firebase URLs
grep -rn 'firebaseio\.com' output_dir/sources/

# Search for hardcoded IPs
grep -rn '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' output_dir/sources/

# Search in shared_prefs XML files (if extracted from device)
grep -rn 'password\|token\|secret' shared_prefs/

# Search for SQL queries (potential injection points)
grep -rni 'rawQuery\|execSQL' output_dir/sources/
```

### Files to Check

| Location | What to Look For |
|---|---|
| `res/values/strings.xml` | Hardcoded strings, API endpoints |
| `res/xml/network_security_config.xml` | Certificate pinning config, cleartext settings |
| `assets/` | Configuration files, databases, embedded credentials |
| `lib/` | Native libraries (reverse with radare2/Ghidra) |
| Source code | Crypto implementations, authentication logic |

## Network Security Configuration

Android 7+ (API 24) supports a declarative network security config:

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <!-- Allow cleartext traffic (insecure) -->
    <base-config cleartextTrafficPermitted="true" />

    <!-- Trust user-installed CAs (allows proxy interception) -->
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>

    <!-- Certificate pinning -->
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set>
            <pin digest="SHA-256">base64_hash_here=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

If the config includes `<certificates src="user" />`, user-installed proxy
certificates will be trusted and interception works without additional bypass.

## References

### Tools

- [jadx](https://github.com/skylot/jadx)
- [Apktool](https://github.com/iBotPeaches/Apktool)
- [dex2jar](https://github.com/pxb1988/dex2jar)
- [androguard](https://github.com/androguard/androguard)

### Official Documentation

- [OWASP MASTG — Android Static Analysis](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/)
- [Android Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)

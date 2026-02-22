% Filename: 09-mobile-security/android/overview.md
% Display name: Android Security Testing
% Last update: 2026-02-11
% Authors: @TristanInSec

# Android Security Testing

## Overview

Android security testing covers static analysis (decompiling APKs, reviewing
code and configurations), dynamic analysis (runtime instrumentation, hooking,
traffic interception), and identifying common vulnerabilities in Android
applications. Android's open architecture and APK format make it more
accessible for security testing than iOS.

## Topics in This Section

- [Android Testing Setup](01-setup.md) — emulator configuration, device prep,
  tool installation
- [Android Static Analysis](02-static-analysis.md) — APK decompilation, manifest
  review, code analysis with jadx and apktool
- [Android Dynamic Analysis](03-dynamic-analysis.md) — runtime hooking with Frida,
  objection, logcat monitoring, and traffic interception
- [Android Common Vulnerabilities](04-common-vulns.md) — insecure storage, exported
  components, WebView issues, and other OWASP Mobile Top 10 findings

## General Approach

1. **Setup** — prepare a rooted emulator or device, install tools, configure
   proxy for traffic interception
2. **Reconnaissance** — identify the app's package name, permissions, exported
   components, and target SDK version
3. **Static analysis** — decompile the APK, review `AndroidManifest.xml`,
   search for hardcoded secrets, analyze code logic
4. **Dynamic analysis** — hook methods at runtime, bypass client-side controls,
   monitor logs and network traffic
5. **Reporting** — document findings with evidence and remediation guidance

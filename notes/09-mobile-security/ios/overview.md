% Filename: 09-mobile-security/ios/overview.md
% Display name: iOS Security Testing
% Last update: 2026-02-11
% Authors: @TristanInSec

# iOS Security Testing

## Overview

iOS security testing involves analyzing IPA files, inspecting binary
protections, runtime hooking with Frida, and identifying vulnerabilities in
iOS applications. iOS testing typically requires a jailbroken device — the
closed ecosystem makes emulator-based testing limited compared to Android.

## Topics in This Section

- [iOS Testing Setup](01-setup.md) — device preparation, jailbreak overview,
  tool installation
- [iOS Static Analysis](02-static-analysis.md) — binary inspection, entitlements,
  Info.plist review, class-dump
- [iOS Dynamic Analysis](03-dynamic-analysis.md) — Frida hooking, objection,
  Keychain inspection, runtime manipulation
- [iOS Common Vulnerabilities](04-common-vulns.md) — insecure data storage,
  jailbreak detection bypass, URL scheme abuse, and other OWASP findings

## General Approach

1. **Setup** — prepare a jailbroken device, install Frida server, configure
   SSH access and proxy
2. **Reconnaissance** — identify the app bundle, entitlements, Info.plist
   settings, and binary protections
3. **Static analysis** — extract the IPA, dump classes, review embedded files,
   search for secrets
4. **Dynamic analysis** — hook Objective-C/Swift methods, bypass security
   controls, inspect Keychain and filesystem
5. **Reporting** — document findings with evidence and remediation guidance

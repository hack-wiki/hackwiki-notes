% Filename: 09-mobile-security/android/01-setup.md
% Display name: Step 1 - Android Testing Setup
% Last update: 2026-02-19
% Authors: @TristanInSec

# Android Testing Setup

## Overview

Setting up an Android testing environment requires either a physical rooted
device or an emulator, ADB for device communication, and a proxy tool for
traffic interception. This guide covers environment preparation on a Kali
Linux host.

## ADB (Android Debug Bridge)

ADB is the primary interface between the testing machine and the Android
device or emulator.

### Device Connection

```bash
# List connected devices
adb devices -l

# Connect to a device over TCP/IP (device must be on the same network)
adb connect <device_ip>:5555

# Connect to a specific device by serial
adb -s <serial> shell
```

### Common ADB Commands

```bash
# Open a shell on the device
adb shell

# Install an APK
adb install target.apk

# Install and replace existing app
adb install -r target.apk

# Uninstall an app
adb uninstall com.example.app

# Push a file to the device
adb push local_file /sdcard/

# Pull a file from the device
adb pull /sdcard/remote_file ./

# List installed packages
adb shell pm list packages

# Find a specific package
adb shell pm list packages | grep -i example

# Get the path to an installed APK
adb shell pm path com.example.app

# Pull the APK from the device
adb pull /data/app/com.example.app-1/base.apk ./target.apk

# View device logs
adb logcat

# Filter logs by tag
adb logcat -s "MyAppTag"

# Clear logcat buffer
adb logcat -c

# Forward a local port to the device
adb forward tcp:27042 tcp:27042

# Reverse forward (device connects to host)
adb reverse tcp:8080 tcp:8080
```

### Setting Up TCP/IP Debugging

```bash
# On a USB-connected device, enable TCP/IP mode
adb tcpip 5555

# Disconnect USB, then connect over network
adb connect <device_ip>:5555
```

## Android Emulator Setup

### Using Android Studio AVD

Android Studio's AVD Manager creates emulators with Google APIs (includes
Play Store) or without (AOSP images — easier to root).

For security testing, use **AOSP images without Google Play** — these run as
root by default via `adb root`.

### Genymotion

Genymotion provides x86 Android emulators that are faster than ARM-based AVDs.
The free version (for personal use) is available from
[genymotion.com](https://www.genymotion.com/).

## Proxy Configuration

### Configuring Device Proxy for Traffic Interception

```bash
# Set proxy via ADB (emulator)
adb shell settings put global http_proxy <host_ip>:<port>

# Remove proxy
adb shell settings put global http_proxy :0

# Alternative: set proxy on Wi-Fi network settings (physical device)
# Settings > Wi-Fi > Long press network > Modify > Advanced > Proxy > Manual
```

### Installing a CA Certificate

To intercept HTTPS traffic, the proxy's CA certificate must be installed as a
system-level trusted certificate (user-installed CAs are not trusted by apps
targeting API level 24+ by default).

```bash
# Export CA certificate from Burp/ZAP in DER format, convert to PEM
openssl x509 -inform DER -in burp_ca.der -out burp_ca.pem

# Get the hash for the system cert store filename
openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -1
# Output example: 9a5ba575

# Rename to <hash>.0
cp burp_ca.pem 9a5ba575.0

# Push to the device system cert store (requires root)
# adb root only works on AOSP/eng builds — silently fails or errors on production devices
adb root
adb remount
adb push 9a5ba575.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0
adb reboot
```

On Android 14+, the system partition is read-only even with root. Use the
Frida-based or objection-based SSL pinning bypass instead.

## Frida Server Setup on Android

Frida requires a server component running on the device.

```bash
# Frida
# https://github.com/frida/frida

# Check host Frida version
frida --version

# Download the matching frida-server for the device architecture
# Check device architecture first
adb shell getprop ro.product.cpu.abi
# Common: arm64-v8a, armeabi-v7a, x86, x86_64

# Download from GitHub releases (match version to host frida)
# https://github.com/frida/frida/releases
# Example: frida-server-17.6.2-android-arm64.xz

# Extract and push to device
xz -d frida-server-17.6.2-android-arm64.xz
adb push frida-server-17.6.2-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server on the device (requires root)
adb shell su -c "/data/local/tmp/frida-server &"

# Verify frida-server is running — list processes from host
frida-ps -U
```

## Objection Setup

Objection uses Frida under the hood and can patch APKs to include the Frida
gadget for non-rooted devices.

```bash
# objection
# https://github.com/sensepost/objection

# Patch an APK with Frida gadget (for non-rooted devices)
objection patchapk -s target.apk

# The patched APK will be at target.objection.apk
# Install it on the device
adb install target.objection.apk

# Connect to a running app (rooted device with frida-server)
objection -n com.example.app start
```

## Essential Tool Checklist

| Tool | Purpose | Install |
|---|---|---|
| adb | Device communication | `sudo apt install -y adb` |
| jadx | APK decompilation to Java | `sudo apt install -y jadx` |
| apktool | APK decode/rebuild (smali) | `sudo apt install -y apktool` |
| frida | Runtime instrumentation | `pip3 install frida-tools` |
| objection | Mobile exploration framework | `pip3 install objection` |
| d2j-dex2jar | Convert DEX to JAR | `sudo apt install -y dex2jar` |
| androguard | Python-based APK analysis | `sudo apt install -y androguard` |
| aapt | APK metadata inspection | `sudo apt install -y aapt` |
| Burp Suite / ZAP | Traffic interception | Pre-installed on Kali |

## References

### Tools

- [Android Debug Bridge (ADB)](https://developer.android.com/tools/adb)
- [Frida](https://github.com/frida/frida)
- [objection](https://github.com/sensepost/objection)

### Official Documentation

- [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)
- [Android Security Documentation](https://source.android.com/docs/security)

% Filename: 09-mobile-security/ios/01-setup.md
% Display name: Step 1 - iOS Testing Setup
% Last update: 2026-02-11
% Authors: @TristanInSec

# iOS Testing Setup

## Overview

iOS security testing requires a jailbroken device in most cases. The iOS
simulator included with Xcode does not run ARM binaries and lacks key
frameworks, making it unsuitable for real-world app testing. This guide covers
device preparation, jailbreak considerations, and tool installation.

## Device Requirements

### Physical Device (Recommended)

A jailbroken iPhone or iPad is the standard testing platform. Key
considerations:

- **Jailbreak compatibility** — not all iOS versions are jailbreakable.
  Check current status at community resources before purchasing a device.
- **Architecture** — modern iPhones use arm64 (A7 chip and later)
- **Wi-Fi** — device must be on the same network as the testing machine for
  proxy interception
- **USB** — required for initial setup and some tool communication

### Corellium (Cloud-Based)

Corellium provides virtualized iOS devices in the cloud with jailbreak support.
It is a commercial service used by security researchers and enterprises.

## Jailbreak Overview

Jailbreaking removes iOS sandbox restrictions, allowing:
- SSH access to the device filesystem
- Installation of unsigned apps and tweaks
- Root access for file inspection
- Running Frida server for runtime analysis

Common jailbreak tools (compatibility varies by iOS version):
- **checkra1n** — hardware-based (A5-A11 chips), survives updates but not
  reboots (semi-tethered)
- **unc0ver** — software-based, supports various iOS versions
- **palera1n** — based on checkm8 exploit, supports newer iOS versions on
  compatible hardware
- **Dopamine** — newer jailbreak for iOS 15+

After jailbreaking, install **Cydia** or **Sileo** (package managers) to
install additional tools.

## Post-Jailbreak Setup

### SSH Access

```bash
# Default SSH credentials after jailbreak:
# User: root / Password: alpine
# User: mobile / Password: alpine

# SSH to the device (over USB with iproxy)
iproxy 2222:22 &
ssh root@localhost -p 2222

# SSH over Wi-Fi
ssh root@<device_ip>

# Change the default password immediately
passwd root
passwd mobile
```

### Installing Tools via Cydia/Sileo

After jailbreaking, install these packages from Cydia/Sileo:

| Package | Purpose |
|---|---|
| OpenSSH | SSH access to the device |
| Frida | Runtime instrumentation server |
| AppSync Unified | Install unsigned IPAs |
| Filza File Manager | GUI file browser with root access |
| NewTerm | On-device terminal |

### Frida Server on iOS

```bash
# Frida
# https://github.com/frida/frida

# Option 1: Install via Cydia
# Add the Frida repository: https://build.frida.re
# Install "Frida" package from Cydia

# Option 2: Manual installation
# Download frida-server for iOS arm64 from GitHub releases
# https://github.com/frida/frida/releases
# Example: frida-server-17.6.2-ios-arm64.xz

# Copy to device
scp frida-server-17.6.2-ios-arm64 root@<device_ip>:/usr/sbin/frida-server
ssh root@<device_ip> chmod 755 /usr/sbin/frida-server

# Start frida-server
ssh root@<device_ip> /usr/sbin/frida-server &

# Verify from host — list running processes
frida-ps -U
```

## Communicating with iOS Devices from Linux

### libimobiledevice Tools

libimobiledevice provides Linux-compatible tools for iOS device communication.

```bash
# Install on Kali
sudo apt install -y libimobiledevice-utils ideviceinstaller usbmuxd libusbmuxd-tools

# List connected devices
idevice_id -l

# Show device info
ideviceinfo

# Show specific domain (e.g., disk usage)
ideviceinfo -q com.apple.disk_usage

# Install an IPA
ideviceinstaller install target.ipa

# List installed apps
ideviceinstaller list

# Uninstall an app
ideviceinstaller uninstall com.example.app
```

### USB Port Forwarding with iproxy

```bash
# Forward local port 2222 to device port 22 (SSH)
iproxy 2222:22 &

# Then SSH via the forwarded port
ssh -p 2222 root@localhost

# Forward Frida port
iproxy 27042:27042 &
```

## Proxy Configuration for iOS

### Manual Proxy Setup

On the iOS device:
1. Settings > Wi-Fi > tap the connected network
2. Scroll down to HTTP Proxy > Configure Proxy > Manual
3. Enter the testing machine's IP and Burp/ZAP port (e.g., 8080)

### Installing Burp CA Certificate

1. Export the Burp CA certificate in DER format
2. Host it on a web server or send via AirDrop
3. On the device: open the certificate file
4. Settings > General > VPN & Device Management > install the profile
5. Settings > General > About > Certificate Trust Settings > enable full
   trust for the Burp certificate

For apps that do not trust user-installed certificates, use Frida-based
SSL pinning bypass (covered in the SSL Pinning file).

## Extracting IPAs

### From a Jailbroken Device

```bash
# Find the app's bundle path
ssh root@<device_ip> find /var/containers/Bundle/Application -name "*.app" 2>/dev/null

# Or find by bundle ID
ssh root@<device_ip> find /var/containers/Bundle/Application -maxdepth 3 -name Info.plist \
    -exec grep -l "com.example.app" {} \;

# Copy the .app directory
scp -r root@<device_ip>:/var/containers/Bundle/Application/<UUID>/Target.app ./

# Create an IPA from the .app directory
mkdir -p Payload
cp -r Target.app Payload/
zip -r target.ipa Payload/
```

### Decrypted IPA (for encrypted App Store apps)

App Store apps are encrypted with FairPlay DRM. To analyze them, the binary
must be decrypted on a jailbroken device. Tools like **frida-ios-dump** or
**flexdecrypt** can dump decrypted binaries at runtime.

## Essential Tool Checklist

| Tool | Purpose | Platform |
|---|---|---|
| frida / frida-tools | Runtime instrumentation | Host (pip3) + Device |
| objection | Mobile exploration framework | Host (pip3) |
| libimobiledevice | iOS device communication from Linux | Host (apt) |
| ideviceinstaller | IPA installation from Linux | Host (apt) |
| iproxy | USB port forwarding | Host (`sudo apt install -y libusbmuxd-tools`) |
| Burp Suite / ZAP | Traffic interception | Host |

## References

### Tools

- [Frida](https://github.com/frida/frida)
- [objection](https://github.com/sensepost/objection)
- [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)

### Official Documentation

- [OWASP MASTG — iOS Testing Setup](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0052/)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)

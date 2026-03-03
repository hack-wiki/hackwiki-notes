% Filename: 09-mobile-security/ios/03-dynamic-analysis.md
% Display name: Step 3 - iOS Dynamic Analysis
% Last update: 2026-02-11
% Authors: @TristanInSec

# iOS Dynamic Analysis

## Overview

iOS dynamic analysis involves runtime instrumentation of apps on a jailbroken
device — hooking Objective-C and Swift methods with Frida, inspecting the
Keychain and filesystem, bypassing security controls, and monitoring runtime
behavior. Since iOS apps are compiled to native code, Frida's ability to hook
at the function level is essential for understanding app behavior.

## Frida on iOS

### Listing Processes

```bash
# Frida
# https://github.com/frida/frida

# List running apps on USB-connected device
frida-ps -Ua

# List all installed apps (including not running)
frida-ps -Uai

# List all processes
frida-ps -U
```

### Attaching and Spawning

```bash
# Frida
# https://github.com/frida/frida

# Attach to a running app by name
frida -U -n "TargetApp"

# Attach by bundle identifier
frida -U -N com.example.app

# Spawn an app with Frida attached from launch
frida -U -f com.example.app

# Load a script
frida -U -f com.example.app -l hook_script.js
```

### Hooking Objective-C Methods

```javascript
// hook_objc.js — hook an Objective-C method
if (ObjC.available) {
    var LoginController = ObjC.classes.LoginController;

    // Hook an instance method (- prefix in ObjC)
    Interceptor.attach(LoginController['- validateCredentials:password:'].implementation, {
        onEnter: function (args) {
            // args[0] = self, args[1] = _cmd, args[2] = first param
            var username = ObjC.Object(args[2]).toString();
            var password = ObjC.Object(args[3]).toString();
            console.log('[+] Username: ' + username);
            console.log('[+] Password: ' + password);
        },
        onLeave: function (retval) {
            console.log('[+] Return: ' + retval);
        }
    });
}
```

### Hooking Swift Methods

Swift methods are name-mangled, making them harder to hook. Find the mangled
name first:

```javascript
// find_swift.js — search for Swift method names
if (ObjC.available) {
    // List all methods of a class
    var methods = ObjC.classes.TargetClass.$ownMethods;
    methods.forEach(function (method) {
        console.log(method);
    });
}

// Or search by module exports
Module.enumerateExports('TargetApp', {
    onMatch: function (exp) {
        if (exp.name.includes('login') || exp.name.includes('Login')) {
            console.log(exp.name + ' @ ' + exp.address);
        }
    },
    onComplete: function () {}
});
```

### Listing ObjC Classes and Methods

```javascript
// enum_objc.js — enumerate Objective-C classes
if (ObjC.available) {
    // List all classes
    for (var cls in ObjC.classes) {
        if (cls.includes('Login') || cls.includes('Auth')) {
            console.log(cls);
        }
    }

    // List all methods of a specific class
    var methods = ObjC.classes.LoginController.$ownMethods;
    methods.forEach(function (m) {
        console.log(m);
    });
}
```

## Objection on iOS

```bash
# objection
# https://github.com/sensepost/objection

# Attach to a running iOS app
objection -n "TargetApp" start

# Or by bundle identifier
objection -n com.example.app start
```

### Common iOS Objection Commands

```bash
# List URL schemes registered by the app
ios info binary

# List the app's plist data
ios plist cat Info.plist

# Dump the Keychain
ios keychain dump

# Dump cookies
ios cookies get

# List pasteboard contents
ios pasteboard monitor

# Disable jailbreak detection
ios jailbreak disable

# Disable SSL pinning
ios sslpinning disable

# List files in the app sandbox
env
ls

# Download a file
file download /var/mobile/Containers/Data/Application/<UUID>/Documents/data.db ./

# Search for files by name
ios bundles list_frameworks

# Hook a method
ios hooking watch method "-[LoginController validateCredentials:password:]" --dump-args --dump-return

# Set a method's return value
ios hooking set return_value "-[SecurityManager isJailbroken]" false
```

## Keychain Inspection

The iOS Keychain stores credentials, tokens, certificates, and keys. On a
jailbroken device, Keychain items can be dumped.

### Dumping with Objection

```bash
# Inside objection session:
ios keychain dump
ios keychain dump_raw
```

### Dumping with Frida

```javascript
// dump_keychain.js — read Keychain items
if (ObjC.available) {
    var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
    var query = NSMutableDictionary.alloc().init();

    // kSecClass = kSecClassGenericPassword
    query.setObject_forKey_('genp', 'class');
    // kSecReturnAttributes + kSecReturnData
    query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), 'r_Attributes');
    query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), 'r_Data');
    // kSecMatchLimit = kSecMatchLimitAll
    query.setObject_forKey_('m_LimitAll', 'm_Limit');

    console.log('[*] Keychain query built — use objection for easier extraction');
}
```

Objection's `ios keychain dump` is the easiest method for Keychain extraction.

## Filesystem Inspection

### App Sandbox Structure

```bash
# On the jailbroken device:
# App bundle (read-only, contains the binary and resources)
ls /var/containers/Bundle/Application/<UUID>/Target.app/

# App data (read-write, contains runtime data)
ls /var/mobile/Containers/Data/Application/<UUID>/

# Subdirectories:
# Documents/   — persistent app data
# Library/     — preferences, caches, cookies
# Library/Preferences/  — NSUserDefaults plist files
# Library/Caches/       — cached data
# tmp/         — temporary files
```

### Searching for Sensitive Data

```bash
# On the jailbroken device, search the app's data directory:
find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.db" -o -name "*.sqlite"
find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.plist"

# Check NSUserDefaults (stored as plist)
cat /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.example.app.plist

# Inspect SQLite databases
sqlite3 /var/mobile/Containers/Data/Application/<UUID>/Documents/app.db ".tables"
sqlite3 /var/mobile/Containers/Data/Application/<UUID>/Documents/app.db "SELECT * FROM users;"
```

## Jailbreak Detection Bypass

### With Objection

```bash
# Inside objection session:
ios jailbreak disable
```

### With Frida

```javascript
// bypass_jailbreak.js — hook common jailbreak detection checks
if (ObjC.available) {
    // Hook NSFileManager fileExistsAtPath:
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function (args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function (retval) {
            var jailbreakPaths = [
                '/Applications/Cydia.app',
                '/usr/sbin/sshd',
                '/bin/bash',
                '/usr/bin/ssh',
                '/etc/apt',
                '/private/var/lib/apt/',
                '/private/var/lib/cydia'
            ];
            for (var i = 0; i < jailbreakPaths.length; i++) {
                if (this.path.includes(jailbreakPaths[i])) {
                    console.log('[+] Jailbreak check bypassed: ' + this.path);
                    retval.replace(0x0);  // Return false
                }
            }
        }
    });

    // Hook canOpenURL: to block Cydia URL scheme check
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
        onEnter: function (args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function (retval) {
            if (this.url.includes('cydia://')) {
                console.log('[+] Blocked canOpenURL for: ' + this.url);
                retval.replace(0x0);
            }
        }
    });
}
```

## Traffic Monitoring

### Monitoring Network Calls with Frida

```javascript
// hook_nsurlsession.js — log all NSURLSession requests
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;

    // Hook dataTaskWithRequest:completionHandler:
    Interceptor.attach(
        NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter: function (args) {
            var request = ObjC.Object(args[2]);
            console.log('[+] URL: ' + request.URL().absoluteString());
            console.log('[+] Method: ' + request.HTTPMethod());
        }
    });
}
```

## References

### Tools

- [Frida](https://github.com/frida/frida)
- [objection](https://github.com/sensepost/objection)

### Official Documentation

- [OWASP MASTG — iOS Dynamic Analysis](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0057/)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)

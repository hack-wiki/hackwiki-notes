% Filename: 09-mobile-security/android/03-dynamic-analysis.md
% Display name: Step 3 - Android Dynamic Analysis
% Last update: 2026-02-11
% Authors: @TristanInSec

# Android Dynamic Analysis

## Overview

Android dynamic analysis examines an app while it runs — hooking methods at
runtime with Frida, monitoring logs and filesystem changes, intercepting
network traffic, and manipulating app behavior. This complements static
analysis by revealing runtime secrets, server-side logic, and behaviors that
are obfuscated or loaded dynamically.

## Frida Basics

Frida injects a JavaScript engine into a running process, allowing you to
hook any function, read memory, and modify behavior in real time.

### Listing Processes and Apps

```bash
# Frida
# https://github.com/frida/frida

# List running processes on USB-connected device
frida-ps -U

# List only applications (not system processes)
frida-ps -Ua

# List installed applications (including not running)
frida-ps -Uai
```

### Attaching to a Running App

```bash
# Frida
# https://github.com/frida/frida

# Attach to a running app by package identifier
frida -U -N com.example.app

# Spawn an app (start it with Frida attached from the beginning)
frida -U -f com.example.app

# Attach and load a script
frida -U -N com.example.app -l hook_script.js

# Spawn and load a script
frida -U -f com.example.app -l hook_script.js
```

### Basic Frida Scripts

Hook a Java method and log arguments:

```javascript
// hook_login.js — hook a login method to capture credentials
Java.perform(function () {
    var LoginActivity = Java.use('com.example.app.LoginActivity');

    LoginActivity.login.implementation = function (username, password) {
        console.log('[+] Username: ' + username);
        console.log('[+] Password: ' + password);

        // Call the original method
        return this.login(username, password);
    };
});
```

Hook an overloaded method:

```javascript
// hook_overloaded.js — hook a method with specific parameter types
Java.perform(function () {
    var MyClass = Java.use('com.example.app.MyClass');

    MyClass.process.overload('java.lang.String', 'int').implementation =
        function (str, num) {
            console.log('[+] String: ' + str + ', Int: ' + num);
            return this.process(str, num);
        };
});
```

Enumerate loaded classes:

```javascript
// enum_classes.js — list all loaded classes matching a pattern
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.includes('example')) {
                console.log(className);
            }
        },
        onComplete: function () {
            console.log('[*] Done enumerating classes');
        }
    });
});
```

List methods of a class:

```javascript
// list_methods.js — list all methods of a specific class
Java.perform(function () {
    var cls = Java.use('com.example.app.TargetClass');
    var methods = cls.class.getDeclaredMethods();
    methods.forEach(function (method) {
        console.log(method.toString());
    });
});
```

### Hooking Native Functions

```javascript
// hook_native.js — hook a native function in a shared library
Interceptor.attach(Module.findExportByName('libnative.so', 'secret_function'), {
    onEnter: function (args) {
        console.log('[+] secret_function called');
        console.log('[+] arg0: ' + args[0]);
        console.log('[+] arg1: ' + args[1].readUtf8String());
    },
    onLeave: function (retval) {
        console.log('[+] Return value: ' + retval);
    }
});
```

## Objection

Objection provides pre-built commands for common mobile testing tasks, built
on top of Frida.

### Starting a Session

```bash
# objection
# https://github.com/sensepost/objection

# Attach to a running app (device with frida-server)
objection -n com.example.app start

# Spawn the app
objection --spawn -n com.example.app start

# Connect over network instead of USB
objection -N -h <device_ip> -n com.example.app start
```

### Common Objection Commands

Once inside the objection REPL:

```bash
# List activities
android hooking list activities

# List services
android hooking list services

# List broadcast receivers
android hooking list receivers

# List all classes (filter with grep)
android hooking list classes
android hooking search classes login

# List methods of a class
android hooking list class_methods com.example.app.LoginActivity

# Hook a method and watch arguments/return values
android hooking watch class_method com.example.app.LoginActivity.login --dump-args --dump-return

# Hook all methods in a class
android hooking watch class com.example.app.LoginActivity

# Set a method's return value
android hooking set return_value com.example.app.SecurityCheck.isRooted false

# Dump the Android Keystore
android keystore list

# List files in the app's data directory
env
ls

# Download a file from the device
file download /data/data/com.example.app/shared_prefs/prefs.xml ./prefs.xml

# Dump shared preferences
android hooking search classes SharedPreferences

# Check for root detection
android root disable

# Disable SSL pinning
android sslpinning disable
```

## Logcat Monitoring

Android logs often contain sensitive information leaked by the app.

```bash
# View all logs
adb logcat

# Filter by app process
adb logcat --pid=$(adb shell pidof com.example.app)

# Filter by tag
adb logcat -s "MyAppTag"

# Filter by priority (V=Verbose, D=Debug, I=Info, W=Warn, E=Error)
adb logcat *:E

# Clear log buffer and start fresh
adb logcat -c && adb logcat

# Save logs to file
adb logcat > app_logs.txt
```

Look for:
- Hardcoded credentials or tokens logged during debugging
- API endpoints and parameters
- Stack traces revealing internal logic
- SQL queries logged by the ORM layer

## Filesystem Inspection

### App Data Directories

```bash
# App private data (requires root)
adb shell ls /data/data/com.example.app/

# Common subdirectories:
# /databases/     — SQLite databases
# /shared_prefs/  — XML preference files
# /files/         — App-created files
# /cache/         — Cached data

# Pull a database for inspection
adb pull /data/data/com.example.app/databases/app.db ./

# Open with sqlite3
sqlite3 app.db
sqlite> .tables
sqlite> SELECT * FROM users;

# Pull shared preferences
adb pull /data/data/com.example.app/shared_prefs/ ./shared_prefs/

# Check external storage for sensitive data
adb shell ls /sdcard/Android/data/com.example.app/
```

### ADB Backup (if allowBackup=true)

```bash
# Create a backup of the app's data
adb backup -f backup.ab com.example.app

# Extract the backup (requires Android Backup Extractor — abe.jar)
# Convert .ab to .tar
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar
```

## Traffic Interception

### Using Burp Suite with ADB

```bash
# Set device proxy to Burp listener
adb shell settings put global http_proxy <burp_ip>:8080

# After testing, remove the proxy
adb shell settings put global http_proxy :0
```

For apps that use their own HTTP stack or WebSocket connections, use Frida to
hook the networking layer directly.

### Monitoring DNS Queries

```bash
# Watch DNS resolution on the device
adb shell dumpsys connectivity | grep -i dns
```

## Interacting with Exported Components

```bash
# Start an exported activity
adb shell am start -n com.example.app/.AdminActivity

# Start with intent data
adb shell am start -n com.example.app/.DeepLinkActivity \
    -d "example://admin?token=test"

# Send a broadcast to an exported receiver
adb shell am broadcast -a com.example.DEBUG \
    -n com.example.app/.DebugReceiver \
    --es "command" "dump_data"

# Query an exported content provider
adb shell content query --uri content://com.example.app.provider/users
```

## References

### Tools

- [Frida](https://github.com/frida/frida)
- [objection](https://github.com/sensepost/objection)

### Official Documentation

- [OWASP MASTG — Android Dynamic Analysis](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)

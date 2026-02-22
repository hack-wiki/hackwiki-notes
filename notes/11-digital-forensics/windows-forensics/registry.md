% Filename: 11-digital-forensics/windows-forensics/registry.md
% Display name: Registry Forensics
% Last update: 2026-02-11
% Authors: @TristanInSec

# Registry Forensics

## Overview

The Windows Registry is a hierarchical database that stores system
configuration, user preferences, installed software, network settings, and
many other system parameters. For forensic investigators, the registry
provides evidence of program execution, user activity, connected devices,
network connections, and persistence mechanisms. Registry hives can be
analyzed offline from forensic images using tools like reglookup, regripper,
and chntpw.

## Registry Hive Files

| Hive | File Location | Contents |
|---|---|---|
| HKLM\SAM | C:\Windows\System32\config\SAM | User accounts, password hashes |
| HKLM\SECURITY | C:\Windows\System32\config\SECURITY | Security policies, LSA secrets |
| HKLM\SOFTWARE | C:\Windows\System32\config\SOFTWARE | Installed software, OS configuration |
| HKLM\SYSTEM | C:\Windows\System32\config\SYSTEM | Hardware, services, boot configuration |
| HKU\<SID> | C:\Users\<user>\NTUSER.DAT | Per-user settings, MRU lists, UserAssist |
| HKU\<SID> | C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat | ShellBags, COM classes |

## Analysis with reglookup

reglookup reads registry hive files and outputs key/value data in a
parseable format.

```bash
# reglookup
# https://www.kali.org/tools/reglookup/

# Dump all keys and values from a hive
reglookup /evidence/config/SOFTWARE

# Search for a specific key path
reglookup -p "Microsoft/Windows/CurrentVersion/Run" /evidence/config/SOFTWARE

# Output specific value types only
reglookup -t SZ /evidence/config/SOFTWARE

# Output in tab-separated format (default)
reglookup /evidence/config/NTUSER.DAT > ntuser_dump.tsv

# Search for a string pattern in values
reglookup /evidence/config/SOFTWARE | grep -i "malware"
```

## Analysis with RegRipper

RegRipper automates the extraction of forensically significant data from
registry hives using plugins.

```bash
# RegRipper
# https://github.com/keydet89/RegRipper3.0

# Auto-detect hive type and run appropriate plugins
regripper -r /evidence/config/SAM -a

# Run with a specific plugin
regripper -r /evidence/config/SOFTWARE -p winver
regripper -r /evidence/config/SYSTEM -p services
regripper -r /evidence/config/NTUSER.DAT -p userassist

# List all available plugins
regripper -l

# Guess the hive type
regripper -r /evidence/config/SOFTWARE -g

# Common plugins by hive:

# SAM hive:
regripper -r /evidence/config/SAM -p samparse    # User accounts and details

# SYSTEM hive:
regripper -r /evidence/config/SYSTEM -p compname  # Computer name
regripper -r /evidence/config/SYSTEM -p timezone   # Timezone setting
regripper -r /evidence/config/SYSTEM -p nic2       # Network interfaces
regripper -r /evidence/config/SYSTEM -p services   # Installed services
regripper -r /evidence/config/SYSTEM -p shimcache  # AppCompat cache

# SOFTWARE hive:
regripper -r /evidence/config/SOFTWARE -p winver    # Windows version
regripper -r /evidence/config/SOFTWARE -p networklist  # Network profiles
regripper -r /evidence/config/SOFTWARE -p run       # Run keys (persistence)
regripper -r /evidence/config/SOFTWARE -p uninstall # Installed programs

# NTUSER.DAT hive:
regripper -r /evidence/NTUSER.DAT -p userassist    # Program execution counts
regripper -r /evidence/NTUSER.DAT -p recentdocs    # Recent documents
regripper -r /evidence/NTUSER.DAT -p typedurls      # Typed URLs in IE/Edge
regripper -r /evidence/NTUSER.DAT -p run            # User Run keys
regripper -r /evidence/NTUSER.DAT -p typedpaths     # Typed paths in Explorer
```

## Analysis with chntpw

chntpw provides an interactive registry editor and SAM password tool for
offline registry hives.

```bash
# chntpw
# https://pogostick.net/~pnh/ntpasswd/

# List users from a SAM hive
chntpw -l /evidence/config/SAM

# Interactive registry editor
chntpw -e /evidence/config/SOFTWARE

# Interactive editor commands:
#   ls           — list subkeys of current key
#   cd <key>     — change to a subkey
#   cat <value>  — display a value
#   nk <name>    — create a new key
#   q            — quit

# Edit a specific user in SAM (password reset / enable)
chntpw -u Administrator /evidence/config/SAM
```

## Forensically Significant Registry Keys

### Persistence Locations

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKLM\SYSTEM\CurrentControlSet\Services (Start = 2 for auto-start)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components
```

### Program Execution

```text
UserAssist:
  HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
  Records program execution with run count and last run time
  Values are ROT13 encoded

ShimCache (AppCompatCache):
  HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
  Records executables that were executed or present on disk

MUICache:
  HKU\<SID>\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
  Records friendly names of executed programs

RecentApps:
  HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps
  Records recently launched applications with timestamps
```

### Network Activity

```text
Network Profiles:
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
  Records all networks the system connected to with first/last connect times

Network Interfaces:
  HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
  IP address configuration per network interface

Wireless Networks:
  HKLM\SOFTWARE\Microsoft\WLANSVC\Profiles
  Stored wireless network profiles
```

### USB and Device History

```text
USB Storage:
  HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
  Records USB storage devices with vendor, product, serial number

USB Devices:
  HKLM\SYSTEM\CurrentControlSet\Enum\USB
  Records all USB devices (including non-storage)

MountPoints2:
  HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
  Records drive letters assigned to devices per user

Device Setup:
  HKLM\SYSTEM\Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration
  Records first connection time of devices
```

### User Activity

```text
Recent Documents:
  HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
  Records recently accessed documents by extension

Typed URLs:
  HKU\<SID>\SOFTWARE\Microsoft\Internet Explorer\TypedURLs
  URLs typed in Internet Explorer / Edge address bar

Typed Paths:
  HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
  Paths typed in Explorer address bar

Last Visited MRU:
  HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
  Records last directories visited via open/save dialogs

Open/Save MRU:
  HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
  Records files opened or saved via dialogs
```

## References

### Tools

- [RegRipper](https://github.com/keydet89/RegRipper3.0)
- [reglookup](https://www.kali.org/tools/reglookup/)
- [chntpw](https://pogostick.net/~pnh/ntpasswd/)

### Further Reading

- [Windows Registry Forensics (Harlan Carvey)](https://www.elsevier.com/books/windows-registry-forensics/carvey/978-0-12-803291-6)

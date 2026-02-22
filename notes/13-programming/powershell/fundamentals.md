% Filename: 13-programming/powershell/fundamentals.md
% Display name: PowerShell Fundamentals
% Last update: 2026-02-11
% Authors: @TristanInSec

# PowerShell Fundamentals

## Overview

PowerShell is an object-oriented scripting language and shell built on .NET.
Unlike Bash where everything is text, PowerShell commands output structured
objects with properties and methods. This makes data manipulation powerful
but requires understanding the object pipeline. This file covers core syntax,
data types, control flow, functions, and working with the object pipeline.

## Variables and Data Types

```powershell
# PowerShell
# https://learn.microsoft.com/en-us/powershell/

# Variable assignment
$target = "10.0.0.1"
$port = 80
$verbose = $true

# Data types
[string]$name = "admin"
[int]$count = 42
[bool]$flag = $true
[array]$ports = @(22, 80, 443)
[hashtable]$config = @{Target="10.0.0.1"; Port=80}

# String operations
$str = "Hello World"
$str.Length                      # 11
$str.ToUpper()                   # HELLO WORLD
$str.ToLower()                   # hello world
$str.Contains("World")           # True
$str.Replace("World", "PS")      # Hello PS
$str.Split(" ")                  # @("Hello", "World")
$str.Substring(0, 5)             # Hello

# String interpolation
$msg = "Scanning $target on port $port"
$msg = "Found $($ports.Count) ports"  # expression in string

# Here-strings (multiline)
$body = @"
Host: $target
Port: $port
Status: Open
"@
```

## Arrays and Hashtables

```powershell
# PowerShell — collections
# https://learn.microsoft.com/en-us/powershell/

# Arrays
$ports = @(22, 80, 443, 8080)
$ports[0]                        # 22
$ports[-1]                       # 8080
$ports.Count                     # 4
$ports += 3389                   # append
$ports -contains 80              # True

# Array slicing
$ports[0..2]                     # 22, 80, 443

# ArrayList (better for frequent modifications)
$list = [System.Collections.ArrayList]::new()
$list.Add("item1") | Out-Null
$list.Add("item2") | Out-Null
$list.Remove("item1")

# Hashtables
$services = @{
    22   = "SSH"
    80   = "HTTP"
    443  = "HTTPS"
    3389 = "RDP"
}
$services[80]                    # HTTP
$services.Keys                   # 22, 80, 443, 3389
$services.Values                 # SSH, HTTP, HTTPS, RDP
$services.ContainsKey(22)        # True
$services[8080] = "HTTP-Alt"     # add entry

# Ordered hashtable (preserves insertion order)
$ordered = [ordered]@{
    First  = 1
    Second = 2
    Third  = 3
}
```

## Operators

```powershell
# PowerShell — operators
# https://learn.microsoft.com/en-us/powershell/

# Comparison (case-insensitive by default)
"abc" -eq "ABC"                  # True
"abc" -ceq "ABC"                 # False (case-sensitive)
5 -gt 3                          # True
5 -lt 3                          # False
5 -ge 5                          # True
5 -le 5                          # True
"abc" -ne "def"                  # True

# Pattern matching
"Hello World" -like "*World*"    # True (wildcard)
"Hello World" -match "^Hello"    # True (regex)
$Matches[0]                      # "Hello" (captured match)

# Containment
@(1,2,3) -contains 2            # True
2 -in @(1,2,3)                   # True
@(1,2,3) -notcontains 5         # True

# Logical
$true -and $false                # False
$true -or $false                 # True
-not $false                      # True
!$false                          # True

# Type operators
"text" -is [string]              # True
42 -is [int]                     # True
```

## Control Flow

```powershell
# PowerShell — control flow
# https://learn.microsoft.com/en-us/powershell/

# If / ElseIf / Else
if ($port -eq 80) {
    Write-Host "HTTP"
} elseif ($port -eq 443) {
    Write-Host "HTTPS"
} else {
    Write-Host "Other: $port"
}

# Switch
switch ($port) {
    22    { "SSH" }
    80    { "HTTP" }
    443   { "HTTPS" }
    3389  { "RDP" }
    default { "Unknown" }
}

# For loop
for ($i = 1; $i -le 254; $i++) {
    $ip = "10.0.0.$i"
}

# ForEach loop
foreach ($port in @(22, 80, 443)) {
    Write-Host "Checking port $port"
}

# ForEach-Object (pipeline)
@(22, 80, 443) | ForEach-Object {
    Write-Host "Port: $_"
}

# While loop
$attempts = 0
while ($attempts -lt 5) {
    $attempts++
    Write-Host "Attempt $attempts"
}

# Do-While / Do-Until
do {
    $userInput = Read-Host "Enter 'quit' to exit"
} while ($userInput -ne "quit")

# Try / Catch / Finally
try {
    $result = Test-Connection -ComputerName $target -Count 1 -ErrorAction Stop
    Write-Host "$target is up"
} catch {
    Write-Host "Error: $_"
} finally {
    Write-Host "Done"
}
```

## Functions

```powershell
# PowerShell — functions
# https://learn.microsoft.com/en-us/powershell/

# Basic function
function Test-Port {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [int]$Port,

        [int]$Timeout = 1000
    )

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)

        if ($wait) {
            $tcp.EndConnect($connect)
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

# Usage
if (Test-Port -ComputerName "10.0.0.1" -Port 80) {
    Write-Host "Port 80 is open"
}

# Function with pipeline input
function Get-IPRange {
    param(
        [string]$Subnet = "10.0.0"
    )
    1..254 | ForEach-Object { "$Subnet.$_" }
}

# Usage: Get-IPRange -Subnet "192.168.1" | ForEach-Object { ... }
```

## Pipeline and Object Manipulation

```powershell
# PowerShell — pipeline
# https://learn.microsoft.com/en-us/powershell/

# Pipeline basics — each cmdlet passes objects to the next
Get-Process | Where-Object { $_.CPU -gt 10 } | Sort-Object CPU -Descending | Select-Object -First 5

# Select specific properties
Get-Process | Select-Object Name, Id, CPU, WorkingSet

# Filter with Where-Object
Get-Service | Where-Object { $_.Status -eq "Running" }

# Sort
Get-Process | Sort-Object WorkingSet -Descending

# Group
Get-WinEvent -LogName System -MaxEvents 100 | Group-Object LevelDisplayName  # Windows only; Get-EventLog removed in PS 7+

# Measure (count, sum, average)
Get-Process | Measure-Object WorkingSet -Sum -Average

# ForEach-Object (transform each object)
Get-ChildItem *.txt | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        SizeKB = [math]::Round($_.Length / 1KB, 2)
    }
}

# Export to CSV
Get-Process | Select-Object Name, Id, CPU | Export-Csv -Path processes.csv -NoTypeInformation

# Export to JSON
Get-Process | Select-Object Name, Id, CPU | ConvertTo-Json | Out-File processes.json

# Import from CSV
$data = Import-Csv -Path data.csv
$data | Where-Object { $_.Status -eq "Open" }
```

## File Operations

```powershell
# PowerShell — file operations
# https://learn.microsoft.com/en-us/powershell/

# Read a file
$content = Get-Content -Path "C:\file.txt"
$content = Get-Content -Path "C:\file.txt" -Raw    # entire file as one string

# Read specific lines
$first10 = Get-Content -Path "C:\file.txt" -TotalCount 10
$last5 = Get-Content -Path "C:\file.txt" -Tail 5

# Write to file
Set-Content -Path "output.txt" -Value "Results"
Add-Content -Path "output.txt" -Value "More results"

# Search in files (like grep)
Select-String -Path "C:\logs\*.log" -Pattern "error" -CaseSensitive
Select-String -Path "C:\logs\*.log" -Pattern "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# Find files
Get-ChildItem -Path C:\ -Recurse -Filter "*.config" -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Recurse -Include "*.txt","*.log" | Where-Object { $_.Length -gt 1MB }

# File hashing
Get-FileHash -Path "file.exe" -Algorithm SHA256
Get-FileHash -Path "file.exe" -Algorithm MD5
```

## Working with JSON and XML

```powershell
# PowerShell — structured data
# https://learn.microsoft.com/en-us/powershell/

# Parse JSON
$json = '{"name": "test", "ports": [22, 80, 443]}'
$obj = $json | ConvertFrom-Json
$obj.name                        # test
$obj.ports                       # 22, 80, 443

# Create JSON
$data = @{
    target = "10.0.0.1"
    ports  = @(22, 80, 443)
    status = "scanned"
}
$jsonOutput = $data | ConvertTo-Json -Depth 3
$jsonOutput | Out-File "results.json"

# Parse XML
[xml]$xml = Get-Content "config.xml"
$xml.configuration.setting.value

# Web API call with JSON
$response = Invoke-RestMethod -Uri "https://api.example.com/data" -Method Get
$response | ConvertTo-Json
```

## Regular Expressions

```powershell
# PowerShell — regex
# https://learn.microsoft.com/en-us/powershell/

# Match operator
"192.168.1.100" -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
$Matches[0]                      # 192.168.1.100

# Named capture groups
"Failed login for admin from 10.0.0.50" -match "for (?<user>\S+) from (?<ip>\S+)"
$Matches.user                    # admin
$Matches.ip                      # 10.0.0.50

# Replace
"Hello World" -replace "World", "PowerShell"    # Hello PowerShell
"test123" -replace "\d+", "XXX"                 # testXXX

# Select-String (grep equivalent)
Get-Content "log.txt" | Select-String -Pattern "ERROR|WARN"
Select-String -Path "*.log" -Pattern "password" -CaseSensitive
```

## References

### Further Reading

- [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)
- [PowerShell About Topics](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/00-introduction)

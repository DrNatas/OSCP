---
title: Enumeration Checklist - What to Scan First
tags: [checklist, enumeration, recon]
---

# Enumeration Checklist

Run through this methodically. Thorough enumeration wins exams.

## Phase 1: Network & Port Scanning (First 30 minutes)

### Basic Nmap (Run First)
```bash
# All ports, fast
nmap -p- --min-rate=5000 TARGET -o nmap_allports.txt

# Get versions and scripts (on discovered ports)
nmap -sV -sC -p PORT1,PORT2,PORT3 TARGET -o nmap_detailed.txt
```

Checklist:
- [ ] Scan completed without timing out
- [ ] All ports documented
- [ ] Service versions identified
- [ ] OS type identified

### What to Look For
```
Common OSCP ports:
Port 21   → FTP (anonymous login?)
Port 22   → SSH (old version? key exchange?)
Port 53   → DNS (zone transfer?)
Port 80   → HTTP (web application)
Port 139  → SMB (enumeration)
Port 445  → SMB (enumeration)
Port 389  → LDAP (enumeration)
Port 443  → HTTPS (web application)
Port 1433 → MSSQL (authentication)
Port 3306 → MySQL (authentication, sqli)
Port 3389 → RDP (credentials)
Port 5985 → WinRM (authentication)
```

## Phase 2: Service Enumeration (Next 1-2 hours)

### For Each Open Port

#### Port 21 (FTP)
```bash
# Check anonymous login
ftp TARGET
> anonymous
> (password: just hit enter or 'anonymous')
> ls -la

# If successful, download everything
```

#### Port 22 (SSH)
```bash
# Banner grab
ssh -v TARGET

# Check for key exchange vulnerabilities
ssh -v TARGET | grep -i "kex\|cipher\|mac"

# Try common credentials
ssh root@TARGET
ssh admin@TARGET
```

#### Port 53 (DNS)
```bash
# Zone transfer attempt
nslookup
> server TARGET
> ls -d TARGET

# Using dig
dig @TARGET TARGET axfr
```

#### Port 80/443 (HTTP/HTTPS)
```bash
# Basic connection and header info
curl -v http://TARGET

# Directory scanning
ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

# Web application scan
nuclei -u http://TARGET -t /path/to/templates

# Check for common vulnerabilities
# - SQL injection: ?id=1'
# - File upload: look for upload forms
# - LFI: ?file=../../../etc/passwd
# - SSTI: test template expressions
```

Checklist:
- [ ] Homepage loaded (check source for comments/version info)
- [ ] All pages enumerated with ffuf
- [ ] Form inputs tested for injection
- [ ] File upload endpoints found
- [ ] Technology identified (wordpress? custom app?)
- [ ] Admin/login pages found
- [ ] Database version obtained (if vulnerable)

#### Port 139/445 (SMB)
```bash
# Enumerate shares
smbclient -L //TARGET -N

# List files on share
smbclient //TARGET/SHARE -N

# Recursive mount and explore
mount -t cifs //TARGET/SHARE /mnt/share -o username=guest

# Enumeration tools
enum4linux -a TARGET
```

Checklist:
- [ ] Shares enumerated (null session?)
- [ ] Anonymous access confirmed/denied
- [ ] Writable shares identified
- [ ] Files downloaded and reviewed
- [ ] OS version identified

#### Port 389 (LDAP)
```bash
# Enumeration without authentication
ldapsearch -x -h TARGET -s base namingContexts

# Full enumeration if allowed
ldapsearch -x -h TARGET -b "dc=example,dc=com"
```

#### Port 1433 (MSSQL)
```bash
# Connect without credentials
sqsh -S TARGET -U sa -P ''

# Check databases
SELECT name FROM master.sys.databases;

# Test for command execution
xp_cmdshell 'whoami'
```

#### Port 3306 (MySQL)
```bash
# Connect without password
mysql -h TARGET -u root

# Basic enumeration
SHOW DATABASES;
SHOW TABLES;
SELECT * FROM mysql.user;
```

#### Port 3389 (RDP)
```bash
# Check if accessible
nmap -p 3389 --script rdp-enum TARGET

# Try common credentials
xfreerdp /u:administrator /p:password /v:TARGET
```

#### Port 5985/5986 (WinRM)
```bash
# Check if accessible
nmap -p 5985,5986 --script winrm-enum TARGET

# Test with credentials (if you have them)
```

## Phase 3: Web Application Deep Dive (1-3 hours)

If HTTP/HTTPS is open, go deep:

### Parameter Testing
- [ ] Search parameters: ?q=, ?search=, ?keyword=
- [ ] ID parameters: ?id=1, ?pid=, ?uid=
- [ ] File parameters: ?file=, ?path=, ?include=
- [ ] User parameters: ?user=, ?username=
- [ ] All POST parameters in forms
- [ ] Cookie values
- [ ] HTTP headers (User-Agent, Referer)

### Vulnerability Testing Pattern
For each parameter, test:
```
1. Basic test: PARAM=1
2. SQL Injection: PARAM=1' OR '1'='1
3. File Inclusion: PARAM=../../../../etc/passwd
4. Command Injection: PARAM=; id ;
5. SSTI: PARAM={{7*7}} or ${7*7}
```

### Form Testing
- [ ] Login/auth bypass (SQL injection, default creds)
- [ ] File upload (shell upload, bypass tests)
- [ ] Comments/feedback forms (stored XSS)
- [ ] Search fields (blind SQL injection)

Checklist:
- [ ] All forms tested for injection
- [ ] All parameters mapped
- [ ] Vulnerable parameter identified
- [ ] Exploitation method chosen
- [ ] Reverse shell prepared

## Phase 4: Post-Access Enumeration

Once you have shell access:

```bash
# System info
uname -a
cat /proc/version
whoami
id

# Kernel version (vulnerable exploits?)
uname -r

# Processes running
ps aux

# Network connections
netstat -tlnp

# Writable directories
find / -writable 2>/dev/null | head -20

# SUID binaries
find / -perm -4000 2>/dev/null

# Sudo permissions
sudo -l

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.d/

# Installed applications
ls /opt/
ls /usr/local/bin/

# Environment variables
env

# SSH keys
ls -la ~/.ssh/

# Config files with credentials
grep -r "password" /home/ 2>/dev/null
grep -r "credential" /etc/ 2>/dev/null
```

## Checklist Verification

Before moving to exploitation, verify:

- [ ] All ports documented
- [ ] All services identified and tested
- [ ] Vulnerable service found
- [ ] Attack vector identified
- [ ] Exploitation method researched
- [ ] Tools prepared/downloaded
- [ ] Reverse shell payload ready
- [ ] HTB machine walkthrough NOT read yet

If you can't find anything:
1. Revisit nmap results - did you miss a port?
2. Try less common ports (8080, 8888, 9000)
3. Check UDP ports
4. Re-run web application scanning with different wordlists
5. Check for timing/false negatives in scans

Remember: Thorough enumeration reveals vulnerabilities. Rushing to exploitation causes failures.

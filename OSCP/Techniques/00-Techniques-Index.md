---
title: Exploitation Techniques Index
description: Organized by attack type and target service
tags: [techniques, index, reference]
---

# Exploitation Techniques Index

All techniques organized by attack category and linked to real HTB examples.

## Initial Access (Getting Shell)

### Web Application Attacks
- [[SQL-Injection-Path|SQL Injection]] - Extract data, write files, RCE
- [[File-Upload-RCE|File Upload Vulnerabilities]] - Direct shell upload
- [[LFI-to-RCE|Local File Inclusion (LFI)]] - File read, log poisoning, RCE
- [[SSTI-Template-Injection|Server-Side Template Injection (SSTI)]] - Code execution
- [[XXE-XML-Injection|XXE/XML Injection]] - File read, entity expansion
- [[Authentication-Bypass|Authentication Bypass]] - Admin access without credentials
- [[API-Exploitation|API Exploitation]] - Reverse engineer API calls

### Windows Services
- [[SMB-Exploitation|SMB/CIFS Exploitation]] - Null sessions, RelayAttacks
- [[WinRM-RCE|WinRM Remote Code Execution]] - PowerShell execution
- [[RDP-Exploitation|RDP Credential Stuffing]] - Default credentials

### Linux Services
- [[SSH-Key-Abuse|SSH Key Exploitation]] - Authorized_keys abuse
- [[Sudo-RCE|Sudo Misconfiguration]] - Command execution as root
- [[Service-Exploits|Service Vulnerabilities]] - Outdated service RCE

## Privilege Escalation (User → Root/SYSTEM)

### Linux Privilege Escalation
- [[Linux-Privesc-Checklist|Complete Linux PrivEsc Checklist]]
  - SUID binary abuse (GTFOBins)
  - Sudo misconfiguration
  - Kernel exploits
  - Capabilities abuse
  - Cronjob abuse
  - Writable system files
  - Container escape

### Windows Privilege Escalation
- [[Windows-Privesc-Checklist|Complete Windows PrivEsc Checklist]]
  - SUID/ACL abuse
  - DLL hijacking
  - Service misconfigurations
  - Token impersonation
  - Potato exploits
  - UAC bypass
  - SeImpersonatePrivilege abuse

### Active Directory Privilege Escalation
- [[AD-Kerberos-Attacks|Kerberos Ticket Attacks]]
  - Golden Ticket forging
  - Silver Ticket forging
  - Kerberoasting
  - Pre-authentication bypass
- [[AD-Credential-Access|AD Credential Access]]
  - NTLM hash dumping
  - Plaintext credential recovery
  - DPAPI decryption
- [[Domain-Controller-Compromise|Domain Controller Attacks]]
  - DCSync
  - Shadow Copy abuse
  - NTDS.dit extraction

## Post-Exploitation

### After Getting Shell
- [[Post-Exploitation/Local-Enum-Checklist|Local Enumeration Checklist]]
- [[Post-Exploitation/Privesc-Vectors|Finding PrivEsc Vectors]]
- [[Post-Exploitation/Credential-Harvesting|Credential Harvesting Techniques]]
- [[Post-Exploitation/Lateral-Movement|Lateral Movement Methods]]

## By Target Service (What You Find Open)

### Port 21 (FTP)
- Anonymous login
- Weak credentials
- FTP bounce attack

### Port 22 (SSH)
- Weak SSH keys
- Shared private keys
- SSH key abuse

### Port 80/443 (HTTP/HTTPS)
- [[SQL-Injection-Path|SQL Injection]]
- [[File-Upload-RCE|File Upload]]
- [[LFI-to-RCE|LFI/RFI]]
- Web directory traversal

### Port 139/445 (SMB)
- [[SMB-Exploitation|SMB enumeration and exploitation]]
- Null session access
- Anonymous share access

### Port 389/636 (LDAP)
- LDAP injection
- Null bind enumeration
- Anonymous credential search

### Port 1433 (MSSQL)
- SQL injection
- Default sa credentials
- xp_cmdshell RCE

### Port 3306 (MySQL)
- SQL injection
- INTO OUTFILE shell upload
- UDF exploitation

### Port 3389 (RDP)
- Credential stuffing
- BlueKeep (CVE-2019-0708)

### Port 5985/5986 (WinRM)
- [[WinRM-RCE|Authenticated WinRM RCE]]
- Evil-WinRM exploitation

## Quick Decision Tree

```
Found vulnerable web app?
 SQL error visible? → SQLi
 File upload field? → File Upload RCE
 Can include files? → LFI
 Template processing? → SSTI
 XML parsing? → XXE

Got initial shell?
 Run local enum checklist
 Check sudo -l
 Find SUID binaries
 Check kernel version
 Look for weak permissions
 Check cron jobs

Have credentials?
 Try against other services
 Check for reuse (ssh, rdp, smb)
 Lateral movement

On domain joined system?
 Dump NTLM hashes
 Look for cached credentials
 Check for kerberoast-able users
 Attempt DCSync if SYSTEM/DA
```

## By OSCP Points Value

### 20-Point Machines (Usually Easier)
- Single vulnerability chain
- Straightforward exploitation
- Quick privesc method

### 25-Point Machines (Standard)
- Multiple steps to shell
- Requires chained exploits
- Complex privesc required

## Search by Technique Name

Find technique by what you're trying to do:

- **Escape user input filtering:** [[SSTI-Template-Injection|SSTI]], [[XXE-XML-Injection|XXE]]
- **Bypass authentication:** [[SQL-Injection-Path|SQLi]], [[LFI-to-RCE|LFI]], [[Authentication-Bypass|Auth Bypass]]
- **Upload code:** [[File-Upload-RCE|File Upload]], [[SMB-Exploitation|SMB]], [[LFI-to-RCE|LFI with log poison]]
- **Get interactive shell:** [[Payloads/Reverse-Shells|Reverse shells]], WinRM, SSH
- **Escalate from user:** [[Linux-Privesc-Checklist|Linux PrivEsc]], [[Windows-Privesc-Checklist|Windows PrivEsc]]
- **Access domain:** [[AD-Kerberos-Attacks|Kerberos]], [[AD-Credential-Access|Credential harvesting]]
- **Reach other machines:** [[Post-Exploitation/Lateral-Movement|Lateral movement]], pivoting

---

Start with [[00-EXAM-START-HERE|00-EXAM-START-HERE]] during your exam.

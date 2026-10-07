---
title: OSCP Exam Reference Hub
description: Optimized for 24-hour exam - use during testing
tags: [oscp, exam, reference, quick-lookup]
---

# OSCP Exam Reference Hub

Start here during your exam. This is your fastest path to points.

## Quick Navigation

### Before You Start
- Read [[OSCP-Exam-Rules|Exam Rules]] (5 min)
- Check [[00-Pre-Exam-Checklist|Pre-Exam Checklist]] (2 min)

### Finding Your Target's Vulnerability

Choose based on what you find:

#### Web Services (HTTP/HTTPS)
- [[Techniques/SQL-Injection-Path|SQL Injection]] - Initial access, data extraction
- [[Techniques/File-Upload-RCE|File Upload]] - Direct shell upload  
- [[Techniques/LFI-to-RCE|Local File Inclusion]] - Arbitrary file read/execution
- [[Techniques/SSTI-Template-Injection|Server-Side Template Injection]] - Code execution
- [[Techniques/XXE-XML-Injection|XXE/XML Injection]] - File read, SSRF

#### Windows Services
- [[Techniques/Windows-Privesc-Checklist|Windows Privilege Escalation]]
  - SUID binaries abused
  - Sudo misconfiguration
  - Weak service permissions
  - Token impersonation
  - UAC bypass
- [[Techniques/AD-Kerberos-Attacks|Active Directory & Kerberos]]
  - Golden Ticket
  - Silver Ticket
  - Kerberoasting
  - DCSync

#### Linux Services
- [[Techniques/Linux-Privesc-Checklist|Linux Privilege Escalation]]
  - SUID binary abuse (GTFOBins)
  - Sudo exploitation
  - Kernel exploits
  - Capabilities
  - Cronjob abuse
  - Writable files/directories

### I Have Shell Access
1. [[Post-Exploitation/Local-Enum-Checklist|Run local enumeration first]]
2. [[Post-Exploitation/Privesc-Vectors|Find privilege escalation vector]]
3. [[Post-Exploitation/Credential-Harvesting|Harvest credentials if needed]]
4. [[Post-Exploitation/Lateral-Movement|Lateral movement to other machines]]

### Getting Stuck?
- [[Quick-Reference|Quick Command Reference]]
- [[Techniques/Index|All Techniques by Category]]
- [[Payloads/Reverse-Shells|Reverse Shell One-Liners]]
- [[Tools-Reference/00-Tools-Index|Tool Commands]]

## Success Path

```
25-point machine:
  Nmap scan → Web vulns/Services → Initial RCE → User privesc → Root
  Time: ~8 hours
  Points: 25

25-point machine:
  Recon → Find weakness → Exploit → Privesc to root
  Time: ~8 hours  
  Points: 25

20-point machine:
  Quick machine (usually easier)
  Time: ~4 hours
  Points: 20

TARGET: 35+ points in 24 hours
```

## Exam Time Breakdown

- T+0-1h: Initial recon on all 3 machines (parallel)
- T+1-8h: Deep enumeration and exploitation
- T+8-12h: First machine owned
- T+12-20h: Second machine owned
- T+20-24h: Third machine owned + report writing

## During Exam Use This

1. [[Techniques/Enum-Checklist|Enumeration Checklist]] - What to scan
2. [[Techniques/Exploitation-Checklist|Exploitation Checklist]] - What to try
3. [[Quick-Reference|Command Quick Reference]] - Copy-paste commands
4. [[Post-Exploitation/Post-Exploit-Checklist|Post-Exploitation Checklist]] - Privesc hunting

## Real Examples from Machines

Each technique page links to HTB machines where it worked:

- [[Techniques/SQL-Injection-Path|SQL Injection examples]] from real machines
- [[Techniques/Windows-Privesc-Checklist|Privesc methods]] with working examples
- [[Post-Exploitation/Lateral-Movement|AD attacks]] with real exploitation chains

## Report Template

When you own machines, document in [[Report-Template|this format]] for exam writeup.

---

**Remember:** 
- Fast enumeration beats slow exploitation
- Try simple things first
- Document everything with screenshots
- 35 points wins - don't get stuck on one machine
- Time management is critical

Good luck on exam day!

Last Updated: 2026-10-07

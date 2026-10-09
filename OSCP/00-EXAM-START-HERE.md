---
title: OSCP Exam Reference Hub
description: Optimized for 24-hour exam - use during testing
tags: [oscp, exam, reference, quick-lookup]
---

# OSCP Exam Reference Hub

Start here during your exam. This is your fastest path to points.

## Quick Navigation

### Before You Start
- Read [[OSCP/OSCP-Exam-Rules|Exam Rules]] (5 min)
- Check [[OSCP/01-Setup/README|Setup and scope checklist]] (2 min)

### Finding Your Target's Vulnerability

Choose based on what you find:

#### Web Services (HTTP/HTTPS)
- [[OSCP/03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control|Web discovery and access control]] - Baseline, inputs, authorization, and hidden paths
- [[OSCP/03-Initial-Access/Techniques/Web/03-File-Upload-and-Execution|File upload and execution]] - Upload processing, callbacks, and execution triggers
- [[OSCP/03-Initial-Access/Techniques/Web/SQL-Injection-Path|SQL injection]] - Detection, extraction, and validation
- [[OSCP/Reference/Web|Web reference]] - LFI, SSTI, XXE, request handling, and payload references

#### Windows Services
- [[OSCP/05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation|Windows Privilege Escalation]]
  - SUID binaries abused
  - Sudo misconfiguration
  - Weak service permissions
  - Token impersonation
  - UAC bypass
- [[OSCP/06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse|Active Directory identity and ACL abuse]]
- [[OSCP/06-Active-Directory/Techniques/Active-Directory/07-Kerberos-Certificates-and-Delegation|Kerberos, certificates, and delegation]]
  - Golden Ticket
  - Silver Ticket
  - Kerberoasting
  - DCSync

#### Linux Services
- [[OSCP/04-Linux-Escalation/Techniques/Linux/Linux-Privesc-Checklist|Linux Privilege Escalation]]
  - SUID binary abuse (GTFOBins)
  - Sudo exploitation
  - Kernel exploits
  - Capabilities
  - Cronjob abuse
  - Writable files/directories

### I Have Shell Access
1. [[OSCP/07-Pivoting/Post-Exploitation/00-Post-Exploitation-Index|Run post-exploitation workflow]]
2. [[OSCP/04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation|Linux escalation]] or [[OSCP/05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation|Windows escalation]]
3. [[OSCP/Reference/Credentials|Handle and validate credentials]]
4. [[OSCP/07-Pivoting/Techniques/Cross-Platform/08-Pivoting-and-Lateral-Movement|Pivot or move laterally]]

### Getting Stuck?
- [[OSCP/00-FAST-TRIAGE|Fast triage and command map]]
- [[OSCP/00-TECHNIQUE-INDEX|All Techniques by Category]]
- [[OSCP/03-Initial-Access/Payloads/00-Payloads-Index|Payloads and transfer notes]]
- [[OSCP/Tools-Reference/00-Tools-Index|Tool Commands]]

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

1. [[OSCP/02-Enumeration/Techniques/Cross-Platform/Enum-Checklist|Enumeration Checklist]] - What to scan
2. [[OSCP/00-TECHNIQUE-INDEX|Technique index]] - Choose the branch from the observation
3. [[OSCP/00-FAST-TRIAGE|Fast triage and command map]] - Copy-paste commands
4. [[OSCP/07-Pivoting/Post-Exploitation/00-Post-Exploitation-Index|Post-Exploitation Index]] - Escalation and movement

## Real Examples from Machines

Each technique page links to HTB machines where it worked:

- [[OSCP/03-Initial-Access/Techniques/Web/SQL-Injection-Path|SQL Injection examples]] from real machines
- [[OSCP/05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation|Privesc methods]] with working examples
- [[OSCP/06-Active-Directory/Techniques/Active-Directory/07-Kerberos-Certificates-and-Delegation|AD/Kerberos methods]] with real exploitation chains

## Report Template

When you own machines, document using the [[OSCP/08-Evidence-and-Reporting/Writeup-Templates/Writeup-Template|writeup template]] for the exam report.

---

**Remember:** 
- Fast enumeration beats slow exploitation
- Try simple things first
- Document everything with screenshots
- 35 points wins - don't get stuck on one machine
- Time management is critical

Good luck on exam day!

Last Updated: 2026-10-07

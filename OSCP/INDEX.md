---
title: OSCP Vault Master Index
description: Complete reference for exam preparation
tags: [oscp, index, reference]
---

# OSCP Vault - Master Index

Your complete resource for passing OSCP.

## During Your Exam

Start here: [[00-EXAM-START-HERE|00-EXAM-START-HERE]]

Contains:
- Pre-exam checklist
- Decision trees for finding vulnerabilities
- Quick reference commands
- Time management breakdown

## Before Exam - Study Phase

### Phase 1: Learn Techniques (Weeks 1-4)

Learn each attack type:
- [[Techniques/00-Techniques-Index|All Techniques by Category]]
- [[Techniques/Enum-Checklist|Reconnaissance Methodology]]
- [[Techniques/SQL-Injection-Path|SQL Injection Attack Path]]
- [[Techniques/Linux-Privesc-Checklist|Linux Privilege Escalation]]

Tools reference:
- [[Tools-Reference/00-Tools-Index|All Tools & Commands]]

### Phase 2: Practice (Weeks 5-20)

Solve machines and compare to writeups:
- [[Writeups|HTB Machine Solutions]]

Document your learning:
- [[Writeup-Templates/Writeup-Template|Use This Template]]

### Phase 3: Master (Weeks 21-28)

Timed practice:
- [[OSCP-Study-Methodology|3-Phase Study Plan]]

Exam rules & format:
- [[OSCP-Exam-Rules|Official Rules]]

## Quick Lookups

### By What You Find Open

- Port 21 (FTP): See Enum-Checklist
- Port 22 (SSH): See Enum-Checklist
- Port 80/443 (HTTP/HTTPS): See Techniques/00-Techniques-Index
- Port 139/445 (SMB): See Enum-Checklist
- Port 3306 (MySQL): See Techniques/SQL-Injection-Path
- Port 3389 (RDP): See Enum-Checklist
- Port 5985 (WinRM): See Enum-Checklist

### By Attack Type

- Web exploits: [[Techniques/00-Techniques-Index|Techniques Index]]
- Privilege escalation (Linux): [[Techniques/Linux-Privesc-Checklist|Linux PrivEsc]]
- Privilege escalation (Windows): [[Techniques/Windows-Privesc-Checklist|Windows PrivEsc]]
- Active Directory: [[Techniques/00-Techniques-Index|Techniques Index]]
- Post-exploitation: [[Post-Exploitation|Post-Exploitation Tactics]]

### By Tool/Command

- [[Tools-Reference/00-Tools-Index|All Tools Index]]
- [[Payloads|Reverse Shells & Payloads]]

## Structure

```
OSCP/
├── 00-EXAM-START-HERE.md          (Use during exam)
├── INDEX.md                        (You are here)
├── OSCP-Exam-Rules.md             (Read before exam)
├── OSCP-Study-Methodology.md      (3-phase study plan)
├── Quick-Reference.md             (Commands quick lookup)
│
├── Techniques/                     (Attack methods)
│   ├── 00-Techniques-Index.md     (All techniques organized)
│   ├── Enum-Checklist.md          (What to scan)
│   ├── SQL-Injection-Path.md      (SQLi from detection to RCE)
│   ├── Linux-Privesc-Checklist.md (Linux privilege escalation)
│   └── Windows-Privesc-Checklist.md (Windows privilege escalation)
│
├── Enumeration/                   (Reconnaissance guides)
├── Post-Exploitation/             (After shell access)
├── Tools-Reference/               (Tool commands)
├── Payloads/                      (Reverse shells, exploits)
├── Writeups/                      (HTB machine solutions)
├── Writeup-Templates/             (Documentation templates)
│
└── resources/                     (External references)
```

## Study Path Recommendation

### Week 1-4: Foundation

1. Read [[OSCP-Exam-Rules|Exam Rules]]
2. Read [[OSCP-Study-Methodology|Study Methodology]]
3. Study each technique in [[Techniques/00-Techniques-Index|Techniques Index]]
   - Start with [[Techniques/Enum-Checklist|Enumeration]]
   - Then [[Techniques/SQL-Injection-Path|SQL Injection]]
   - Then [[Techniques/Linux-Privesc-Checklist|Linux PrivEsc]]
4. Practice [[Tools-Reference/00-Tools-Index|Tools]] on your own test systems

### Week 5-20: Practice Machines

1. Solve HTB machines
2. Document findings in [[Writeup-Templates/Writeup-Template|Template]]
3. Compare with [[Writeups|Solutions]] only after solving
4. Review which techniques worked, why, and exact commands

### Week 21-28: Exam Prep

1. Re-read [[OSCP-Exam-Rules|Exam Rules]]
2. Timed challenges (8 hours, targeting 35+ points)
3. Practice writing professional reports
4. Review [[00-EXAM-START-HERE|Exam Hub]] until it's second nature

## During Your 24-Hour Exam

Use this flow:

1. Open [[00-EXAM-START-HERE|00-EXAM-START-HERE]] first
2. Follow decision trees to identify vulnerabilities
3. Look up specific technique in [[Techniques/00-Techniques-Index|Techniques]]
4. Copy commands from [[Quick-Reference|Quick Reference]] or specific guides
5. Document findings as you go
6. Use [[Writeup-Templates/Writeup-Template|Report Template]] for writeup

## Key Files

| File | Purpose | When |
|------|---------|------|
| 00-EXAM-START-HERE | Main exam hub | During exam (open first!) |
| Techniques/00-Techniques-Index | All attack methods | When stuck, need technique |
| Techniques/Enum-Checklist | What to scan | First 30-60 minutes |
| Techniques/Linux-Privesc-Checklist | Privilege escalation | When you have shell |
| Techniques/SQL-Injection-Path | SQL injection attacks | When you find web app |
| Quick-Reference | Commands quick lookup | Throughout exam |
| OSCP-Exam-Rules | Official rules | Read before exam |
| OSCP-Study-Methodology | Study plan | Before starting prep |

## Support During Exam

Stuck?

1. Check [[00-EXAM-START-HERE|Exam Hub]] - decision trees
2. Search [[Techniques/00-Techniques-Index|Techniques by Type]]
3. Use [[Quick-Reference|Quick Reference]] for commands
4. Review relevant [[Writeups|Machine Writeup]] for similar techniques

Remember: Don't look at writeups while solving. Use them to learn after you complete a machine.

## Success Formula

```
Systematic Enumeration
     ↓
Find Vulnerability
     ↓
Match to Technique
     ↓
Execute Exploitation
     ↓
Privilege Escalation
     ↓
Capture Flags
     ↓
Document Everything
     ↓
35+ Points in 24 Hours
```

Good luck. You have everything you need to pass.

---

**Last Updated:** 2026-10-07  
**Status:** Clean, organized, ready for exam

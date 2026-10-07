---
title: OSCP Exam Rules & Restrictions
description: Official guidelines and restrictions for OSCP exam
tags: [oscp, exam, rules, important]
---

# ⚠️ OSCP Exam Rules & Restrictions

> **CRITICAL**: Review these rules before attempting your OSCP exam. Violations can result in exam failure or certification revocation.

**Last Reviewed**: [Check OffSec official documentation](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)

---

## 🚫 Prohibited Tools & Techniques

### Automatic Exploitation is **PROHIBITED**

❌ **NOT Allowed:**
- `sqlmap` in automatic mode (`-dbs`, `--dump`, etc.)
- Automatic payload generation and execution
- Metasploit automatic exploitation modules
- Burp Suite's automatic vulnerability scanning

✅ **What IS Allowed:**
- Manual SQL injection testing with `sqlmap --wizard` for parameter detection
- Manual use of Metasploit (creating handler, configuring manually)
- Manual exploitation of identified vulnerabilities
- Using tools to verify/assist in manual exploitation

### Automatic Gaining Root/System

❌ **NOT Allowed:**
- Running automated privilege escalation scripts that automatically execute exploits
  - e.g., LinPEAS running and auto-executing privilege escalation

✅ **What IS Allowed:**
- Running LinPEAS/WinPEAS to enumerate potential privesc vectors
- Manually exploiting a vulnerability identified by enumeration tools
- Using exploit frameworks after manual configuration

### Vulnerability Scanners in Automatic Mode

❌ **NOT Allowed:**
- Nessus/OpenVAS auto-exploitation
- Qualys auto-remediation
- Automatic vulnerability assessment scans that auto-exploit

✅ **What IS Allowed:**
- Nessus/OpenVAS for vulnerability identification only
- Manual testing of identified vulnerabilities
- Using scan output to guide manual testing

---

## ✅ What IS Allowed

### Information Gathering
- ✅ Nmap and all scanning variations
- ✅ Burp Suite (manual testing only, not automated)
- ✅ Enumeration tools (enum4linux-ng, ldapsearch, etc.)
- ✅ Web fuzzers (ffuf, gobuster, feroxbuster)
- ✅ Metasploit modules for information gathering

### Manual Exploitation
- ✅ Writing custom exploit code
- ✅ Modifying existing PoCs to fit your target
- ✅ Using tools like curl, sqlcmd, etc. manually
- ✅ Creating custom payloads (msfvenom, etc.)
- ✅ Using reverse shell commands manually

### Post-Exploitation
- ✅ Manual credential dumping (mimikatz, pypykatz on files)
- ✅ Manual lateral movement
- ✅ Privilege escalation via identified vulnerabilities
- ✅ Data exfiltration

### Documentation
- ✅ Screenshots of shells/access
- ✅ Command logs
- ✅ Proof of exploitation

---

## 📋 OSCP Exam Restrictions by Stage

### Stage 1: Exploitation Attempt

> You must **demonstrate manual exploitation**, not run automated tools.

**Allowed:**
- Identify vulnerability
- Manually craft exploit or payload
- Modify existing PoC if needed
- Execute step-by-step
- Show evidence of each step

**NOT Allowed:**
- "Click to exploit" buttons
- Running automated exploit chains
- Using Metasploit automatic handlers without manual config

### Stage 2: Privilege Escalation

> You must **manually exploit** the privilege escalation, not run automatic scripts that execute.

**Allowed:**
- Run enumeration scripts (LinPEAS, WinPEAS)
- Manually compile exploits
- Create bash/PowerShell scripts to exploit
- Use tools like chisel, socat for pivoting

**NOT Allowed:**
- Running automatic privilege escalation tools that execute exploits without your intervention
- Running scripts that chain multiple exploits automatically

### Stage 3: Reporting

> Demonstrate that YOU understand the vulnerability and exploitation.

**Requirement:**
- Screenshots of your shells at each stage
- Command evidence showing manual exploitation
- Explanation of vulnerabilities in your own words
- Proof that you tested manual exploitation

---

## 🎯 Key Exam Rules Summary

| Rule | Implication |
|------|-------------|
| **No automatic exploitation** | Must manually verify each step |
| **No vulnerability scanners in auto mode** | Identify vulns, then manually test |
| **Must understand what you exploit** | Can't use PoCs blindly |
| **Manual verification required** | Screenshot proof at each stage |
| **Command evidence needed** | Show exactly what you ran |
| **Reproducible exploitation** | Anyone should be able to follow your steps |

---

## 📝 Exam Preparation Checklist

Before the exam:

- [ ] **Read** the [official exam guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [ ] **Practice** manual exploitation on machines
- [ ] **Understand** every CVE/exploit you use
- [ ] **Test** your documentation process (screenshots, logs)
- [ ] **Verify** you can manually exploit without scripts
- [ ] **Know** your tools and their "allowed" vs "automatic" modes
- [ ] **Review** this checklist 1 day before exam

---

## ⏰ Exam Timeline & Scoring

### Exam Duration
- **24 hours** of exam time (+ 24 hours for writeup completion)
- **100 points** total needed to pass (~70%)

### Scoring Breakdown
- **User flag**: Usually 10-15 points
- **Root/System flag**: Usually 15-25 points
- **Proof of manual exploitation**: Screenshots required

### Writeup Requirements
- **3 machines** minimum documentation required for certification
- **Proof of exploitation** must be evident in writeup
- **Methodology** must be explained step-by-step
- **Screenshots** at key stages (access, shell, privilege escalation)

---

## 🔒 Exam Conduct Rules

### Allowed During Exam
- ✅ One terminal window
- ✅ Web browser for documentation
- ✅ Obsidian/notes application (this vault!)
- ✅ Calculator
- ✅ Text editor

### NOT Allowed
- ❌ Screen sharing / livestreaming
- ❌ External communication during exam
- ❌ AI/ChatGPT assistance during exam
- ❌ Copying code without understanding
- ❌ Using other people's exploits without modification

### Proctoring
- Webcam required
- Screen recording throughout
- Proctor monitors periodically
- Room must be clear of notes/references

---

## 🛠️ Safe Tool Usage During Exam

### Metasploit

```bash
# ✅ ALLOWED: Manual configuration
$ msfconsole
> use exploit/windows/...
> set RHOST <TARGET>
> set LHOST <LHOST>
> set LPORT <LPORT>
> run

# ❌ NOT ALLOWED: Automatic modules
$ msfconsole -m vulnerability_scan -a <TARGET>
```

### SQLmap

```bash
# ❌ NOT ALLOWED: Automatic exploitation
$ sqlmap -u <URL> -dbs --dump

# ✅ ALLOWED: Manual parameter testing
$ sqlmap -u <URL> --identify-waf -p parameter
# Then manually craft SQL injection
```

### Burp Suite

```
✅ ALLOWED: Manual parameter fuzzing, manual exploitation
❌ NOT ALLOWED: Active scanner in automatic mode, auto-exploit
```

---

## 🎓 Study Recommendations

### Practice Without Restrictions First

Use [[00-Index|this vault]] to:
1. Learn each technique deeply
2. Practice manual exploitation
3. Understand vulnerability mechanics
4. Build custom exploits

### Then Simulate Exam Conditions

Without automatic tools:
1. Solve machines manually
2. Document everything
3. Write detailed writeups
4. Verify you can explain each step

### Readiness Check

- Can you exploit every machine WITHOUT automated tools?
- Can you write a detailed writeup in under 2 hours?
- Can you explain the vulnerability in layman's terms?
- Do you have proof (screenshots) of each stage?

If YES to all → **You're ready for the exam**

---

## 📞 Questions About Rules?

Official OffSec Resources:
- [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [Proctored Exams](https://help.offsec.com/hc/en-us/sections/360008126631-Proctored-Exams)
- [Support Portal](https://help.offsec.com)

---

## 📚 Related Notes

- [[00-Index|OSCP Knowledge Base]] — Complete study resource
- [[Writeup-Templates/Writeup-Template|Writeup Template]] — Document everything
- [[Exploitation/00-Exploitation-Index|Exploitation Techniques]] — Learn manual methods

---

**Last Updated**: 2026-10-07 | **Status**: Review before every exam attempt

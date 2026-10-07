---
title: OSCP Knowledge Base
description: Comprehensive Obsidian-compatible OSCP study vault
tags: [oscp, home, index]
created: 2026-10-07
updated: 2026-10-07
---

# 🎯 OSCP Knowledge Base

> Your comprehensive penetration testing and OSCP preparation vault. Technique-focused, beautifully organized, and searchable across all attack surfaces.

---

## 🚀 Quick Start

### For OSCP Exam Prep
1. **Study Mode**: Browse [[Enumeration|Enumeration Techniques]] by target type
2. **Practice Machines**: Use [[Writeup-Template]] to document your findings
3. **Cheat Reference**: Search [[00-Index#Tools-by-Category|Tools by Category]] during practice

### Exam Restrictions Reminder
> ⚠️ **IMPORTANT**: Automatic exploitation tools (e.g., `sqlmap` auto-exploitation) are **prohibited** in OSCP exams.
> - Always manually verify exploitability before reporting
> - Document your methodology, not automation output
> - See [[OSCP-Exam-Rules]] for current guidelines

---

## 📚 Knowledge Base Structure

### [🔍 Enumeration](Enumeration/00-Enumeration-Index.md)
Reconnaissance and information gathering techniques by target type.
- [[Enumeration/Web-Enumeration|Web Enumeration]] — Burp, ffuf, Nuclei, parameter discovery
- [[Enumeration/Windows-Enumeration|Windows Enumeration]] — SMB, RPC, WMI enumeration
- [[Enumeration/Linux-Enumeration|Linux Enumeration]] — Port scanning, service fingerprinting
- [[Enumeration/Active-Directory|Active Directory]] — LDAP, Kerberos, domain reconnaissance
- [[Enumeration/Database-Enumeration|Databases]] — MySQL, MSSQL, PostgreSQL, MongoDB, Redis

### [⚔️ Exploitation](Exploitation/00-Exploitation-Index.md)
Attack techniques organized by vulnerability type and target platform.

#### Web Application
- [[Exploitation/Web/SQL-Injection|SQL Injection]] — Authentication bypass, data extraction
- [[Exploitation/Web/Local-File-Inclusion|LFI/RFI]] — Path traversal, file inclusion
- [[Exploitation/Web/Cross-Site-Scripting|XSS]] — Reflected, stored, DOM-based
- [[Exploitation/Web/Server-Side-Template-Injection|SSTI]] — Code injection in templates
- [[Exploitation/Web/File-Upload-Vulnerabilities|File Upload Bypasses]] — PHP, aspx, shell extensions
- [[Exploitation/Web/XXE-Injection|XXE/XML Injection]] — External entity attacks

#### Windows
- [[Exploitation/Windows/Privilege-Escalation|Windows PrivEsc]] — SUID, DLL hijacking, service misconfigs
- [[Exploitation/Windows/Active-Directory-Attacks|AD Attacks]] — DCSync, Kerberoasting, Certificate abuse
- [[Exploitation/Windows/NTLM-Relay|NTLM Relay]] — Potato exploits, coercion techniques
- [[Exploitation/Windows/Reverse-Shells|Reverse Shells]] — PowerShell, staged/stageless

#### Linux
- [[Exploitation/Linux/Privilege-Escalation|Linux PrivEsc]] — SUID, capabilities, wildcard abuse
- [[Exploitation/Linux/Container-Escape|Container Escape]] — Docker, cgroup breakout

### [🔧 Post-Exploitation](Post-Exploitation/00-Post-Exploitation-Index.md)
Credential harvesting, lateral movement, persistence mechanisms.
- [[Post-Exploitation/Credential-Harvesting|Credential Harvesting]] — Mimikatz, lsassy, registry dumping
- [[Post-Exploitation/Lateral-Movement|Lateral Movement]] — Pass-the-hash, Kerberos relaying
- [[Post-Exploitation/Persistence|Persistence]] — Backdoors, scheduled tasks, registry keys
- [[Post-Exploitation/Data-Exfiltration|Data Exfiltration]] — Covert channels, archiving

### [🛠️ Tools Reference](Tools-Reference/00-Tools-Index.md)
Curated tool list with links, installation, and key commands.
- [[Tools-Reference/Information-Gathering|Information Gathering]] — Nmap, enum4linux-ng, ldapsearch
- [[Tools-Reference/Web-Fuzzing|Web Fuzzing]] — ffuf, feroxbuster, Burp Suite
- [[Tools-Reference/Password-Attacks|Password Attacks]] — Hashcat, John, Hydra, Kerbrute
- [[Tools-Reference/Exploitation-Frameworks|Exploitation]] — Metasploit, Impacket, Evil-WinRM
- [[Tools-Reference/Payloads|Payloads & Shells]] — msfvenom, reverse shells, one-liners

### [📝 Writeup Templates](Writeup-Templates/00-Writeup-Index.md)
Templates and examples for documenting machine solutions.
- [[Writeup-Templates/Writeup-Template|Machine Writeup Template]] — Standard structure for documenting solutions
- [[Writeup-Templates/Findings-Template|Findings Template]] — Organize vulnerabilities and exploitation paths
- [[Writeup-Templates/Lessons-Learned|Lessons Learned Template]] — Reflect on techniques applied

### [🎯 HTB Machine Writeups](Writeups/00-Writeups-Index.md)
Complete collection of Hack the Box machine solutions with exploitation methodology.
- **17 Complete Writeups** — Easy, Medium, Hard difficulty machines
- **Enumeration Examples** — Real-world reconnaissance examples
- **Exploitation Paths** — Step-by-step exploitation chains
- **Lessons Learned** — Key insights from each machine

### [🎓 Academy Training](Academy/00-Academy-Index.md)
Integrated Hack the Box Academy courses for comprehensive security knowledge.
- [[Academy/Bug-Bounty-Hunter/WEB-APPLICATIONS|Web Applications]]
- [[Academy/Bug-Bounty-Hunter/WEB-REQUESTS|Web Requests]]
- [[Academy/Bug-Bounty-Hunter/FILE-UPLOAD-ATTACKS|File Upload Attacks]]

### [💾 Payloads & Resources](Payloads/00-Payloads-Index.md)
Pre-built payloads, reverse shells, and exploit code.
- [[Payloads/Reverse-Shells|Reverse Shells]] — Bash, PowerShell, PHP, Python
- [[Payloads/Web-Payloads|Web Payloads]] — SQLi, LFI, XSS, SSTI examples
- [[Payloads/Windows-Payloads|Windows Payloads]] — UAC bypass, DLL injection
- [[Payloads/Wordlists|Wordlists]] — Common dictionaries for brute-forcing

---

## 🎓 Study Paths

### Beginner Path (0-3 months)
1. Start: [[Enumeration/Web-Enumeration|Web Enumeration]]
2. Practice: Find common web vulns (OWASP Top 10)
3. Move: [[Exploitation/Web/SQL-Injection|SQL Injection]]
4. Document: Use [[Writeup-Templates/Writeup-Template|Writeup Template]]

### Intermediate Path (3-6 months)
1. [[Enumeration/Windows-Enumeration|Windows Enumeration]]
2. [[Exploitation/Windows/Privilege-Escalation|Windows PrivEsc]]
3. [[Enumeration/Active-Directory|AD Enumeration]] & [[Exploitation/Windows/Active-Directory-Attacks|AD Attacks]]
4. Practice: HTB Windows machines

### Advanced Path (6-9 months)
1. [[Exploitation/Windows/NTLM-Relay|NTLM Relay]] & complex AD chains
2. [[Exploitation/Linux/Container-Escape|Container Escape]]
3. Full network pivoting scenarios
4. Practice: Multi-machine lab chains

---

## 🔗 How to Use This Vault

### In Obsidian
- **Graph View**: Visualize connections between techniques and tools
- **Search**: Cmd+P / Ctrl+P to search across all notes
- **Backlinks**: See which notes reference your current note
- **Tags**: Click tags to filter by category (#oscp, #lpe, #windows)

### During Practice
- Open your machine name in a new pane
- Link to relevant technique notes: `[[Exploitation/Web/SQL-Injection#Blind-SQLi]]`
- Build your own "discoveries" vault linking to findings

### Before Exam
- Review [[OSCP-Exam-Rules]]
- Print techniques checklists
- Practice [[Writeup-Templates/Writeup-Template|writeup structure]]

---

## 📊 Tags & Categories

All notes use consistent tags for filtering:
- `#oscp` — OSCP exam relevant
- `#enumeration` — Information gathering
- `#exploitation` — Active attacks
- `#windows` / `#linux` / `#web` — Target platform
- `#privilege-escalation` — Privilege escalation
- `#ad` — Active Directory specific
- `#automated-tools` — Marked where automation is available

---

## 🔄 Contributing & Updates

This vault is designed to grow with your learning:
1. **Add findings** from machines to Writeups
2. **Link patterns** you discover to Exploitation techniques
3. **Document bypasses** you create in Payloads
4. **Update tool versions** as you encounter new features

---

## 📖 Resources

- [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [HackTricks](https://book.hacktricks.xyz)
- [IppSec.rocks](https://ippsec.rocks)
- [GTFOBins](https://gtfobins.github.io)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

**Last Updated**: 2026-10-07 | **Format**: Obsidian Markdown | **Sharing**: Public GitHub

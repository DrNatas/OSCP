---
title: HTB Machine Solutions Index
description: Comprehensive writeups of solved Hack the Box machines
tags: [htb, writeup, oscp, machines]
---

# 🎯 HTB Machine Solutions (17 Machines)

> Complete solutions for machines I've pwned, organized by difficulty and platform. Each writeup is structured to emphasize methodology and learning.

---

## 📊 Quick Stats

| Metric | Count |
|--------|-------|
| **Total Machines** | 17 |
| **Windows Machines** | ~8 |
| **Linux Machines** | ~9 |
| **Active Directory** | 4+ |
| **Web Focus** | 3+ |
| **Difficulty Range** | Easy - Hard |

---

## 🏆 By Difficulty

### 🟢 Easy (Beginner-friendly)

Great for learning fundamentals and common exploitation paths.

- **[[Writeups/HTB-Alert/Alert-Writeup|Alert]]** — Monitoring software exploitation
- **[[Writeups/HTB-Chemistry/Chemistry-Writeup|Chemistry]]** — Web chemistry application
- **[[Writeups/HTB-Puppy/Puppy-Writeup|Puppy]]** — Cute name, not-so-cute exploitation
- **[[Writeups/HTB-RustyKey/RustyKey-Writeup|RustyKey]]** — Key-based system

### 🟡 Medium (Core Concepts)

Solidify your skills with diverse attack vectors.

- **[[Writeups/HTB-Administrator/Administrator-Writeup|Administrator]]** — Windows AD domain controller
- **[[Writeups/HTB-Certified/Certified-Writeup|Certified]]** — Certificate manipulation
- **[[Writeups/HTB-LinkVortex/LinkVortex-Writeup|LinkVortex]]** — Link-based attack vector
- **[[Writeups/HTB-Planning/Planning-Writeup|Planning]]** — Project planning application
- **[[Writeups/HTB-Sightless/Sightless-Writeup|Sightless]]** — Blind vulnerability exploitation
- **[[Writeups/HTB-Support/Support-Writeup|Support]]** — Support ticket system
- **[[Writeups/HTB-TombWatcher/TombWatcher-Writeup|TombWatcher]]** — ADCS certificate abuse
- **[[Writeups/HTB-UnderPass/UnderPass-Writeup|UnderPass]]** — Underground exploitation
- **[[Writeups/HTB-Voleur/Voleur-Writeup|Voleur]]** — Theft-themed box

### 🔴 Hard (Advanced)

Master complex attack chains and multi-step exploitation.

- **[[Writeups/HTB-Code/Code-Writeup|Code]]** — Code review vulnerability
- **[[Writeups/HTB-Nocturnal/Nocturnal-Writeup|Nocturnal]]** — Night-time exploitation
- **[[Writeups/HTB-theFrizz/theFrizz-Writeup|theFrizz]]** — Complex Windows AD chain
- **[[Writeups/HTB-oscp-notes/oscp-notes|OSCP Notes]]** — Synthesis of OSCP techniques

---

## 🪟 By Platform

### Windows Machines

Windows exploitation, privilege escalation, Active Directory attacks.

- [[Writeups/HTB-Administrator/Administrator-Writeup|Administrator]] — **Windows AD** — kerberoasting, DCSync
- [[Writeups/HTB-Certified/Certified-Writeup|Certified]] — **Windows ADCS** — Certificate template abuse
- [[Writeups/HTB-LinkVortex/LinkVortex-Writeup|LinkVortex]] — **Windows Web** — Web application RCE
- [[Writeups/HTB-Planning/Planning-Writeup|Planning]] — **Windows Web** — Project management app
- [[Writeups/HTB-TombWatcher/TombWatcher-Writeup|TombWatcher]] — **Windows ADCS** — Certificate escalation
- [[Writeups/HTB-theFrizz/theFrizz-Writeup|theFrizz]] — **Windows AD** — Complex AD chain
- [[Writeups/HTB-Alert/Alert-Writeup|Alert]] — **Windows Monitoring** — Monitoring software bypass
- [[Writeups/HTB-Voleur/Voleur-Writeup|Voleur]] — **Windows Web** — Web exploitation

### Linux Machines

Linux exploitation, privilege escalation, container escape.

- [[Writeups/HTB-Chemistry/Chemistry-Writeup|Chemistry]] — **Linux Web** — Web app exploitation
- [[Writeups/HTB-Code/Code-Writeup|Code]] — **Linux Web** — Code review vulnerabilities
- [[Writeups/HTB-Nocturnal/Nocturnal-Writeup|Nocturnal]] — **Linux Web** — Web-based exploitation
- [[Writeups/HTB-Puppy/Puppy-Writeup|Puppy]] — **Linux Web** — Web application
- [[Writeups/HTB-RustyKey/RustyKey-Writeup|RustyKey]] — **Linux SSH** — SSH key exploitation
- [[Writeups/HTB-Sightless/Sightless-Writeup|Sightless]] — **Linux Web** — Blind exploitation
- [[Writeups/HTB-Support/Support-Writeup|Support]] — **Linux Web** — Support system
- [[Writeups/HTB-UnderPass/UnderPass-Writeup|UnderPass]] — **Linux Web** — Underground exploitation

---

## 🎯 By Attack Type

### Web Application Exploitation

- [[Writeups/HTB-Chemistry/Chemistry-Writeup|Chemistry]] — SQLi, file upload
- [[Writeups/HTB-Code/Code-Writeup|Code]] — Code review, SSTI
- [[Writeups/HTB-LinkVortex/LinkVortex-Writeup|LinkVortex]] — LFI, command injection
- [[Writeups/HTB-Planning/Planning-Writeup|Planning]] — SQL injection, privesc
- [[Writeups/HTB-Sightless/Sightless-Writeup|Sightless]] — Blind SQLi
- [[Writeups/HTB-Support/Support-Writeup|Support]] — Active Directory password reset

### Active Directory Attacks

- [[Writeups/HTB-Administrator/Administrator-Writeup|Administrator]] — Kerberoasting, DCSync
- [[Writeups/HTB-Certified/Certified-Writeup|Certified]] — ADCS, certificate abuse
- [[Writeups/HTB-TombWatcher/TombWatcher-Writeup|TombWatcher]] — ADCS templates, ESC
- [[Writeups/HTB-theFrizz/theFrizz-Writeup|theFrizz]] — Complex multi-step AD chain

### Privilege Escalation

- [[Writeups/HTB-Alert/Alert-Writeup|Alert]] — Windows privesc
- [[Writeups/HTB-Puppy/Puppy-Writeup|Puppy]] — Linux privesc
- [[Writeups/HTB-RustyKey/RustyKey-Writeup|RustyKey]] — SSH key reuse
- [[Writeups/HTB-Voleur/Voleur-Writeup|Voleur]] — File manipulation

---

## 🔗 Techniques Used Across Machines

### Techniques by Frequency

| Technique | Machines | Difficulty |
|-----------|----------|-----------|
| [[Exploitation/Web/SQL-Injection|SQL Injection]] | Chemistry, Sightless, Planning, Support | Low-Medium |
| [[Exploitation/Web/File-Upload-Vulnerabilities\|File Upload]] | Chemistry, Puppy | Low |
| [[Exploitation/Windows/Active-Directory-Attacks\|AD Attacks]] | Administrator, Certified, TombWatcher, theFrizz | Medium-Hard |
| [[Exploitation/Web/Command-Injection\|Command Injection]] | LinkVortex, Support | Medium |
| [[Exploitation/Linux/Privilege-Escalation\|Linux PrivEsc]] | Puppy, Nocturnal, Code | Low-Medium |
| [[Exploitation/Web/Server-Side-Template-Injection\|SSTI]] | Code | Medium |
| [[Exploitation/Windows/Privilege-Escalation\|Windows PrivEsc]] | Alert, Voleur | Low-Medium |

---

## 📈 Learning Path (Recommended Order)

### Beginner (Build Foundations)
1. [[Writeups/HTB-Chemistry/Chemistry-Writeup|Chemistry]] — Learn basic SQLi & file upload
2. [[Writeups/HTB-Puppy/Puppy-Writeup|Puppy]] — Linux privesc fundamentals
3. [[Writeups/HTB-Alert/Alert-Writeup|Alert]] — Windows basics

### Intermediate (Expand Skills)
4. [[Writeups/HTB-Sightless/Sightless-Writeup|Sightless]] — Advanced blind SQLi
5. [[Writeups/HTB-Planning/Planning-Writeup|Planning]] — Web + Windows combination
6. [[Writeups/HTB-Administrator/Administrator-Writeup|Administrator]] — First AD machine
7. [[Writeups/HTB-Support/Support-Writeup|Support]] — AD password attacks

### Advanced (Master Chains)
8. [[Writeups/HTB-Code/Code-Writeup|Code]] — Complex code vulnerabilities
9. [[Writeups/HTB-Certified/Certified-Writeup|Certified]] — ADCS basics
10. [[Writeups/HTB-TombWatcher/TombWatcher-Writeup|TombWatcher]] — Complex ADCS
11. [[Writeups/HTB-theFrizz/theFrizz-Writeup|theFrizz]] — Full AD chain mastery

---

## 📊 Key Insights by Machine

### Recon Patterns
- Use `nmap -p- -T5` for speed, then detailed scan on open ports
- Web apps almost always need `ffuf` or Burp fuzzing
- Windows boxes: check SMB, LDAP, Kerberos (ports 445, 389, 88)

### Common Findings
- Default credentials found in config files
- Web apps often vulnerable to SQLi or file upload
- Windows: Always check AD misconfigurations
- Linux: SUID binaries or sudo permissions

### Privilege Escalation Vectors
- **Windows**: Service misconfiguration, token impersonation, ADCS
- **Linux**: SUID binaries, sudo rights, cron jobs, kernel exploits
- **Web**: File upload → RCE → system shell

---

## 🎓 Lessons by Machine

### Most Impactful Learnings

- **Administrator**: DCSync and Kerberoasting in practice
- **Code**: Server-side template injection (SSTI)
- **Chemistry**: SQLi variations (union, blind, time-based)
- **theFrizz**: Multi-step AD exploitation chains
- **TombWatcher**: ADCS certificate template abuse

---

## 📝 How to Use This Index

1. **Learning**: Follow the recommended order from Beginner → Advanced
2. **Reference**: Search by technique to find which machines demonstrate it
3. **Review**: Use this as a study guide before OSCP exam
4. **Insights**: Review "Lessons by Machine" for key takeaways

---

## 🔗 Related

- [[../00-Index|Main OSCP Index]]
- [[../Enumeration/00-Enumeration-Index|Enumeration Techniques]]
- [[../Exploitation/00-Exploitation-Index|Exploitation Techniques]]
- [[../Quick-Reference|Quick Reference Cheatsheet]]

---

**Status**: 17/17 machines documented | **Last Updated**: 2026-10-07

---
title: OSCP Study Methodology
description: Three-phase approach to passing OSCP using this vault
tags: [oscp, methodology, study-guide, planning]
---

#  OSCP Study Methodology

> A structured three-phase approach to mastering penetration testing and passing the OSCP exam using this integrated vault.

> Navigation note: use the [main guide](README.md) for the current assessment workflow and the [technique index](00-TECHNIQUE-INDEX.md) for reusable attack patterns. This study-plan page is for pacing and review, not a second command reference.

---

##  Overview

**Goal:** Pass the OSCP exam (35+ points out of 100)  
**Timeline:** 3-9 months (depending on starting level)  
**Format:** Exam = 2x 25-point machines + 1x 20-point machine  
**Time Limit:** 24 hours  

---

##  PHASE 1: LEARN (Weeks 1-4)

### Objective
Build foundational knowledge of reconnaissance and exploitation techniques

### Study Path

#### Week 1-2: Enumeration Fundamentals
1. **Read:** [[OSCP/02-Enumeration/Enumeration/Web-Enumeration|Web Enumeration]]
   - DNS enumeration (nslookup, dig, fierce)
   - Directory scanning (ffuf, feroxbuster)
   - Service fingerprinting (nmap, Nuclei)
   
2. **Read:** [[OSCP/04-Linux-Escalation/README|Linux Enumeration and escalation]]
   - Port scanning methodology
   - Service detection
   - Common ports and services

3. **Reference:** [[OSCP/Tools-Reference/00-Tools-Index|Tools Index]]
   - Bookmark key tools
   - Understand tools available
   - Check installation requirements

#### Week 3-4: Basic Exploitation
1. **Study:** [[OSCP/03-Initial-Access/Techniques/Web/SQL-Injection-Path|SQL Injection]]
   - Union-based SQLi
   - Blind SQLi
   - Time-based detection

2. **Study:** [[OSCP/03-Initial-Access/Techniques/Web/03-File-Upload-and-Execution|File Upload Attacks]]
   - File type bypass techniques
   - Shell upload methodology
   - Extension bypass tricks

3. **Study:** [[OSCP/04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation|Linux PrivEsc]]
   - SUID binaries abuse
   - Sudo misconfiguration
   - Kernel exploits
   - Capabilities abuse

### Deliverables
- [ ] Understand nmap scan workflow
- [ ] Can identify 5+ web vulnerabilities manually
- [ ] Know 3+ PrivEsc vectors for Linux
- [ ] Have tools installed and tested

### Resources
- [[OSCP/Tools-Reference/00-Tools-Index|Information Gathering Tools]]
- [[OSCP/Tools-Reference/00-Tools-Index|Web Fuzzing Tools]]
- [[OSCP/Reference/Shells|Reverse Shell Payloads]]

---

##  PHASE 2: PRACTICE (Weeks 5-20)

### Objective
Develop exploitation skills through hands-on machine solving

### Study Path

#### Stage 1: Easy Machines (Weeks 5-8)
**Goal:** Gain confidence with basic exploitation chains

1. **Easy HTB Machines:**
   - [[Writeups/HTB-Machines/LinkVortex|Link Vortex]]
   - [[Writeups/HTB-Machines/Certified|Certified]]
   - [[Writeups/HTB-Machines/RustyKey|Rusty Key]]
   - [[Writeups/HTB-Machines/Nocturnal|Nocturnal]]

2. **For Each Machine:**
   - [ ] Attempt without looking at writeup
   - [ ] Document findings using [[OSCP/08-Evidence-and-Reporting/Writeup-Templates/Writeup-Template|template]]
   - [ ] Compare your approach with provided writeup
   - [ ] Note techniques used and lessons learned

#### Stage 2: Medium Machines (Weeks 9-14)
**Goal:** Handle multi-step exploitation chains

1. **Medium HTB Machines:**
   - [[Writeups/HTB-Machines/Code|Code]]
   - [[Writeups/HTB-Machines/Support|Support]]
   - [[Writeups/HTB-Machines/Alert|Alert]]
   - [[Writeups/HTB-Machines/Chemistry|Chemistry]]

2. **New Techniques:**
   - Study [[OSCP/03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control|SSTI entry points]]
   - Study [[OSCP/03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control|RCE methods]]
   - Study [[OSCP/07-Pivoting/Post-Exploitation/00-Post-Exploitation-Index|Post-Exploitation]]

#### Stage 3: Hard Machines (Weeks 15-20)
**Goal:** Master complex exploitation and AD attacks

1. **Hard HTB Machines:**
   - [[Writeups/HTB-Machines/Administrator|Administrator]]
   - [[Writeups/HTB-Machines/TombWatcher|TombWatcher]]
   - [[Writeups/HTB-Machines/Puppy|Puppy]]
   - [[Writeups/HTB-Machines/UnderPass|UnderPass]]
   - [[Writeups/HTB-Machines/Voleur|Voleur]]
   - [[Writeups/HTB-Machines/Sightless|Sightless]]

2. **Advanced Topics:**
   - [[OSCP/02-Enumeration/Enumeration/Active-Directory|Active Directory Enumeration]]
   - [[OSCP/06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse|AD Attacks]]
   - [[OSCP/07-Pivoting/Techniques/Cross-Platform/08-Pivoting-and-Lateral-Movement|Lateral Movement]]
   - [[OSCP/Reference/Active-Directory|NTLM Relay]]

### Methodology: How to Solve Each Machine

```
1. RECON (30 min)
    Nmap scan (all ports, all services)
    Record findings in writeup
    Identify target services

2. ENUMERATION (60-90 min)
    Deep dive on each open port
    Use appropriate [[OSCP/Tools-Reference/00-Tools-Index|tools]]
    Fuzz parameters and endpoints
    Document all findings

3. EXPLOITATION (60-120 min)
    Identify vulnerability path
    Achieve initial access
    Verify shell as specific user
    Document proof (id, whoami)

4. POST-EXPLOITATION (30-60 min)
    System enumeration (id, sudo -l, find SUID)
    Identify privesc vector
    Execute privilege escalation
    Capture proof (cat /root/root.txt)

5. DOCUMENTATION (30 min)
    Fill [[OSCP/08-Evidence-and-Reporting/Writeup-Templates/Writeup-Template|template]]
    Document complete attack chain
    Link to techniques [[OSCP/00-TECHNIQUE-INDEX|used]]
    Record lessons learned
```

### Deliverables
- [ ] Complete 4 Easy machines with writeups
- [ ] Complete 4 Medium machines with writeups
- [ ] Complete 6 Hard machines with writeups
- [ ] Understand AD attacks (AD-heavy hard machines)
- [ ] Can write polished technical writeups
- [ ] Know 10+ privilege escalation vectors

---

##  PHASE 3: MASTER (Weeks 21-28)

### Objective
Prepare for exam conditions and master complex scenarios

### Preparation Tasks

#### Week 21: Exam Rules & Restrictions
1. **Read:** [[OSCP/OSCP-Exam-Rules|Exam Rules]]
   - No automatic SQLi tools in exam
   - No Metasploit (except 1x in 24 hours)
   - Manual exploitation required
   - Proper report documentation mandatory

2. **Restriction Practice:**
   - Solve 2+ machines WITHOUT Metasploit
   - Solve 1+ machine WITHOUT sqlmap
   - Manually create all exploits

#### Week 22-23: Timed Challenges
1. **Self-Challenge:**
   - Pick 3 random hard machines
   - Set timer for 8 hours
   - Solve without looking at writeups
   - Mimic exam pressure

2. **Track Performance:**
   - Time spent per stage (recon, enum, exploit, privesc)
   - Techniques that worked/failed
   - Tools that proved invaluable

#### Week 24-25: AD & Windows Focus
1. **Multi-Machine Scenarios:**
   - [[Writeups/HTB-Machines/Administrator|Administrator]] (AD machine)
   - Practice chaining machines together
   - Practice lateral movement
   - Practice persistence mechanisms

2. **Windows PrivEsc Deep Dive:**
   - [[OSCP/05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation|Windows PrivEsc]]
   - [[OSCP/06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse|AD Attacks]]
   - [[OSCP/Reference/Credentials|Credential Harvesting]]

#### Week 26-28: Final Prep
1. **Review Phase:**
   - Re-read [[OSCP/02-Enumeration/Enumeration/Web-Enumeration|enumeration techniques]]
   - Review your hardest writeups
   - Study your "Lessons Learned" from machines

2. **Mock Exam:**
   - 24-hour timed challenge
   - 2x 25-point + 1x 20-point format
   - Target: 35+ points
   - Full report writing

3. **Report Writing:**
   - Practice professional penetration testing reports
   - Include screenshots with annotations
   - Clear exploitation proofs
   - Timeline of all actions

### Deliverables
- [ ] Pass mock exam (≥35 points)
- [ ] Complete 1 machine WITHOUT Metasploit
- [ ] Complete 1 machine WITHOUT automatic tools
- [ ] Professional report format practiced
- [ ] Exam rules fully understood
- [ ] Confidence in timed scenarios

---

##  Success Metrics

### Phase 1 Completion
 Understand reconnaissance workflow  
 Know 5+ web vulnerability types  
 Know 5+ privilege escalation vectors  
 Can use [[OSCP/Tools-Reference/00-Tools-Index|key tools]]

### Phase 2 Completion
 Complete 14 machines with writeups  
 Can exploit 25-point machines  
 Understand AD attack chains  
 Can write technical documentation  

### Phase 3 Completion (Ready for Exam)
 Pass mock exam (≥35 points)  
 No tool dependency anxiety  
 Confident in manual exploitation  
 Professional report quality  

---

##  Daily Routine

### Learning Days (Phase 1)
```
Morning (2h):     Read [[OSCP/00-TECHNIQUE-INDEX|technique]] + take notes
Afternoon (2h):   Set up tools & practice commands
Evening (1h):     Review and link to vault
```

### Practice Days (Phase 2)
```
Morning (3h):     Machine recon & enumeration
Afternoon (3h):   Exploitation attempts
Evening (2h):     Documentation & reflection
```

### Challenge Days (Phase 3)
```
Full Day (8h):    Timed machine challenges
Evening (2h):     Report writing & review
```

---

##  Quick Reference: Machine Difficulty Progression

```
BEGINNER
  ↓ (Easy Machines: 1-4)
INTERMEDIATE  
  ↓ (Medium Machines: 1-4)
ADVANCED
  ↓ (Hard Machines: 1-6)
MASTERY
  ↓ (Timed Labs)
EXAM READY 
```

---

##  Tips for Success

### Enumeration
- Always run full port scan (-p-) first
- Use Nuclei for quick vulnerability scanning
- Manually verify every automated finding
- Document ALL open ports and services

### Exploitation
- Try simple vulnerabilities first (common misconfigs)
- Manual exploitation > automated tools
- Always verify with multiple proof methods
- Document every command and output

### Privilege Escalation
- Enumerate fully before attempting PrivEsc
- Check: sudo -l, SUID binaries, writable files, cron jobs
- Use [[OSCP/Tools-Reference/00-Tools-Index|PrivEsc tools]]
- Understand WHY each technique works

### Time Management
- Allocate 8 hours per machine in mock exam
- Save Metasploit use for hardest machine
- Don't waste time on dead ends (move on after 30 min)
- Keep running timer to track pace

### Reporting
- Take screenshots WITH annotations
- Include command execution proofs
- Show full exploitation path with timeline
- Professional format and language

---

##  Related Resources

- [[OSCP/README|Main OSCP Guide]]
- [[OSCP/OSCP-Exam-Rules|Exam Rules & Restrictions]]
   - [[Writeups/00-HTB-Solutions-Index|All HTB Machines]]
- [[OSCP/03-Initial-Access/Academy/00-Academy-Index|Academy Materials]]
- [[OSCP/OSCP-Methodology-Canvas|Methodology Canvas (Visual)]]

---

**Version:** 1.0  
**Last Updated:** 2026-10-07  
**Success Rate:** Follows proven OSCP study path

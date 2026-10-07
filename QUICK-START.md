# Quick Start Guide

## Your OSCP Vault is Ready!

You now have a complete, unified knowledge base for OSCP preparation with:
- [x] 17 fully documented HTB machine writeups
- [x] Academy training materials integrated
- [x] Comprehensive study methodology
- [x] Visual canvas diagram
- [x] All connected with wikilinks

---

## Start Here

### Option 1: Just Learning (Phase 1)
1. Open `OSCP/00-Index.md`
2. Follow the "Beginner Path" section
3. Start with `Enumeration/Web-Enumeration`
4. Use `Tools-Reference/00-Tools-Index` to find commands

### Option 2: Practice with Machines (Phase 2)
1. Open `OSCP/OSCP-Study-Methodology.md`
2. Start with Easy machines:
   - [[Writeups/HTB-Machines/LinkVortex|Link Vortex]]
   - [[Writeups/HTB-Machines/Certified|Certified]]
3. Use template: `Writeup-Templates/Writeup-Template.md`

### Option 3: Visual Methodology
1. Open `OSCP/OSCP-Methodology-Canvas.canvas` in Obsidian
2. See the complete study flow visually
3. Click nodes to navigate

---

## Essential Files

| File | Purpose | When to Use |
|------|---------|------------|
| `00-Index.md` | Main hub | Orientation & overview |
| `OSCP-Study-Methodology.md` | Study plan | Planning your study |
| `Writeups/00-Writeups-Index.md` | All machines | Find machines by difficulty |
| `Enumeration/*` | Techniques | Learning reconnaissance |
| `Exploitation/*` | Techniques | Learning exploitation |
| `Tools-Reference/*` | Tools | Command reference |
| `Payloads/*` | Exploits | Ready-to-use code |
| `OSCP-Exam-Rules.md` | Exam info | Before taking exam |

---

##  Your Study Path

```
Week 1-4:  LEARN Techniques
           → Read Enumeration, Exploitation, Tools

Month 2-5: PRACTICE Machines
           → Easy machines (LinkVortex, Certified, RustyKey, Nocturnal)
           → Medium machines (Code, Support, Alert, Chemistry)
           → Document with template for each

Month 6-8: MASTER Challenges
           → Hard machines (6 hardest writeups)
           → Timed practice (8 hours per machine)
           → Full report writing

EXAM READY → Take OSCP! 
```

---

##  Pro Tips

### While Studying
- Link techniques to machines: `[[Exploitation/Web/SQL-Injection]]`
- Take notes in your own writeups
- Reference tools while practicing
- Keep a log of lessons learned

### While Solving Machines
1. **Enumerate First** → Use all techniques from Enumeration/
2. **Manual Exploitation** → Try methods before Metasploit
3. **Document Everything** → Screenshot proof of exploitation
4. **Update Template** → Fill writeup as you progress

### Before Exam
-  Review `OSCP-Exam-Rules.md`
-  Practice no-Metasploit challenges
-  Practice no-automation challenges  
-  Write 3 full professional reports
-  Do 1-2 timed labs (8 hours)

---

##  What's in Each Section

### Enumeration/
Reconnaissance and information gathering:
- Web apps (ffuf, Burp, Nuclei)
- Linux services (nmap, banner grabbing)
- Windows/AD (SMB, LDAP, Kerberos)
- Databases (MySQL, PostgreSQL, etc)

### Exploitation/
Attack techniques organized by:
- **Web:** SQL injection, file upload, XSS, SSTI, XXE, LFI
- **Windows:** PrivEsc, AD attacks, NTLM relay
- **Linux:** PrivEsc, container escape

### Writeups/HTB-Machines/
17 complete machine solutions:
- Easy (4): Warm-up machines
- Medium (4): Multi-step chains
- Hard (9): Complex exploitation
- All with technique links

### Academy/
Bug Bounty training:
- Web applications fundamentals
- HTTP/HTTPS requests deep dive
- File upload attack vectors

### Tools-Reference/
Command reference and cheatsheets:
- Information gathering (nmap, enum4linux)
- Web fuzzing (ffuf, feroxbuster, Burp)
- Exploitation (Metasploit, Impacket)
- Password attacks (hashcat, John)

### Payloads/
Ready-to-use exploits:
- Reverse shells (bash, PowerShell, Python)
- SQLi payloads
- File upload shells
- Windows UAC bypasses

---

##  Quick Machine Solving Checklist

```
 Nmap scan (all ports, all services)
  nmap -p- -sV -sC target.htb

 Record findings in writeup template

 Web enumeration (if applicable)
  ffuf, Burp Suite, Nuclei, manual exploration

 Identify vulnerability path

 Exploit and gain shell (low priv)
  echo proof of shell (whoami, id)

 Post-exploitation enumeration
  sudo -l, find SUID, cronjobs, kernel version

 Privilege escalation

 Capture flags
  cat /home/user/user.txt
  cat /root/root.txt

 Fill writeup template completely

 Link techniques used to writeup
```

---

##  Stuck?

### Can't Find Something?
1. Use search in Obsidian (Cmd+P / Ctrl+P)
2. Check the main `00-Index.md` for navigation
3. Browse section indexes (00-*-Index.md files)

### Can't Solve a Machine?
1. Check the writeup: `Writeups/HTB-Machines/[MachineName]`
2. Review the exploitation technique used
3. Compare your enumeration with the writeup

### Can't Remember a Tool?
1. Open `Tools-Reference/00-Tools-Index.md`
2. Search by tool category
3. Find commands and usage examples

---

##  Study Tips for Success

### Time Management
- Allocate 8 hours per machine (like real exam)
- Easy machines should take 2-3 hours
- Harder machines might take 8+ hours
- Don't get stuck for more than 30 min on one thing

### Effective Learning
- **Active practice** beats passive reading
- Solve machines first, then read writeups
- Document YOUR findings before comparing
- Link everything in your vault

### Exam Simulation
- Create timed challenges (24 hours)
- Use realistic point values (25+25+20)
- Write full professional reports
- No tools outside your vault for reference

---

##  Features You Now Have

###  Complete Methodology
- Week-by-week study plan
- 3-phase progression (Learn → Practice → Master)
- Success metrics for each phase
- Daily routine templates

###  Visual Navigation
- Canvas diagram showing complete workflow
- Interconnected technique nodes
- Study phase visualization
- Easy browsing

###  17 Real Examples
- Easy machines to build confidence
- Medium machines for chaining
- Hard machines for mastery
- All with detailed writeups

###  Smart Linking
- Techniques link to machines using them
- Machines link back to techniques
- Tools referenced with commands
- Cross-referenced templates

###  Reference Library
- 50+ tools documented
- 100+ payloads ready
- Technique checklists
- Command templates

---

##  Next Action

### Right Now:
1. Open Obsidian in `OSCP/` directory
2. Go to `00-Index.md`
3. Choose your path (Learn/Practice/Master)
4. Take first steps today

### This Week:
1. Familiarize with structure
2. Read 2-3 enumeration techniques
3. Practice tool usage
4. Link your notes in the vault

### This Month:
1. Complete Phase 1 (Learn)
2. Start Phase 2 (Practice Easy machines)
3. Document 2-3 machines with template
4. Identify weak areas to study

---

##  Your Numbers

| Metric | Value | Status |
|--------|-------|--------|
| Machines | 17 | Ready to practice |
| Techniques | 50+ | Ready to study |
| Tools | 50+ | Ready to reference |
| Templates | 3 | Ready to use |
| Study Weeks | 28 | Ready to follow |
| Confidence |  | Will grow! |

---

##  You're All Set!

Everything you need is organized and ready. This isn't just a knowledge base—it's your personal OSCP bootcamp. Use it, learn from it, and let it guide you to passing the exam.

**Your journey to OSCP starts now. Let's go! **

---

*Created: 2026-10-07*  
*Status: Ready for study*  
*Good luck! *

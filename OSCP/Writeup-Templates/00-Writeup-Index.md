---
title: Writeup Templates & Examples
description: Structure for documenting machine solutions and findings
tags: [templates, writeup, oscp, documentation]
---

# 📝 Writeup Templates & Examples

> Document your penetration tests, machine solutions, and findings using these templates. Good writeups reinforce learning and create a personal reference library.

---

## Why Document Everything?

✅ **Learning retention** — Writing explains your thinking  
✅ **Reference library** — Find similar techniques later  
✅ **Proof of work** — Demonstrate methodology to others  
✅ **OSCP requirement** — Official exam requires writeups of 3 machines  

---

## [[Writeup-Template|Machine Writeup Template]]

Standard structure for documenting a machine solution from reconnaissance to shell.

**Sections:**
- Enumeration findings
- Vulnerability identified
- Exploitation process
- Post-exploitation (if applicable)
- Lessons learned

**When to use:** After solving any HTB/Hack-to-Pwn machine

---

## [[Findings-Template|Vulnerabilities & Findings Template]]

Isolated vulnerability documentation—useful for audits or reporting.

**Sections:**
- Vulnerability name & CVE
- Description
- Impact
- Proof of concept
- Remediation

**When to use:** When testing multiple targets or creating audit reports

---

## [[Lessons-Learned-Template|Lessons Learned Template]]

Reflection on techniques used, mistakes made, and insights gained.

**Sections:**
- What worked well
- What didn't work
- Key insights
- Techniques to practice more
- Related techniques to explore

**When to use:** After each major challenge or completed machine

---

## Example Writeups (From Your Machines)

### 👉 How to Add Your First Writeup

1. **Create a new folder**: `Writeups/<MACHINE-NAME>/`
2. **Copy template**: Start with [[Writeup-Template]]
3. **Fill section by section** as you work through machine
4. **Link to techniques**: Use [[Exploitation/Web/SQL-Injection|technique links]] to connect to reference material
5. **Save command history**: Paste key commands used
6. **Screenshot proof**: Include proof of shell/flags

### Example: Your HTB Box Writeups

Once you solve your first machine, structure it like:

```
Writeups/
├── HTB-Retired/
│   ├── Lame/
│   │   ├── Lame-Writeup.md         # Main writeup
│   │   ├── findings.md              # Enumeration data
│   │   └── proof-of-exploitation/   # Screenshots
│   ├── Blue/
│   └── ...
└── HTB-Active/
    ├── <Current machine>/
    └── ...
```

---

## 📚 Recommended Study Workflow

### While Solving a Machine

1. **Keep terminal log**: `script machine-name.log` to record all commands
2. **Take screenshots** of key findings (enum, shell prompt, flag)
3. **Note timestamps** of when you identified each vulnerability
4. **Save exploits** used in `exploits/` folder with notes

### After Solving

1. **Review your terminal log** and writeup template
2. **Extract key commands** into writeup
3. **Explain the vulnerability** in your own words
4. **Link to related techniques** from this vault
5. **Note what you'd do differently** in lessons learned

---

## 💡 Writeup Tips

### ✅ Do's

- **Clear structure** — Use headings, sections, code blocks
- **Show your thinking** — Explain why you tried each technique
- **Include failed attempts** — Learning from failures is valuable
- **Link to tools** — Reference where to find/install tools used
- **Code formatting** — Bash, PowerShell blocks with syntax highlighting
- **Visual proof** — Screenshots of shells, flags, key output
- **Lessons learned** — Reflection on what you learned

### ❌ Don'ts

- Don't copy-paste the entire tool manual
- Don't skip the "why" — focus on methodology
- Don't include full credentials (blur or use \<REDACTED\>)
- Don't just paste PoC code without explanation
- Don't skip the exploitation verification step

---

## 🎯 Example Writeup (Skeleton)

```markdown
# HTB: <MACHINE-NAME>

**Date Solved**: 2024-XX-XX
**Difficulty**: Easy/Medium/Hard
**OS**: Linux/Windows
**IP**: 10.10.10.XXX

## Enumeration

### Nmap

\`\`\`bash
$ nmap -sC -sV 10.10.10.XXX
...findings...
\`\`\`

**Key Findings:**
- Port 22 (SSH) — OpenSSH 7.4
- Port 80 (HTTP) — Apache 2.4.6
- Port 3306 (MySQL) — MySQL 5.5.60

### Web Enumeration

...ffuf, Burp results...

## Vulnerability Analysis

[[Exploitation/Web/SQL-Injection|SQL Injection]] found in login form.

## Exploitation

### Step 1: SQL Injection Login Bypass

...command & proof...

### Step 2: Upload Shell

...command & proof...

### Step 3: Reverse Shell

...command & shell proof...

## Post-Exploitation

### Privilege Escalation

Found SUID binary, exploited [[Exploitation/Linux/Privilege-Escalation#SUID-Abuse|SUID vulnerability]].

...root shell proof...

## Lessons Learned

- **What worked**: Early fuzzing found injectable parameter
- **What didn't**: Tried SQLi on wrong param first
- **Key insight**: Always check for SUID after initial shell
- **To practice**: SSTI, NoSQL injection

## Related Techniques

- [[Exploitation/Web/SQL-Injection]]
- [[Exploitation/Linux/Privilege-Escalation]]
```

---

## 🔗 Related Templates

- [[Writeup-Template|Full writeup template]]
- [[Findings-Template|Findings template]]
- [[Lessons-Learned-Template|Lessons learned template]]

---

**Status**: Templates ready | **Last Updated**: 2026-10-07

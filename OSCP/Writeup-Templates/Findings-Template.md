---
title: Vulnerability Findings Template
description: Document individual vulnerabilities and findings
tags: [template, findings, oscp]
---

# 🔍 Vulnerability Findings Template

> Use this template to document individual vulnerabilities discovered during testing. Useful for reports and audit documentation.

---

## Vulnerability Information

| Field | Value |
|-------|-------|
| **Title** | Vulnerability Name |
| **CVE** | CVE-XXXX-XXXXX (if applicable) |
| **Type** | [SQL Injection](../Reference/Databases.md#sql-injection) / [PrivEsc](../Reference/Windows.md#windows-privilege-escalation) / etc. |
| **Severity** | Critical / High / Medium / Low |
| **Status** | Verified / Exploited / Patched |
| **Date Discovered** | YYYY-MM-DD |

---

## Description

### Overview

What is this vulnerability and how does it work?

### Root Cause

Why does this vulnerability exist? What coding/configuration mistake led to it?

### Affected Component

- **Application/Service**: [Name] [Version]
- **File/Function**: [Path/Name]
- **Configuration**: [Specific setting]
- **Technology Stack**: [relevant tech]

---

## Impact Assessment

### Confidentiality

**Impact Level:** None / Low / Medium / High / Critical

**Details:** 
What data can be accessed or leaked?

### Integrity

**Impact Level:** None / Low / Medium / High / Critical

**Details:**
What data can be modified or corrupted?

### Availability

**Impact Level:** None / Low / Medium / High / Critical

**Details:**
Can the system be made unavailable or resources exhausted?

### Business Impact

What is the real-world impact to the organization?

---

## Proof of Concept

### Prerequisites

- [ ] Network access to [service]
- [ ] Exploitation/... knowledge required
- [ ] Tools: [List tools needed]

### Step-by-Step Exploitation

#### Step 1: [First Stage]

```bash
$ [command]
$ [output]
```

Explanation: What does this step accomplish?

#### Step 2: [Second Stage]

```bash
$ [command]
$ [output]
```

Explanation: What does this step accomplish?

#### Step 3: [Exploitation]

```bash
$ [command]
$ [output - proof of exploitation]
```

Explanation: How does this demonstrate the vulnerability?

---

## Evidence

### Screenshots

> Attach screenshots showing:
> - The vulnerable input/parameter
> - The successful exploitation
> - The impact (data accessed, command executed, etc.)

### Command Output

```
[Paste relevant output demonstrating the vulnerability]
```

### Logs

```
[Security logs, application logs, or system logs showing exploitation]
```

---

## Remediation

### Recommended Fix

**Priority:** Immediate / High / Medium / Low

**Description:**

What is the correct way to fix this vulnerability?

### Implementation Details

```
Code snippet or configuration change needed
```

### Validation

How to test that the fix is effective?

### Timeline

- **Discovery**: [Date]
- **Notification**: [Date]
- **Deadline**: [Date]
- **Target Fix**: [Date]
- **Verification**: [Date]

---

## References

### Documentation

- [Official documentation link]
- [Framework security guide]
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### Tools & Resources

- Tool Name — Used for exploitation
- Technique Name — Related technique

### External References

- [CVE Database](https://cve.mitre.org/)
- [Exploit Database](https://www.exploit-db.com/)
- [HackTricks](https://book.hacktricks.xyz/)

---

## Similar Vulnerabilities

Have you seen this pattern before? Link to related findings:

- Machine 1 — Similar [SQLi](../Reference/Databases.md#sql-injection) vulnerability
- Machine 2 — Different exploitation vector, same root cause

---

## Notes & Observations

### Interesting Details

- Detail 1: [Why this is notable]
- Detail 2: [Unexpected behavior]
- Detail 3: [Potential for escalation]

### Defense Evasion Observations

Did the target have any detection or prevention mechanisms?

- WAF rules: [Observed rules]
- IDS/IPS signatures: [Encountered signatures]
- Logging: [What gets logged]

---

## Metadata

| Field | Value |
|-------|-------|
| **Tester** | Your Name |
| **Organization** | [Your org] |
| **Target** | [Machine/Application name] |
| **Assessment Type** | Penetration Test / Code Review / Configuration Audit |
| **Duration** | [How long testing took] |
| **Status** | Open / Resolved / Accepted Risk |

---

**Template Version**: 1.0  
**Last Updated**: 2026-10-07

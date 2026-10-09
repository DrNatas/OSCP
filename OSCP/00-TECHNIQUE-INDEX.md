---
title: OSCP Technique Index
description: Reusable attack patterns connected to methodology, references, and HTB evidence
tags: [oscp, techniques, index, htb]
---

# OSCP technique index

Use this folder after [enumeration](02-Enumeration/README.md) gives you an observation. Each page explains the prerequisite chain and points to a worked HTB example. Use the [reference index](Reference/00-Reference-Index.md) only after choosing the technique.

## OS-oriented layout

| Folder | Use it for | Start here |
| --- | --- | --- |
| [Linux](04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md) | Linux shells, containers, sudo, SUID, services, and root escalation | [Linux privilege escalation](04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md) |
| [Windows](05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation.md) | Windows shells, services, tasks, DLLs, installers, tokens, and SYSTEM escalation | [Windows privilege escalation](05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation.md) |
| [Active-Directory](06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse.md) | Domain identity, ACLs, Kerberos, certificates, and delegation | [AD identity and ACL abuse](06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse.md) |
| [Web](03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md) | HTTP discovery, authorization, uploads, command injection, and SQL injection | [Web discovery and access control](03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md) |
| [Cross-Platform](02-Enumeration/Techniques/Cross-Platform/01-Recon-and-Service-Enumeration.md) | Reconnaissance, service mapping, pivoting, and techniques that span operating systems | [Recon and service enumeration](02-Enumeration/Techniques/Cross-Platform/01-Recon-and-Service-Enumeration.md) |

## Core technique notes

| Technique family | Start here | HTB evidence |
| --- | --- | --- |
| Recon and service enumeration | [Recon and service enumeration](02-Enumeration/Techniques/Cross-Platform/01-Recon-and-Service-Enumeration.md) | [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md) |
| Web discovery and access control | [Web discovery and access control](03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md) | [Facts](../Writeups/HTB-Machines/Facts-Writeup.md), [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md), [CCTV](../Writeups/HTB-Machines/CCTV-Writeup.md), [Reactor](../Writeups/HTB-Machines/Reactor-Writeup.md) |
| File upload and execution | [File upload and execution](03-Initial-Access/Techniques/Web/03-File-Upload-and-Execution.md) | [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md), [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md) |
| Linux privilege escalation | [Linux privilege escalation](04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md) | [Facts](../Writeups/HTB-Machines/Facts-Writeup.md), [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md) |
| Windows privilege escalation | [Windows privilege escalation](05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation.md) | [Logging](../Writeups/HTB-Machines/Logging-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md) |
| AD identity and ACL abuse | [AD identity and ACL abuse](06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse.md) | [Logging](../Writeups/HTB-Machines/Logging-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md), [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md) |
| Kerberos, certificates, and delegation | [Kerberos, certificates, and delegation](06-Active-Directory/Techniques/Active-Directory/07-Kerberos-Certificates-and-Delegation.md) | [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md), [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md) |
| Pivoting and lateral movement | [Pivoting and lateral movement](07-Pivoting/Techniques/Cross-Platform/08-Pivoting-and-Lateral-Movement.md) | [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md) |

## Specialist notes and checklists

- [SQL injection attack path](03-Initial-Access/Techniques/Web/SQL-Injection-Path.md) — focused web/database path.
- [Enumeration checklist](02-Enumeration/Techniques/Cross-Platform/Enum-Checklist.md) — compact first-pass checklist; use the [recon technique](02-Enumeration/Techniques/Cross-Platform/01-Recon-and-Service-Enumeration.md) for reasoning.
- [Linux privilege escalation checklist](04-Linux-Escalation/Techniques/Linux/Linux-Privesc-Checklist.md) — legacy command-heavy checklist; use [Linux privilege escalation](04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md) as the canonical technique note.

## Decision path

```text
New service or host
  → Recon and service enumeration
  → Web discovery/access control, file execution, or AD enumeration
  → Validate the smallest prerequisite
  → Initial access
  → Linux/Windows privilege escalation or AD identity transition
  → Pivot if reachability changed
  → Capture evidence and update the technique note
```

## Technique note standard

When adding a technique, include:

- trigger/observation;
- prerequisite chain;
- validation test;
- execution outline;
- identity or boundary crossed;
- evidence and cleanup;
- at least one link to a machine writeup.

The old `01-MASTER-REFERENCE.md`, `02-ACTIVE-DIRECTORY-COMPLETE.md`, and `03-WINDOWS-EXPLOITATION.md` files are retained as historical references. They are intentionally not the primary navigation path because their command and technique coverage overlaps the canonical pages above.

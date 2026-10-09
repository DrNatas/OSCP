---
title: OSCP Notes - Main Guide
description: A practical, methodology-first guide to enumeration, exploitation, privilege escalation, Active Directory, pivoting, and evidence
tags: [oscp, guide, methodology, techniques, htb]
---

# OSCP notes: main guide

This is the teaching entry point for the repository. It is written so that someone who did not create these notes can understand the assessment process, choose the next useful test, and use the HTB writeups as evidence rather than as disconnected solutions.

The notes are for authorized labs, practice targets, and exam preparation. Always confirm scope before testing, and treat credentials, IP addresses, and commands in machine writeups as lab-specific evidence—not reusable secrets.

## The core method

Do not begin with a favorite tool or exploit. Begin with an observation and turn it into a testable hypothesis:

```text
observation → hypothesis → prerequisite → smallest test → result → next identity or route
```

For every meaningful lead, record:

```text
Observation:
Hypothesis:
Prerequisite to prove:
Tool or command:
Result:
Identity/reachability change:
Next action:
Evidence:
```

A banner, scanner result, credential, BloodHound edge, or CVE match is not success by itself. Success is a reproducible chain that proves what changed and why the next step became possible.

## How to use this repository

1. Start with the [fast triage board](00-FAST-TRIAGE.md) when working under time pressure.
2. Use the phase table below to choose the next phase and checkpoint.
3. Use the [technique index](00-TECHNIQUE-INDEX.md) after an observation identifies an attack pattern.
4. Use the [reference index](Reference/00-Reference-Index.md) for command syntax after choosing the technique.
5. Open the relevant [HTB writeup](../Writeups/00-HTB-Solutions-Index.md) to compare a worked chain.
6. Add the reusable lesson to the technique note; leave machine-specific output in the writeup.

## Assessment flow

| Phase | Main question | Start here |
| --- | --- | --- |
| Setup | What is in scope, and how will evidence be saved? | [Setup phase](01-Setup/README.md) |
| Enumeration | What services, names, applications, and data are reachable? | [Enumeration phase](02-Enumeration/README.md) |
| Initial access | Which observed weakness can produce a usable session? | [Initial access phase](03-Initial-Access/README.md) |
| Linux escalation | Which permission or trust boundary can cross into root? | [Linux escalation phase](04-Linux-Escalation/README.md) |
| Windows escalation | Which service, task, token, installer, or credential can cross into SYSTEM? | [Windows escalation phase](05-Windows-Escalation/README.md) |
| Active Directory | Which identity or object permission creates the next transition? | [Active Directory phase](06-Active-Directory/README.md) |
| Pivoting | What route reaches the next in-scope host or service? | [Pivoting phase](07-Pivoting/README.md) |
| Evidence | Can another person reproduce the complete chain? | [Evidence and reporting phase](08-Evidence-and-Reporting/README.md) |

The phases are iterative. Re-run enumeration after every new credential, identity, host, route, or privilege boundary.

## Choose a technique from what you found

| Observation | Technique note | HTB example to study |
| --- | --- | --- |
| New port, hostname, banner, or unusual service | [Recon and service enumeration](02-Enumeration/Techniques/Cross-Platform/01-Recon-and-Service-Enumeration.md) | [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md) |
| HTTP/HTTPS, login, API, hidden path, or authorization difference | [Web discovery and access control](03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md) | [Facts](../Writeups/HTB-Machines/Facts-Writeup.md), [CCTV](../Writeups/HTB-Machines/CCTV-Writeup.md), [Reactor](../Writeups/HTB-Machines/Reactor-Writeup.md) |
| Upload, archive, preview, parser, or admin review | [File upload and execution](03-Initial-Access/Techniques/Web/03-File-Upload-and-Execution.md) | [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md), [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md) |
| Linux shell, container, SUID, sudo, cron, or writable service | [Linux privilege escalation](04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md) | [Facts](../Writeups/HTB-Machines/Facts-Writeup.md), [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md) |
| Windows shell, service, task, DLL, installer, or token privilege | [Windows privilege escalation](05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation.md) | [Logging](../Writeups/HTB-Machines/Logging-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md) |
| Domain account, group, ACL edge, or machine-account permission | [AD identity and ACL abuse](06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse.md) | [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md) |
| SPN, TGT, certificate template, delegation, or clock-skew error | [Kerberos, certificates, and delegation](06-Active-Directory/Techniques/Active-Directory/07-Kerberos-Certificates-and-Delegation.md) | [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md), [theFrizz TGT](../Writeups/HTB-Machines/theFrizz-TGT.md) |
| Internal subnet, second interface, or service reachable only from foothold | [Pivoting and lateral movement](07-Pivoting/Techniques/Cross-Platform/08-Pivoting-and-Lateral-Movement.md) | [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md) |

## How to learn from an HTB writeup

Use a writeup after attempting the path or reaching a timebox. Read only the relevant section and answer:

- What observation made the technique relevant?
- Which prerequisite was confirmed before the exploit or transition?
- What was the smallest successful test?
- Which identity, privilege, or network boundary changed?
- What evidence proved the result?
- What failed assumption would have saved time?

Then close the writeup and reproduce the reasoning in your own practice notes. The [HTB index](../Writeups/00-HTB-Solutions-Index.md) groups the boxes by technique, platform, and preserved-note status.

## Tool discipline

Tools support a hypothesis; they do not replace one. Use the [tools index](Tools-Reference/00-Tools-Index.md) to see which tools have worked examples, and the [tool catalog](Reference/Tools-Catalog.md) for project links.

| Need | Useful starting tools | Worked notes |
| --- | --- | --- |
| Map services and names | Nmap, NetExec, SMB/LDAP tools | [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md) |
| Map web behavior | Burp, ffuf, feroxbuster, WhatWeb | [Facts](../Writeups/HTB-Machines/Facts-Writeup.md), [CCTV](../Writeups/HTB-Machines/CCTV-Writeup.md) |
| Test directory permissions | BloodHound, bloodyAD, NetExec | [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md), [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md) |
| Test tickets and certificates | Impacket, Rubeus, Certipy-AD | [Logging](../Writeups/HTB-Machines/Logging-Writeup.md), [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md) |
| Reach internal services | Ligolo-ng, Chisel, Proxychains | [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md) |

## Note organization

- **The eight numbered phase folders** are the primary path: setup, enumeration, initial access, Linux escalation, Windows escalation, Active Directory, pivoting, and evidence/reporting.
- **Phase-local `Techniques` folders** contain reusable attack patterns, prerequisites, validation, evidence, and HTB references, grouped into `Linux`, `Windows`, `Active-Directory`, `Web`, and `Cross-Platform`.
- **Reference** contains command syntax and tool documentation.
- **Exploitation** and **Payloads** contain focused supporting material inside `OSCP/`.
- **Writeups** contains machine-specific observations, credentials, outputs, screenshots, and attack chains.
- **Templates** provides a repeatable format for new practice notes.

Avoid creating another general checklist when a canonical technique or reference note already owns the material. Improve the canonical note and link the machine evidence instead.

## Add a useful note

When documenting a new box or technique, include:

1. Scope and starting conditions.
2. Observation and hypothesis.
3. Prerequisite and validation test.
4. Exact tool/command and meaningful result.
5. Identity or reachability change.
6. Failed assumption or dead end.
7. Evidence and cleanup.
8. A link between the reusable technique and the machine writeup.

Use the [writeup template](08-Evidence-and-Reporting/Writeup-Templates/Writeup-Template.md), then update the relevant technique page during review.

## Supporting entry points

- [Fast triage](00-FAST-TRIAGE.md)
- [Practice exam workflow](Practice-Exam-Methodology.md)
- [Fast triage](00-FAST-TRIAGE.md)
- [Exam rules and official guide](OSCP-Exam-Rules.md)
- [Image audit](Image-Audit.md)

The large consolidated references remain available in the [evidence archive](08-Evidence-and-Reporting/Archive/). They are not the primary study path because their content overlaps the phase, technique, and reference pages above.

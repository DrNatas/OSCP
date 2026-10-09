---
title: OSCP Fast Triage
description: A speed-first decision board that maps observations to techniques, tools, and HTB evidence
tags: [oscp, fast-triage, decision-tree, methodology]
---

# OSCP fast triage

Use this page during a timed practice run. Start with the observation you have, choose one hypothesis, run the smallest confirming test, and open the linked HTB note only when you need a worked example.

## The 30-second loop

```text
observation → hypothesis → prerequisite → smallest test → evidence → next identity/route
```

Record every branch in the format:

```text
Observation:
Hypothesis:
Prerequisite to prove:
Smallest test:
Result:
Next action:
Evidence path:
```

## Choose by observation

| You see | Open first | Then reference | HTB evidence |
| --- | --- | --- | --- |
| New port, banner, hostname, or unusual service | [Recon and service enumeration](02-Enumeration/Techniques/Cross-Platform/01-Recon-and-Service-Enumeration.md) | [Enumeration commands](Reference/00-Reference-Index.md) | [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md) |
| HTTP/HTTPS, login, API, hidden path, or hostname redirect | [Web discovery and access control](03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md) | [Web reference](Reference/Web.md) | [Facts](../Writeups/HTB-Machines/Facts-Writeup.md), [CCTV](../Writeups/HTB-Machines/CCTV-Writeup.md), [Reactor](../Writeups/HTB-Machines/Reactor-Writeup.md) |
| Upload, preview, parser, archive, or admin review | [File upload and execution](03-Initial-Access/Techniques/Web/03-File-Upload-and-Execution.md) | [Web reference](Reference/Web.md) | [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md), [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md) |
| Linux shell, container, SUID, sudo, cron, or writable service | [Linux privilege escalation](04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md) | [Linux reference](Reference/Linux.md) | [Facts](../Writeups/HTB-Machines/Facts-Writeup.md), [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md) |
| Windows shell, service, task, DLL, installer, or token privilege | [Windows privilege escalation](05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation.md) | [Windows reference](Reference/Windows.md) | [Logging](../Writeups/HTB-Machines/Logging-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md) |
| Domain account, ACL edge, group, or machine-account permission | [AD identity and ACL abuse](06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse.md) | [AD reference](Reference/Active-Directory.md) | [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md) |
| SPN, TGT, certificate template, delegation, or time error | [Kerberos, certificates, and delegation](06-Active-Directory/Techniques/Active-Directory/07-Kerberos-Certificates-and-Delegation.md) | [AD reference](Reference/Active-Directory.md) | [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md), [theFrizz TGT](../Writeups/HTB-Machines/theFrizz-TGT.md) |
| Internal subnet, second interface, or service reachable only from foothold | [Pivoting and lateral movement](07-Pivoting/Techniques/Cross-Platform/08-Pivoting-and-Lateral-Movement.md) | [Pivoting reference](Reference/Pivoting.md) | [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md) |

## First 15 minutes on a new target

1. Confirm scope, target IP, hostname, and an evidence directory.
2. Run a full TCP scan; follow with version/default-script scans on discovered ports.
3. Record every name: DNS, TLS certificate, HTTP redirect, SMB domain, and Kerberos realm.
4. For web, capture the baseline response before fuzzing: status, size, headers, cookies, technology, and random-path behavior.
5. For SMB/LDAP/Kerberos, test anonymous access and document the exact identity used.
6. Convert each result into one hypothesis. Do not run a tool just because it is available.
7. If a lead has no prerequisite or observable proof, park it and select the next branch.

## State reset table

| Current state | Next check | Canonical reference |
| --- | --- | --- |
| New target | Ports → services → names → accessible content | [Network enumeration](Reference/Network-Enumeration.md) |
| Web application | Baseline → inputs → authenticated behavior → specific hypothesis | [Web](Reference/Web.md), [SQL](Reference/Databases.md) |
| Credentials found | Identity → service access → effective rights → reuse clues | [Credentials](Reference/Credentials.md), [access](Reference/Access-and-Transfers.md) |
| Linux shell | Identity → sudo → services/tasks → writable dependencies → secrets | [Linux](Reference/Linux.md) |
| Windows shell | Token/groups → services/tasks → writable dependencies → secrets | [Windows](Reference/Windows.md) |
| Domain identity | DNS/time → shares/users/groups → verified permission path | [Active Directory](Reference/Active-Directory.md) |
| Internal service | Reachability → tunnel → one known service → enumeration | [Pivoting](Reference/Pivoting.md) |
| Objective reached | Identity/IP/proof → screenshot → reproducible commands | [Evidence](08-Evidence-and-Reporting/README.md) |
| No progress | Record blocker → revisit assumptions → switch lead → break | [Stuck workflow](Practice-Exam-Methodology.md#when-stuck) |

## Fast tool map

- [Nmap and service discovery](Tools-Reference/00-Tools-Index.md#tools-in-the-htb-notes) → [MonitorsFour](../Writeups/HTB-Machines/MonitorsFour-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md)
- [ffuf / feroxbuster](Tools-Reference/00-Tools-Index.md#tools-in-the-htb-notes) → [Facts](../Writeups/HTB-Machines/Facts-Writeup.md), [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md)
- [BloodHound / bloodyAD](Tools-Reference/00-Tools-Index.md#tools-in-the-htb-notes) → [NanoCorp](../Writeups/HTB-Machines/NanoCorp-Writeup.md), [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md)
- [NetExec / Impacket](Tools-Reference/00-Tools-Index.md#tools-in-the-htb-notes) → [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md), [Logging](../Writeups/HTB-Machines/Logging-Writeup.md)
- [Certipy-AD](Tools-Reference/00-Tools-Index.md#tools-in-the-htb-notes) → [Logging](../Writeups/HTB-Machines/Logging-Writeup.md), [Checkpoint](../Writeups/HTB-Machines/Checkpoint-Writeup.md)
- [Ligolo-ng](Tools-Reference/00-Tools-Index.md#tools-in-the-htb-notes) → [Pirate](../Writeups/HTB-Machines/Pirate-Writeup.md)

## When stuck

- Re-run enumeration after every new credential, identity, route, or privilege.
- Compare the same request as anonymous, normal user, and administrator where authorized.
- Ask which exact process consumes the writable file or permission.
- Validate time, DNS, and account format before troubleshooting Kerberos.
- Read the HTB writeup’s relevant section, then close it and reproduce the test from your own notes.

Related pages: [practice exam methodology](Practice-Exam-Methodology.md) · [technique index](00-TECHNIQUE-INDEX.md) · [all HTB writeups](../Writeups/00-HTB-Solutions-Index.md)

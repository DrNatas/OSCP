---
title: HTB Machine Writeups
type: writeup-index
tags: [htb, writeups, worked-examples, technique-evidence]
---

# HTB machine writeups

There are **26 HTB/practice notes** under this single `Writeups/` folder. These are historical lab records; verify commands, scope, and completion before reuse.

## Start by technique

| Technique | Worked notes |
| --- | --- |
| Recon and service enumeration | [MonitorsFour](HTB-Machines/MonitorsFour-Writeup.md), [NanoCorp](HTB-Machines/NanoCorp-Writeup.md), [Logging](HTB-Machines/Logging-Writeup.md), [Reactor](HTB-Machines/Reactor-Writeup.md) |
| Web access control and credential recovery | [Facts](HTB-Machines/Facts-Writeup.md), [MonitorsFour](HTB-Machines/MonitorsFour-Writeup.md), [CCTV](HTB-Machines/CCTV-Writeup.md) |
| File upload and execution | [NanoCorp](HTB-Machines/NanoCorp-Writeup.md), [Checkpoint](HTB-Machines/Checkpoint-Writeup.md), [Logging](HTB-Machines/Logging-Writeup.md) |
| Linux privilege escalation | [Facts](HTB-Machines/Facts-Writeup.md), [MonitorsFour](HTB-Machines/MonitorsFour-Writeup.md) |
| Windows privilege escalation | [Logging](HTB-Machines/Logging-Writeup.md), [NanoCorp](HTB-Machines/NanoCorp-Writeup.md) |
| AD identity and ACL abuse | [Checkpoint](HTB-Machines/Checkpoint-Writeup.md), [NanoCorp](HTB-Machines/NanoCorp-Writeup.md), [Logging](HTB-Machines/Logging-Writeup.md) |
| Kerberos, ADCS, and delegation | [Pirate](HTB-Machines/Pirate-Writeup.md), [Logging](HTB-Machines/Logging-Writeup.md), [Checkpoint](HTB-Machines/Checkpoint-Writeup.md) |
| Pivoting and lateral movement | [Pirate](HTB-Machines/Pirate-Writeup.md), [NanoCorp](HTB-Machines/NanoCorp-Writeup.md) |

## Migrated root notes

| Machine | Platform | Status |
| --- | --- | --- |
| [CCTV](HTB-Machines/CCTV-Writeup.md) | Linux | Partial: recon, default credentials, CSRF analysis, CVE entry point |
| [Checkpoint](HTB-Machines/Checkpoint-Writeup.md) | Windows / AD | Source notes; review evidence before reuse |
| [Facts](HTB-Machines/Facts-Writeup.md) | Linux | Source notes; review evidence before reuse |
| [Logging](HTB-Machines/Logging-Writeup.md) | Windows / AD | Source notes; review evidence before reuse |
| [MonitorsFour](HTB-Machines/MonitorsFour-Writeup.md) | Windows / containers | Source notes; review evidence before reuse |
| [NanoCorp](HTB-Machines/NanoCorp-Writeup.md) | Windows / AD | Source notes; review evidence before reuse |
| [Pirate](HTB-Machines/Pirate-Writeup.md) | Windows / AD | Source notes; review evidence before reuse |
| [Reactor](HTB-Machines/Reactor-Writeup.md) | Linux | Partial: recon and vulnerability identification |

## Preserved machine notes

These notes are preserved in `Writeups/HTB-Machines/` so no historical work is lost. Use the technique index above to choose what to review instead of reading them as one large sequence.

| Machine | Note |
| --- | --- |
| Administrator | [Administrator](HTB-Machines/Administrator.md) |
| Alert | [Alert](HTB-Machines/Alert.md) |
| Certified | [Certified](HTB-Machines/Certified.md) |
| Chemistry | [Chemistry](HTB-Machines/Chemistry.md) |
| Code | [Code](HTB-Machines/Code.md) |
| LinkVortex | [LinkVortex](HTB-Machines/LinkVortex.md) |
| Nocturnal | [Nocturnal](HTB-Machines/Nocturnal.md) |
| Planning | [Planning](HTB-Machines/Planning.md) |
| Puppy | [Puppy](HTB-Machines/Puppy.md) |
| RustyKey | [RustyKey](HTB-Machines/RustyKey.md) |
| Sightless | [Sightless](HTB-Machines/Sightless.md) |
| Support | [Support](HTB-Machines/Support.md) |
| TombWatcher | [TombWatcher](HTB-Machines/TombWatcher.md) |
| UnderPass | [UnderPass](HTB-Machines/UnderPass.md) |
| Voleur | [Voleur](HTB-Machines/Voleur.md) |
| theFrizz | [theFrizz](HTB-Machines/theFrizz.md) |
| theFrizz TGT | [theFrizz TGT](HTB-Machines/theFrizz-TGT.md) |
| OSCP notes | [OSCP notes](HTB-Machines/oscp-notes.md) |

## Practice use

1. Attempt the machine without opening the solution.
2. Record the observation, hypothesis, command, result, and next step.
3. Compare only after the attempt or timebox ends.
4. Extract one reusable lesson into the matching [technique note](../OSCP/00-TECHNIQUE-INDEX.md).

[OSCP guide](../OSCP/README.md) · [Practice workflow](../OSCP/Practice-Exam-Methodology.md) · [Machine template](../OSCP/08-Evidence-and-Reporting/Writeup-Templates/Writeup-Template.md) · [Screenshot status](../OSCP/Image-Audit.md)

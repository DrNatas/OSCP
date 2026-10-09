---
title: Reconnaissance and service enumeration
description: Turn ports, names, and banners into tested attack hypotheses
tags: [oscp, techniques, reconnaissance, enumeration]
---

# Reconnaissance and service enumeration

## Goal

Build an attack-surface map that records what is reachable, what it reveals, and what should be tested next. Enumeration is complete for a service only when the result has evidence and a next action (or a reason to defer it).

## Workflow

1. Scan all TCP ports, then identify versions and run safe default scripts on the discovered ports.
2. Run a focused UDP pass when the target or exercise makes it relevant; verify `open|filtered` results with a protocol query.
3. Record the target IP, hostname, virtual hosts, TLS names, domain, and clock difference together. Names affect HTTP routing and Kerberos.
4. For each service, test anonymous access, read/write permissions, exposed files, authentication, and service-specific metadata.
5. Re-run the relevant checks after obtaining credentials or a new identity. Access changes the attack surface.

Use [network reference](../../../Reference/Network-Enumeration.md), [web enumeration](../../Enumeration/Web-Enumeration.md), and [Active Directory enumeration](../../../06-Active-Directory/README.md) for commands.

## Evidence to record

| Field | Why it matters |
| --- | --- |
| Port, protocol, product, version | Narrows the technique and exploit prerequisites |
| Hostname/vhost and redirect behavior | Prevents testing the wrong application |
| Authentication result and account | Separates reachable from usable access |
| Readable or writable resource | Often more useful than the banner |
| Raw response, file, or screenshot | Makes the hypothesis reproducible |
| Next test and reason | Prevents repeated dead ends |

## HTB examples

- [MonitorsFour](../../../../Writeups/HTB-Machines/MonitorsFour-Writeup.md): a small HTTP surface became useful only after adding both the main hostname and `cacti` vhost, then checking `/.env` and a low-size `/user` response.
- [NanoCorp](../../../../Writeups/HTB-Machines/NanoCorp-Writeup.md): the nonstandard CheckMK port exposed service identity and execution context before the web upload became meaningful.
- [Logging](../../../../Writeups/HTB-Machines/Logging-Writeup.md): SMB log contents revealed a host, an account, and a password-rotation clue; BloodHound then converted directory data into testable edges.
- [Reactor](../../../../Writeups/HTB-Machines/Reactor-Writeup.md): Nuclei identified a version-specific Next.js issue, but the note correctly keeps vulnerability identification separate from exploitation proof.

## Common mistakes

- Stopping after the top-1000 scan.
- Treating a product/version match as a confirmed vulnerability.
- Fuzzing without establishing a normal response and a nonexistent-path baseline.
- Ignoring alternate ports, vhosts, downloaded files, and service output.
- Reusing anonymous results after credentials change without rechecking authenticated access.

---
title: Linux privilege escalation techniques
description: Prioritize Linux privilege escalation by permissions, configuration, and trust boundaries
tags: [oscp, techniques, linux, privilege-escalation]
---

# Linux privilege escalation techniques

## Order of operations

1. Identify the user, host, kernel, groups, routes, local listeners, processes, containers, and installed applications.
2. Check `sudo -l`, SUID/SGID, capabilities, writable files/directories, cron/timers, services, and credentials in application configuration.
3. Prefer an application-specific permission mistake over a kernel exploit. A version match is only a lead until build and prerequisites agree.
4. For every candidate, prove the complete chain: current user → writable/allowed component → privileged trigger → resulting identity.
5. Capture the privileged proof and return to enumeration; root access may reveal another host, credential, or route.

## Technique decision table

| Finding | Prove before exploitation |
| --- | --- |
| `sudo` entry | Exact command, arguments, environment, and whether user-controlled input reaches a shell or file |
| SUID/SGID or capability | Binary owner, behavior, version, and a supported abuse path |
| Cron, timer, or service | Execution user, trigger, writable dependency, and timing |
| Readable application data | Credential belongs to a useful identity and the service accepts it |
| Docker/container API or socket | Socket/API is reachable, unauthenticated or authorized, and the host boundary is exposed |
| Kernel/package issue | Exact kernel/package build and exploit prerequisites |

Use [Linux reference](../../../Reference/Linux.md) for commands and GTFOBins links. Automated enumeration is a lead generator; verify manually.

## HTB examples

- [Facts](../../../../Writeups/HTB-Machines/Facts-Writeup.md): `sudo /usr/bin/facter --custom-dir /tmp/` loaded attacker-controlled Ruby as root. The reusable lesson is a privileged interpreter with a user-controlled module path.
- [MonitorsFour](../../../../Writeups/HTB-Machines/MonitorsFour-Writeup.md): a web shell was inside a container; an unauthenticated Docker API and WSL2 host mount crossed the container boundary.

## Common misses

- Running linpeas without reading the application and service configuration it points to.
- Treating a writable directory as an exploit without identifying a privileged consumer.
- Checking only `/etc/passwd` and missing environment variables, backups, local services, or container metadata.
- Forgetting to re-enumerate after switching users.

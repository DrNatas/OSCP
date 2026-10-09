---
title: Windows privilege escalation techniques
description: Validate Windows service, task, DLL, installer, token, and credential paths
tags: [oscp, techniques, windows, privilege-escalation]
---

# Windows privilege escalation techniques

## Method

1. Record `whoami /all`, groups, token privileges, hostname, domain, routes, processes, services, scheduled tasks, installed software, and accessible files.
2. Follow the process that runs with a stronger identity. Identify its executable, arguments, configuration, working directory, DLL search path, inputs, and trigger.
3. Check ACLs on each dependency. “Users can write here” matters only if the privileged process consumes that location.
4. Test one prerequisite at a time: write access, architecture, trigger, restart rights, and callback reachability.
5. Verify the resulting identity and record cleanup. A group membership or enabled privilege alone is not proof.

## High-value patterns

| Pattern | Required chain |
| --- | --- |
| DLL search/load hijack | Privileged loader, attacker-writable search location, correct DLL architecture/exports, and a trigger |
| Scheduled task abuse | Useful execution account, writable action/dependency, and achievable trigger |
| Service path/configuration abuse | Writable executable or argument, service restart/control, and privileged service identity |
| MSI repair or installer abuse | Repair path reachable as the current user, writable artifact/configuration, and SYSTEM execution behavior |
| Credential reuse or token impersonation | Secret belongs to a relevant account and that account has the needed logon or object rights |

Use [Windows reference](../../../Reference/Windows.md) for command syntax and [AD phase](../../../06-Active-Directory/README.md) when directory permissions are part of the chain.

## HTB examples

- [Logging](../../../../Writeups/HTB-Machines/Logging-Writeup.md): a scheduled task loaded `settings_update.dll` from a writable staging workflow, producing a shell as `jaylee.clifton`.
- [NanoCorp](../../../../Writeups/HTB-Machines/NanoCorp-Writeup.md): a CheckMK MSI repair trusted staged scripts in a world-writable directory; `msiexec` executed the repair path as SYSTEM.
- [MonitorsFour](../../../../Writeups/HTB-Machines/MonitorsFour-Writeup.md): the boundary was container-to-host rather than a classic Windows service, but the same method applied—identify the privileged consumer and its writable input.

## Proof checklist

- [ ] Current and resulting identities recorded.
- [ ] ACL/permission and privileged consumer shown.
- [ ] Trigger and timing documented.
- [ ] Payload architecture and required exports/options documented.
- [ ] Cleanup and detection notes captured.

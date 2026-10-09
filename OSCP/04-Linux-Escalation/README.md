# 4. Linux privilege escalation

[Main guide](../README.md) · [Linux commands](../Reference/Linux.md)

Technique companion: [Linux privilege escalation techniques](Techniques/Linux/04-Linux-Privilege-Escalation.md). Worked examples: [Facts](../../Writeups/HTB-Machines/Facts-Writeup.md) and [MonitorsFour](../../Writeups/HTB-Machines/MonitorsFour-Writeup.md).

## First pass

```bash
id
hostname
uname -a
cat /etc/os-release
sudo -l
ip addr
ip route
ss -lntup
ps auxww
```

Read configuration and application files your account can access. Record owners, file permissions, service identities, credentials, keys, and internal endpoints.

## Follow permissions before guessing exploits

| Finding | What must be true | Next action |
| --- | --- | --- |
| Sudo entry | Exact permitted executable, arguments, environment, and authentication requirements are known | Inspect its supported behavior and matching [sudo notes](../Reference/Linux.md#sudo-bypass) |
| SUID/SGID or capabilities | Binary behavior can cross the current privilege boundary | Check ownership/version and [SUID/capability notes](../Reference/Linux.md) |
| Cron, timer, or service | A privileged process actually consumes something you can modify | Record schedule, execution user, writable component, and trigger |
| Local-only listener | Service is reachable through the foothold and has a useful access path | Inspect locally or [forward the port](../07-Pivoting/README.md) |
| Credentials or keys | They belong to a relevant account/service | Validate narrowly and re-enumerate as that identity |
| Container or Docker socket | Container/host boundary and actual permissions are understood | Inspect mounts, groups, socket access, and [container notes](../Reference/Linux.md#docker--container-escape) |
| Kernel/package issue | Exact build and prerequisites match | Review [CVE notes](../Reference/CVE-Reference.md) after configuration paths |

Enumeration scripts can help find leads; manually confirm each relevant result. Save original content before modifying a file and track cleanup.

**Checkpoint:** demonstrate the privileged identity, capture evidence, and record the complete chain. New access may expose an internal network or another account; return to enumeration.

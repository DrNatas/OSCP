---
title: Active Directory identity and ACL abuse
description: Turn directory permissions and identity data into validated account transitions
tags: [oscp, techniques, active-directory, acl, identity]
---

# Active Directory identity and ACL abuse

## Core model

Treat every BloodHound edge as a hypothesis. The useful chain is:

```text
source principal → exact right → destination object → required condition → next identity/access
```

Record domain, DC, DNS, clock difference, account format, authentication type, and the service used to validate each transition.

## Workflow

1. Collect users, groups, computers, SPNs, trusts, shares, sessions, delegation, certificate templates, and object ACLs.
2. Build an identity ledger: material, source, validated service, effective rights, and next test.
3. Recheck important edges with current directory data. Confirm inheritance, object type, required privileges, and whether the destination is reachable.
4. After every transition, enumerate again as the new identity. Group membership, remote logon rights, shares, and object permissions may change.
5. Avoid broad password guessing; read policy and prefer discovered clues, offline cracking, or narrowly justified tests.

## Reusable ACL patterns

| Right or condition | Technique direction |
| --- | --- |
| `GenericWrite` on a user/computer | Shadow Credentials, attribute modification, or other account-specific abuse; confirm the target and rollback state |
| `AddSelf` to a group | Add the source account, then re-enumerate rights inherited from the group |
| `ForceChangePassword` / password write | Reset only when authorized; validate the destination account and logon path |
| Write access to Deleted Objects or a tombstone | Reanimate the object, then validate its password and enabled state |
| Create-child plus a writable service account/dMSA path | Confirm domain/server prerequisites before any delegated-account technique |
| Machine account or DNS record write | Consider relay, RBCD, or name-resolution redirection only after proving the exact rights |

Use [AD enumeration](../../../02-Enumeration/Enumeration/Active-Directory.md) and [AD command reference](../../../Reference/Active-Directory.md) for collection and syntax.

## HTB examples

- [Logging](../../../../Writeups/HTB-Machines/Logging-Writeup.md): `GenericWrite` on `msa_health$` enabled Shadow Credentials; Protected Users forced Kerberos instead of NTLM.
- [NanoCorp](../../../../Writeups/HTB-Machines/NanoCorp-Writeup.md): `AddSelf` to `IT_SUPPORT` combined with `ForceChangePassword` on `monitoring_svc`.
- [Checkpoint](../../../../Writeups/HTB-Machines/Checkpoint-Writeup.md): write access to Deleted Objects reanimated a user, then a known password was tested narrowly against the restored account.
- [Pirate](../../../../Writeups/HTB-Machines/Pirate-Writeup.md): machine-account and delegation rights were chained into access to another host.

## Evidence checklist

- [ ] Source identity and authentication method.
- [ ] Exact right and target distinguished name.
- [ ] Required group, privilege, protocol, clock, or signing condition.
- [ ] Resulting identity or ticket validated on a specific service.
- [ ] Original attribute/ACL state recorded for cleanup.

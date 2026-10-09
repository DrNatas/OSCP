# 6. Active Directory

[Main guide](../README.md) · [AD enumeration](../02-Enumeration/Enumeration/Active-Directory.md) · [AD commands](../Reference/Active-Directory.md)

Technique companions: [AD identity and ACL abuse](Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse.md) and [Kerberos, certificates, and delegation](Techniques/Active-Directory/07-Kerberos-Certificates-and-Delegation.md). Worked examples: [Checkpoint](../../Writeups/HTB-Machines/Checkpoint-Writeup.md), [Logging](../../Writeups/HTB-Machines/Logging-Writeup.md), and [Pirate](../../Writeups/HTB-Machines/Pirate-Writeup.md).

## Establish domain context

1. Record domain, DC IP/FQDN, DNS resolver, provided identity, and reachable subnets.
2. Check name resolution and clock differences before troubleshooting Kerberos credentials.
3. Validate the supplied/discovered account against a relevant service. Distinguish successful authentication from permission to execute remotely.
4. Enumerate accessible shares, users, groups, computers, SPNs, trusts, and object permissions.
5. Record password policy before any repeated authentication attempts. Prefer clues and offline analysis to broad guessing.

## Choose the next identity transition

| Evidence | Follow-up |
| --- | --- |
| Readable share/configuration/backup | Extract relevant account names and credential clues; record their source |
| Account without preauthentication | Validate the account property before AS-REP work |
| Service account/SPN | Assess ticket request and offline cracking path |
| Group membership or object ACL edge | Verify source principal, destination object, right, inheritance, and required conditions |
| Delegation or certificate configuration | Confirm the exact configuration and tool/version requirements before using a lab technique |
| Local administrative rights | Review credentials and access exposed on that host; update the identity table |
| New credential, hash, or ticket | Determine its identity, scope, validity, and reachable services |

BloodHound is a map of collected data. Confirm important edges with current directory information. A graph path is a hypothesis until each prerequisite and identity transition succeeds.

## Identity ledger

| Identity | Material / private evidence path | Source | Validated service | Effective rights | Next test |
| --- | --- | --- | --- | --- | --- |
| DOMAIN\user | | | | | |

After each transition, recheck shares, group membership, remote logon rights, and reachable hosts. Preserve exact commands, required environment variables, ticket files used, and the identity that ran each command.

If the next host is unreachable, go to [pivoting](../07-Pivoting/README.md). If a credential fails, separate DNS, clock, account format, authentication type, permissions, and transport before discarding it.

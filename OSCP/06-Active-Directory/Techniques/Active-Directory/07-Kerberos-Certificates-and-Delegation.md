---
title: Kerberos, certificates, and delegation
description: Recognize and validate common AD ticket, certificate, and delegation paths
tags: [oscp, techniques, active-directory, kerberos, adcs, delegation]
---

# Kerberos, certificates, and delegation

## First checks

- Synchronize time or document the offset before troubleshooting tickets.
- Establish the realm, DC FQDN/IP, DNS resolution, SPN, account type, and ticket cache in use.
- Distinguish a password, NT hash, TGT, service ticket, certificate, and private key; each has different scope.
- Validate the ticket or certificate against the intended service before building the next step.

## Technique map

| Signal | Direction | Proof required |
| --- | --- | --- |
| User SPN with crackable service account | Kerberoasting | SPN, requested ticket, offline result, and usable account access |
| Machine-account time material | Timeroast | Machine identity, recovered secret, TGT, and permitted service |
| Readable gMSA password | gMSA retrieval | Principals allowed to read it and a service where the hash works |
| Writable `msDS-KeyCredentialLink` | Shadow Credentials | Exact target write, PKINIT result, recovered key/hash, and restored attribute |
| Vulnerable certificate template | ADCS abuse | Enrollment rights, EKU/SAN/subject settings, CA path, and certificate authentication result |
| Resource-based or constrained delegation | S4U/RBCD | Delegation edge, SPN/service, impersonated identity, and ticket use |
| Writable SPN plus delegation | SPN hijack | Original and new SPNs, duplicate avoidance, ticket service, and cleanup |
| Replication rights on a DC | DCSync | Exact replication right and least-privileged account/hash requested |

Use [AD reference](../../../Reference/Active-Directory.md) for commands and [credentials reference](../../../Reference/Credentials.md) for material handling.

## HTB examples

- [Pirate](../../../../Writeups/HTB-Machines/Pirate-Writeup.md): Timeroast → gMSA retrieval → RBCD/NTLM relay → constrained delegation → SPN hijack → DCSync.
- [Logging](../../../../Writeups/HTB-Machines/Logging-Writeup.md): Protected Users required Kerberos setup; Shadow Credentials yielded an NT hash, then ADCS supplied a trusted WSUS certificate.
- [Checkpoint](../../../../Writeups/HTB-Machines/Checkpoint-Writeup.md): `tgtdeleg` produced a TGT, then a dMSA/BadSuccessor path exposed the `svc_deploy` key.
- [theFrizz TGT notes](../../../../Writeups/HTB-Machines/theFrizz-TGT.md): focused ticket acquisition, cache handling, and verification.
- [NanoCorp](../../../../Writeups/HTB-Machines/NanoCorp-Writeup.md): clock skew and WinRM over TLS mattered after an ACL-based password transition.

## Troubleshooting order

1. DNS/name resolution.
2. Clock and realm configuration.
3. Account format and authentication type.
4. Ticket cache and service SPN.
5. Authorization on the destination service.

Do not change all five at once; the error boundary is part of the evidence.

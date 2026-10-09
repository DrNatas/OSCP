---
title: Pivoting and lateral movement
description: Reach newly discovered hosts while preserving identity and evidence boundaries
tags: [oscp, techniques, pivoting, lateral-movement]
---

# Pivoting and lateral movement

## Workflow

1. From the foothold, list interfaces, routes, local listeners, DNS behavior, and reachable internal hosts.
2. Confirm the destination is in scope and identify the service you need, not just the subnet.
3. Choose the smallest transport: local port forward for one service, SOCKS for proxy-aware TCP tools, or a routed tunnel for broader access.
4. Confirm the tunnel with one known service before scanning more broadly.
5. Re-run service enumeration through the working route and validate credentials separately on the new host.

## Transport choices

| Need | Method | Watch for |
| --- | --- | --- |
| One internal TCP service | SSH/local forward | The destination is reached from the SSH server, not the attacker |
| Several TCP tools | SOCKS/Chisel | Configure proxy-aware tools; ordinary SYN and UDP scans do not traverse a normal SOCKS proxy |
| Native routes and multiple hosts | Ligolo or another routed tunnel | Interface, route, session, and conflicting VPN routes |
| Callback from internal target | Forwarded listener | The target must be able to reach the callback address and port |

## Lateral movement is an identity problem

For every new host, record: source host, source identity, material used, destination service, destination identity, and authorization result. A valid credential is not automatically valid remote access.

## HTB examples

- [Pirate](../../../../Writeups/HTB-Machines/Pirate-Writeup.md): Ligolo exposed `192.168.100.0/24`, then PetitPotam/NTLM relay and delegation moved the chain from WEB01 to DC01.
- [NanoCorp](../../../../Writeups/HTB-Machines/NanoCorp-Writeup.md): an ACL transition produced a service-account credential, then Kerberos and WinRM over TLS validated the next host access.
- [Checkpoint](../../../../Writeups/HTB-Machines/Checkpoint-Writeup.md): a recovered key was tested against the `VMBackups` SMB share before memory forensics produced the next credential.

Use [pivoting reference](../../../Reference/Pivoting.md) for syntax and [AD phase](../../../06-Active-Directory/README.md) for identity tracking.

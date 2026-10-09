# 2. Enumeration

[Main guide](../README.md) · [Next: initial access](../03-Initial-Access/README.md)

Technique companion: [Reconnaissance and service enumeration](Techniques/Cross-Platform/01-Recon-and-Service-Enumeration.md). For web-specific decisions, continue to [web discovery and access control](../03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md).

## Discover, then inspect

Run on Kali with `TARGET` set and the target's `scans/` directory ready:

```bash
nmap -Pn -sT --top-ports 1000 -oA scans/tcp-top "$TARGET"
nmap -Pn -sT -p- -oA scans/tcp-all "$TARGET"
# Replace the example list with the ports found above.
nmap -Pn -sV -sC -p 22,80,445 -oA scans/tcp-services "$TARGET"
sudo nmap -Pn -sU --top-ports 20 -oA scans/udp-top "$TARGET"
```

Review default scripts for the service and exercise before running them. A failed ping does not prove the host is down. Recheck ambiguous ports with a targeted scan; high scan rates can miss services. Treat `open|filtered` UDP results as uncertain until the protocol responds.

## Follow the service

| Observation | Next actions | Reference |
| --- | --- | --- |
| HTTP/HTTPS | Read pages and source; inspect redirects, certificates, cookies, parameters, and JavaScript; record hostnames; enumerate content and vhosts | [Web](Enumeration/Web-Enumeration.md) |
| SMB/RPC | Inspect anonymous/guest access where applicable; list readable shares; review configuration and scripts; repeat with discovered credentials | [Network](../Reference/Network-Enumeration.md), [SMB access](../Reference/Access-and-Transfers.md#smb) |
| DNS | Query records and discovered names; identify domain controllers when relevant | [Network](../Reference/Network-Enumeration.md#dns-enumeration) |
| FTP/NFS/SNMP | Check anonymous or exposed access and permissions; inspect returned paths, names, and service configuration | [Network](../Reference/Network-Enumeration.md) |
| Database | Identify engine, authenticate if possible, enumerate rights and data; inspect linked servers or file access only when privileges permit | [Databases](../Reference/Databases.md) |
| Kerberos/LDAP | Confirm domain, DNS, clock, users, groups, and current account access | [AD workflow](../06-Active-Directory/README.md) |
| SSH/WinRM/RDP | Validate discovered credentials and whether that identity has remote access | [Access](../Reference/Access-and-Transfers.md) |

## Web pass

1. Browse every web port. Keep hostname and port together in the target table.
2. Establish a baseline for a nonexistent path and vhost before filtering fuzz results.
3. Check robots, source, scripts, downloads, backups, and exposed repository/configuration files.
4. Map each input and role: query, form, JSON, header, cookie, upload, and authenticated function.
5. Match file extensions and wordlists to the observed stack. Follow interesting responses manually.

**Checkpoint:** each service has recorded evidence, a hypothesis, and an explicit next action or reason to defer. A product banner alone is not proof of a vulnerability.

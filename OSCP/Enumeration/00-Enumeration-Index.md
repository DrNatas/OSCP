---
title: Enumeration Techniques
description: Reconnaissance and information gathering by target type
tags: [enumeration, oscp, information-gathering]
---

#  Enumeration Techniques

> Information gathering is the foundation of every successful penetration test. Thorough enumeration reduces exploitation time significantly.

## By Target Type

| Target | Focus | Tools | Difficulty |
|--------|-------|-------|------------|
| **Web Applications** | Services, endpoints, parameters, tech stack | ffuf, Burp, httpx, Nuclei | Low |
| **Windows Hosts** | SMB shares, RPC, WMI, users, groups | smbmap, enum4linux-ng, net commands | Low-Medium |
| **Linux Hosts** | Open ports, running services, processes, capabilities | nmap, ncat, ps, capabilities | Low |
| **Active Directory** | Users, groups, computers, trusts, ACLs | ldapsearch, Kerbrute, PowerView | Medium |
| **Databases** | Version, databases, tables, stored procedures | db clients, default creds, sqli | Medium |

---

## [ Web Enumeration](Web-Enumeration.md)

Discover and fingerprint web services, technologies, and endpoints.

**Key Techniques:**
- Service discovery (httpx, naabu)
- Technology detection (Wappalyzer, Nuclei)
- Directory/parameter fuzzing (ffuf, Burp)
- API endpoint discovery (Arjun)
- Hidden files (robots.txt, .git, .env)

**Tools:** ffuf, feroxbuster, Burp Suite, httpx, Nuclei, WhatWeb, nikto

**Links:** [[Enumeration/Web-Enumeration#ffuf-Directory-Scanning|ffuf examples]] · [[Enumeration/Web-Enumeration#Burp-Suite|Burp basics]]

---

## [ Windows Enumeration](Windows-Enumeration.md)

Enumerate SMB, RPC, local users, groups, and system information.

**Key Techniques:**
- SMB share enumeration (smbmap, smbclient)
- RPC enumeration (rpcclient)
- User and group enumeration
- Local privilege enumeration
- Service path auditing

**Tools:** enum4linux-ng, smbmap, rpcclient, net commands, PowerShell, seatbelt

**Links:** [[Enumeration/Windows-Enumeration#SMB|SMB enumeration]] · [[Enumeration/Windows-Enumeration#RPC|RPC querying]]

---

## [ Linux Enumeration](Linux-Enumeration.md)

Port scanning, service fingerprinting, and local system reconnaissance.

**Key Techniques:**
- Port scanning (nmap, ncat)
- Service version detection
- Process and capability auditing
- SSH key discovery
- Writable directory identification

**Tools:** nmap, ncat, ss/netstat, ps, cap, find, LinPEAS

**Links:** [[Enumeration/Linux-Enumeration#Nmap|Nmap command reference]] · [[Enumeration/Linux-Enumeration#Process-Analysis|Process analysis]]

---

## [ Active Directory Enumeration](Active-Directory.md)

Domain reconnaissance, user/group enumeration, trust discovery, and ACL auditing.

**Key Techniques:**
- LDAP queries (ldapsearch, PowerView)
- Kerberos user enumeration (Kerbrute)
- Forest/domain trust mapping
- Group Policy discovery
- DACL and ACE enumeration (BloodHound)

**Tools:** ldapsearch, PowerView, BloodHound, Kerbrute, Certify, adPEAS, ldapdomaindump

**Links:** [[Active-Directory.md#LDAP-Queries|LDAP queries]] · [[Active-Directory.md#BloodHound|BloodHound setup]]

---

## [ Database Enumeration](Database-Enumeration.md)

Connect to databases, discover schemas, extract credentials.

**Key Techniques:**
- Default credential testing
- Version/capability queries
- Database and table enumeration
- User privilege discovery
- UDF/stored procedure abuse

**Tools:** mysql, sqlcmd, psql, mongosh, redis-cli, mssqlclient (Impacket)

**Links:** [[Database-Enumeration.md#MySQL|MySQL commands]] · [[Database-Enumeration.md#MSSQL|MSSQL xp_cmdshell]]

---

##  Quick Reference: Common Ports

| Service | Port | Protocol | Enumeration |
|---------|------|----------|-------------|
| FTP | 21 | TCP | `nmap -sV`, anonymous login |
| SSH | 22 | TCP | Banner grabbing, version detection |
| SMTP | 25 | TCP | VRFY, EXPN, user enumeration |
| DNS | 53 | TCP/UDP | Zone transfer (axfr), dig, nslookup |
| HTTP | 80 | TCP | Web enumeration (see above) |
| HTTPS | 443 | TCP | Web enumeration + TLS certificate |
| SMB | 445 | TCP | smbmap, smbclient, enum4linux-ng |
| LDAP | 389 | TCP | ldapsearch, anonymous bind |
| HTTPS (alt) | 8443 | TCP | Web enumeration, alternate HTTPS |
| NFS | 2049 | TCP | showmount, nfs-utils |
| MSSQL | 1433 | TCP | `sqlcmd`, `mssqlclient` |
| MySQL | 3306 | TCP | mysql client, default creds |
| RDP | 3389 | TCP | xfreerdp, nmap --script rdp-enum |
| PostgreSQL | 5432 | TCP | `psql`, password-less auth checks |
| Redis | 6379 | TCP | redis-cli, no auth |
| MongoDB | 27017 | TCP | mongosh, no auth, bulk upload |
| VNC | 5900 | TCP | vncviewer |

---

##  Enumeration Workflow

### Phase 1: Network Discovery
```
nmap -sn 10.10.10.0/24          # Ping sweep to find hosts
nmap -p- <TARGET>                # Full TCP port scan
nmap -sU <TARGET>                # UDP scan common ports
```

### Phase 2: Service Fingerprinting
```
nmap -sV -sC -p <PORTS> <TARGET>  # Version detection + NSE scripts
httpx -l <HOSTS> -sc -title -td   # Probe web services
```

### Phase 3: Targeted Enumeration
```
# If web: ffuf, Burp, Nuclei
# If SMB: smbmap, enum4linux-ng
# If AD: ldapsearch, Kerbrute, BloodHound
# If DB: Try default credentials, version queries
```

### Phase 4: Documentation
- **Record all findings** in your writeup
- **Note credential sources** (found, default, guessed)
- **Build attack surface map** (what can be attacked)

---

##  Enumeration Checklist

- [ ] **All ports** enumerated (TCP -p-, UDP common)
- [ ] **Service versions** identified
- [ ] **HTTP(S)** — directories, parameters, technologies fuzzing
- [ ] **SMB** — shares, permissions, null sessions
- [ ] **RPC/LDAP** — users, groups, domain info (if AD)
- [ ] **Databases** — versions, defaults, accessible DBs
- [ ] **Credentials** — found, guessed, harvested (if any)
- [ ] **Attack surface** — clear list of exploitable services

---

##  Related

- [[Exploitation/00-Exploitation-Index|Exploitation Techniques]]
- [[Tools-Reference/Information-Gathering|Tools Reference]]
- [[OSCP-Exam-Rules|Exam Rules & Restrictions]]

---

**Status**: Complete reference | **Last Updated**: 2026-10-07

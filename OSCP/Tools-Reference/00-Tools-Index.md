---
title: Tools Reference
description: Curated tool list with links, installation, and key commands
tags: [tools, reference, oscp]
---

#  Tools Reference

> Essential tools for OSCP preparation, organized by category. Each tool includes installation, key commands, and gotchas.

---

##  By Category

### [[Information-Gathering|Information Gathering Tools]]

Essential for reconnaissance and initial enumeration.

| Tool | Purpose | Install | Cost |
|------|---------|---------|------|
| **Nmap** | Port scanning, service detection | `apt install nmap` | Free |
| **enum4linux-ng** | SMB/NetBIOS enumeration | `pip install enum4linux-ng` | Free |
| **ldapsearch** | LDAP directory queries | `apt install ldap-utils` | Free |
| **Kerbrute** | Kerberos user enumeration | GitHub release | Free |
| **naabu** | Fast port scanner | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | Free |
| **httpx** | HTTP service probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` | Free |

---

### [[Web-Fuzzing|Web Fuzzing & Scanning]]

Discover web resources, endpoints, and vulnerabilities.

| Tool | Purpose | Flags |
|------|---------|-------|
| **ffuf** | Fast web fuzzer | `-w wordlist -u URL/FUZZ` |
| **feroxbuster** | Recursive dir scanner | `-u URL -w wordlist` |
| **Burp Suite** | Web proxy & scanner | Manual testing only |
| **Nuclei** | Vulnerability scanner | `-target URL -as` |
| **nikto** | Web server scanner | `-h RHOST` |
| **WPScan** | WordPress scanner | `--url URL --enumerate u` |

**Key Commands:**

```bash
# ffuf directory enumeration
ffuf -w wordlist.txt -u http://target/FUZZ -mc 200,301,302 -c

# feroxbuster recursive
feroxbuster -u http://target -w wordlist.txt -t 100

# Nuclei auto-detection scan
nuclei -target http://target -as -s high,critical

# nikto scan
nikto -h target.com -o report.txt
```

---

### [[Password-Attacks|Password Cracking & Attacks]]

Crack hashes, brute force services, and manage passwords.

| Tool | Purpose | Hash Type |
|------|---------|-----------|
| **hashcat** | GPU-accelerated cracking | MD5, SHA, NTLM, bcrypt, etc. |
| **John** | CPU cracking + format detection | All formats |
| **Hydra** | Service brute force | SSH, SMB, HTTP, FTP, etc. |
| **Kerbrute** | Kerberos brute force | Krb5 tickets |
| **CeWL** | Wordlist generation | From web pages |

**Common Commands:**

```bash
# hashcat NTLM
hashcat -m 1000 hashes.txt wordlist.txt

# John with rules
john hashes.txt --wordlist=wordlist.txt --rules=best64

# Hydra SSH brute force
hydra -l user -P wordlist.txt ssh://target

# Kerbrute user spray
./kerbrute passwordspray -d DOMAIN --dc DC users.txt "Password123"
```

---

### [[Exploitation-Frameworks|Exploitation Frameworks & Tools]]

Frameworks and tools for active exploitation.

| Tool | Purpose | Manual? | Notes |
|------|---------|---------|-------|
| **Metasploit** | Exploitation framework | Yes* | Manual config required |
| **Impacket** | Windows/AD tools | Yes | Python scripts (mssqlclient, etc.) |
| **Evil-WinRM** | Windows shell | Yes | PowerShell remoting |
| **PwnCat** | Unified shell handler | Yes | Multiple payload support |
| **Exploit-DB** | Exploit database | Yes | Search + modify PoCs |

*Metasploit auto modules are NOT allowed in OSCP; manual setup only.

---

### [[Payloads|Payload Generators]]

Create custom shells and exploits.

| Tool | Purpose | Command |
|------|---------|---------|
| **msfvenom** | Metasploit payload gen | `msfvenom -p windows/meterpreter/reverse_tcp ...` |
| **php_filter_chain_generator** | PHP RCE chain | `python3 generator.py --chain "<?= system($_GET[0]); ?>"` |
| **PyWhisker** | AD certificate abuse | `python3 pywhisker.py -d DOMAIN -u USER --action create` |

---

##  Top 10 Essential Tools for OSCP

1. **Nmap** — Port scanning (indispensable)
2. **ffuf** — Directory & parameter fuzzing
3. **Burp Suite** — Web proxy & manual testing
4. **enum4linux-ng** — SMB enumeration
5. **ldapsearch** — LDAP directory queries
6. **hashcat** — Password cracking
7. **Metasploit** — Exploitation framework (manual mode)
8. **Impacket** — Windows/AD exploitation tools
9. **Evil-WinRM** — Windows shell handler
10. **sqlmap** — SQL injection (manual mode with `--wizard`)

---

##  Installation Quickstart

### Kali Linux (Pre-installed)

Most OSCP tools come pre-installed on Kali. Check version:

```bash
nmap --version
ffuf --version
burpsuite --version
```

### Manual Installation

```bash
# Go tools (httpx, nuclei, naabu, etc.)
apt install golang-go
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Python tools
pip install impacket pwntools scapy requests

# Download from GitHub
wget https://github.com/carlospolop/PEASS-ng/releases/download/20240101/linpeas.sh
wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.3.1/BloodHound-linux-x64.zip
```

---

##  Tool Gotchas

### Metasploit

-  Auto-exploit modules are NOT allowed
-  DO: Manual handler setup, set options, then `run`
-  Check which version (v5.x, v6.x) for reliable modules

### sqlmap

-  Automatic DB dump (`-dbs --dump`) is NOT allowed
-  DO: Use `--wizard` for parameter detection, then manually test
-  Always manually verify SQL injection first

### Burp Suite

-  Active Scanner's "Exploit" feature is NOT allowed
-  DO: Manual testing, use Repeater, modify payloads manually
-  Passive scanner is fine

### LinPEAS / WinPEAS

-  Running for enumeration is allowed
-  Auto-executing recommended exploits is NOT allowed
-  Manually verify each escalation vector before exploitation

---

##  Installation Resources

- **Kali Linux** (pre-configured): [kali.org](https://www.kali.org/)
- **GitHub Security Tools**: [awesome-hacking](https://github.com/carpedm20/awesome-hacking)
- **PayloadsAllTheThings**: [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings)
- **GTFOBins** (Linux privesc): [gtfobins.github.io](https://gtfobins.github.io)
- **LOLBAS** (Windows privesc): [lolbas-project.github.io](https://lolbas-project.github.io)

---

##  Related

- [[../Exploitation/00-Exploitation-Index|Exploitation Techniques]]
- [[../Enumeration/00-Enumeration-Index|Enumeration Guide]]
- [[../Payloads/00-Payloads-Index|Pre-built Payloads]]

---

**Status**: Index ready | **Last Updated**: 2026-10-07

# Certified
OS: Windows\
Difficulty: Medium

## Steps
> We are to use the following provided credentials: *judith.mader:judith09*

### Recon
```Bash
┌─[us-vip-3]─[10.10.14.4]─[gntsqid@htb-gb4yn4fqt9]─[~]
└──╼ [★]$ nmap -T5 --min-rate=1500 -Pn -p- -sV certified.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-08 17:02 CST
Nmap scan report for certified.htb (10.10.11.41)
Host is up (0.065s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-09 06:03:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.54 seconds
```
```Bash
┌─[us-vip-3]─[10.10.14.4]─[gntsqid@htb-gb4yn4fqt9]─[~]
└──╼ [★]$ bloodhound-python --help
usage: bloodhound-python [-h] [-c COLLECTIONMETHOD] [-d DOMAIN] [-v] [-u USERNAME] [-p PASSWORD] [-k] [--hashes HASHES] [-no-pass] [-aesKey hex key]
                         [--auth-method {auto,ntlm,kerberos}] [-ns NAMESERVER] [--dns-tcp] [--dns-timeout DNS_TIMEOUT] [-dc HOST] [-gc HOST] [-w WORKERS]
                         [--exclude-dcs] [--disable-pooling] [--disable-autogc] [--zip] [--computerfile COMPUTERFILE] [--cachefile CACHEFILE] [--use-ldaps]
                         [-op PREFIX_NAME]

Python based ingestor for BloodHound
For help or reporting issues, visit https://github.com/Fox-IT/BloodHound.py

options:
  -h, --help            show this help message and exit
  -c COLLECTIONMETHOD, --collectionmethod COLLECTIONMETHOD
                        Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default (all previous), DCOnly (no computer connections), DCOM,
                        RDP,PSRemote, LoggedOn, Container, ObjectProps, ACL, All (all except LoggedOn). You can specify more than one by separating them with a
                        comma. (default: Default)
  -d DOMAIN, --domain DOMAIN
                        Domain to query.
  -v                    Enable verbose output

authentication options:
  Specify one or more authentication options. 
  By default Kerberos authentication is used and NTLM is used as fallback. 
  Kerberos tickets are automatically requested if a password or hashes are specified.

  -u USERNAME, --username USERNAME
                        Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.
  -p PASSWORD, --password PASSWORD
                        Password
  -k, --kerberos        Use kerberos
  --hashes HASHES       LM:NLTM hashes
  -no-pass              don't ask for password (useful for -k)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  --auth-method {auto,ntlm,kerberos}
                        Authentication methods. Force Kerberos or NTLM only or use auto for Kerberos with NTLM fallback

collection options:
  -ns NAMESERVER, --nameserver NAMESERVER
                        Alternative name server to use for queries
  --dns-tcp             Use TCP instead of UDP for DNS queries
  --dns-timeout DNS_TIMEOUT
                        DNS query timeout in seconds (default: 3)
  -dc HOST, --domain-controller HOST
                        Override which DC to query (hostname)
  -gc HOST, --global-catalog HOST
                        Override which GC to query (hostname)
  -w WORKERS, --workers WORKERS
                        Number of workers for computer enumeration (default: 10)
  --exclude-dcs         Skip DCs during computer enumeration
  --disable-pooling     Don't use subprocesses for ACL parsing (only for debugging purposes)
  --disable-autogc      Don't automatically select a Global Catalog (use only if it gives errors)
  --zip                 Compress the JSON output files into a zip archive
  --computerfile COMPUTERFILE
                        File containing computer FQDNs to use as allowlist for any computer based methods
  --cachefile CACHEFILE
                        Cache file (experimental)
  --use-ldaps           Use LDAP over TLS on port 636 by default
  -op PREFIX_NAME, --outputprefix PREFIX_NAME
                        String to prepend to output file names

```

> **RUN THIS ONCE VPN IS WORKING AS PARROT DOES NOT HAVE DNS SERVER**
```Bash
faketime 'now + 7 hours' bloodhound-python -u judith.mader -p judith09 -d 10.10.11.41 -c All -dc certified.htb
```
This kept failing no matter what I did...


```Bash
[slang@crucible ~]$ rpcclient 10.10.11.41 -U judith.mader --password="judith09"
rpcclient $> queryuser judith.mader
	User Name   :	judith.mader
	Full Name   :	Judith Mader
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 08 Jan 2025 23:19:42 PST
	Logoff Time              :	Wed, 31 Dec 1969 16:00:00 PST
	Kickoff Time             :	Wed, 31 Dec 1969 16:00:00 PST
	Password last set Time   :	Tue, 14 May 2024 12:22:11 PDT
	Password can change Time :	Wed, 15 May 2024 12:22:11 PDT
	Password must change Time:	Wed, 13 Sep 30828 19:48:05 PDT
	unknown_2[0..31]...
	user_rid :	0x44f
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000006
	padding1[0..7]...
	logon_hrs[0..21]...
rpcclient $> queryusergroups 0x44f
	group rid:[0x201] attr:[0x7]
rpcclient $> querygroup 0x201
	Group Name:	Domain Users
	Description:	All domain users
	Group Attribute:7
	Num Members:8
```
```Bash
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[judith.mader] rid:[0x44f]
user:[management_svc] rid:[0x451]
user:[ca_operator] rid:[0x452]
user:[alexander.huges] rid:[0x641]
user:[harry.wilson] rid:[0x642]
user:[gregory.cameron] rid:[0x643]
```

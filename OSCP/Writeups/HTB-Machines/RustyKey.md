```bash
$ sudo nmap -Pn -T5 -sV -A -sC 10.10.11.75 -oX rustyKey_nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-15 18:51 PDT
Nmap scan report for rustykey.htb (10.10.11.75)
Host is up (0.078s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-16 09:51:15Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Aggressive OS guesses: Microsoft Windows 10 1709 - 21H2 (97%), Microsoft Windows Server 2016 (96%), Microsoft Windows Server 2019 (96%), Microsoft Windows 10 (93%), Microsoft Windows 10 1903 (93%), Microsoft Windows 10 21H1 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2022 (93%), Windows Server 2019 (92%), Microsoft Windows Vista SP1 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-16T09:51:23
|_  start_date: N/A
|_clock-skew: 7h59m54s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   78.09 ms 10.10.14.1
2   78.22 ms rustykey.htb (10.10.11.75)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.71 seconds

```


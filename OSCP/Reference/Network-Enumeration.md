# Network and service enumeration

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options.


## Nmap

```bash
sudo nmap -A -T4 -sC -sV -p- <RHOST>                                                                   # full TCP scan with scripts and service detection
sudo nmap -sV -sU <RHOST>                                                                              # UDP scan with service detection
sudo nmap -A -T4 -sC -sV --script vuln <RHOST>                                                         # run vulnerability NSE scripts
sudo nmap -sC -sV -p- --scan-delay 5s <RHOST>                                                          # slower full TCP scan for fragile services
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>    # enumerate Kerberos users
```

## Port Scanning (No Nmap)

```bash
for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt                                                                           # quick full TCP scan with netcat
export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open" 2>/dev/null; done    # bash TCP port sweep
```

## Common Ports & Protocols

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

## DNS Enumeration

```bash
# AD Domain Controller SRV Record Lookup
dig @<DNS_SERVER_IP> _ldap._tcp.dc._msdcs.<AD_DOMAIN> SRV +short    # query AD domain controller SRV records
# Example: dig @10.10.11.60 _ldap._tcp.dc._msdcs.frizz.htb SRV +short
# Output: 0 100 389 frizzdc.frizz.htb.  (priority weight port hostname)
```

## NetBIOS / SMB Enumeration

```bash
nbtscan <RHOST>                                                                                         # enumerate NetBIOS names
nmblookup -A <RHOST>                                                                                    # query NetBIOS adapter status
enum4linux-ng -A <RHOST>                                                                                # enumerate SMB/NetBIOS/LDAP info
smbmap -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN> -H <RHOST>                                             # enumerate SMB shares and permissions
smbmap -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -H <RHOST> -x 'net group "Domain Admins" /domain'    # execute command over SMB
```

## SNMP

```bash
snmpwalk -c public -v1 <RHOST>                          # walk SNMP v1 with public community
snmpwalk -v2c -c public <RHOST> .1                      # walk full SNMP tree with v2c
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25    # enumerate Windows users over SNMP
```

## memcached

```bash
echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211    # request memcached stats manually
sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info                          # enumerate memcached service
```

## ldapsearch

```bash
ldapsearch -x -h <RHOST> -s base namingcontexts                                                            # discover LDAP naming contexts
ldapsearch -H ldap://<RHOST> -x -s base -b '' "(objectClass=*)" "*" +                                      # query LDAP rootDSE attributes
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local"                                       # anonymous LDAP domain query
ldapsearch -x -h <RHOST> -D "<USERNAME>" -b "DC=<DOMAIN>,DC=<DOMAIN>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd    # search for LAPS passwords
```

Another:
- ez
- linux

## RECON
```Bash
┌─[us-vip-2]─[10.10.14.32]─[gntsqid@htb-dno3aw1bu3]─[~]
└──╼ [★]$ nmap -T5 --min-rate=1500 --open nocturnal.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-21 15:31 CDT
Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.93 seconds
┌─[us-vip-2]─[10.10.14.32]─[gntsqid@htb-dno3aw1bu3]─[~]
└──╼ [★]$ nmap -T5 --min-rate=1500 --open -sU nocturnal.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-21 15:31 CDT
Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up (0.092s latency).
All 1000 scanned ports on nocturnal.htb (10.10.11.64) are in ignored states.
Not shown: 993 open|filtered udp ports (no-response), 7 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 2.58 seconds
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/9cf35bea-0246-4883-ac56-6514b230c0c4) returned 404 during the image audit (2026-10-08).


made a login\
user:password

## EXFILTRATION ATTEMPT
Reviewing the web page, we can upload files.\
First, testing what kind of files it accepts.
> There is no outright allow/disallow list


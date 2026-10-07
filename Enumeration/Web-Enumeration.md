---
title: Web Application Enumeration
description: Service discovery, fingerprinting, and endpoint mapping
tags: [enumeration, web, oscp]
difficulty: Beginner
tools: [ffuf, Burp, httpx, Nuclei, nikto, WhatWeb]
---

# 🌐 Web Application Enumeration

> Comprehensive reconnaissance of web services, technologies, and attack surfaces.

## Quick Commands

```bash
# Discover live web services
httpx -l <HOSTS> -sc -title -td -server -fr -o <URLS>

# Probe with technology detection
nuclei -target http://<RHOST> -as -s medium,high,critical

# Enumerate directories
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401

# Fuzz parameters
arjun -u http://<RHOST>/<PATH> -m GET
```

---

## 1. Service Discovery & Fingerprinting

### httpx - Fast HTTP Service Probing

```bash
# Probe list of hosts and extract titles/technologies
httpx -l hosts.txt -sc -title -td -server -o probed.txt

# Options explained:
# -sc   = status code
# -title = page title
# -td    = JARM fingerprint (SSL/TLS)
# -server = server header
# -fr    = follow redirects
```

### WhatWeb - Web Framework Detection

```bash
whatweb -a 3 <RHOST>                      # aggressive fingerprinting
whatweb -i <FILE> --colour=never          # scan list from file
```

### Wappalyzer (Manual or CLI via Node)

Detects CMS, frameworks, analytics, CDN, hosting.

---

## 2. Directory & File Discovery

### ffuf - Fast Web Fuzzer

#### Basic Directory Scan

```bash
# Standard directory brute force
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u http://<RHOST>/FUZZ \
  --fs <SIZE>                 # filter by response size
  -mc 200,204,301,302,307,401 # match status codes
  -c                          # colorize output
```

#### Recursive Directory Discovery

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u http://<RHOST>/FUZZ \
  -recursion \
  -recursion-depth 2
```

#### File Extension Enumeration

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u http://<RHOST>/FUZZ \
  -e .php,.txt,.html,.bak,.aspx
```

#### Virtual Host/Subdomain Fuzzing

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://<RHOST>/ \
  -H "Host: FUZZ.<RHOST>" \
  -fs 185 \
  -ac               # auto calibrate baseline noise
```

#### Parameter Fuzzing

```bash
ffuf -u "http://<RHOST>/<PATH>?FUZZ=<VALUE>" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -ac
```

### feroxbuster - Recursive Brute Force

```bash
# Recursive scanning with auto-scan of discovered directories
feroxbuster -u http://<RHOST> \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -t 100 \
  -r                # follow redirects
  --filter-status 403
```

### Gobuster - Directory & DNS Enumeration

```bash
# Directory brute force
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u http://<RHOST>/ \
  -x php,txt,html,js

# DNS subdomain enumeration
gobuster dns -d <DOMAIN> \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Common Wordlists

| Wordlist | Use Case | Size |
|----------|----------|------|
| `/usr/share/wordlists/dirb/common.txt` | General directories | Small |
| `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` | Comprehensive dirs | Medium |
| `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt` | Exhaustive | Large |
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` | Raft list | Medium |

---

## 3. API & Parameter Discovery

### Arjun - Parameter Discovery

```bash
# Discover GET parameters
arjun -u http://<RHOST>/<PATH> -m GET

# Discover POST parameters  
arjun -u http://<RHOST>/<PATH> -m POST

# With authentication cookie
arjun -u http://<RHOST>/<PATH> \
  --headers "Cookie: <COOKIE>"

# Scan list of URLs
arjun -i <URLS_FILE> -oT output.txt
```

### API Endpoint Fuzzing

```bash
# Common API paths
ffuf -u https://<RHOST>/api/v2/FUZZ \
  -w api_endpoints.txt \
  -c -ac -t 250 \
  -fc 400,404,412
```

---

## 4. Hidden Files & Configuration

### Common Hidden Files to Check

```bash
# Manual checks for common files
curl -s http://<RHOST>/robots.txt
curl -s http://<RHOST>/sitemap.xml
curl -s http://<RHOST>/.env
curl -s http://<RHOST>/.git/config
curl -s http://<RHOST>/web.config
curl -s http://<RHOST>/wp-config.php

# Exposed Git repository
curl -s http://<RHOST>/.git/HEAD
# If found, use GitTools to dump
```

### Backup File Discovery

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common-backups.txt \
  -u http://<RHOST>/FUZZ \
  -mc 200
```

---

## 5. Vulnerability Scanning

### Nuclei - Automated Vulnerability Detection

```bash
# Auto-detect technologies and scan
nuclei -target http://<RHOST> -as

# Scan by severity
nuclei -target http://<RHOST> \
  -s medium,high,critical \
  -o nuclei-findings.txt

# Scan list of URLs with tags
nuclei -l urls.txt \
  -tags exposure,misconfig,cve \
  -rl 25 -c 10

# Output as JSON for analysis
nuclei -target http://<RHOST> -as -jsonl -o findings.jsonl

# Update templates
nuclei -ut
```

### nikto - Legacy Web Scanner

```bash
nikto -h <RHOST> -C all       # Run all checks
nikto -h <RHOST> -T 9,10,11   # Specific tests (admin, skip slow)
nikto -h <RHOST> -output nikto.html  # HTML report
```

---

## 6. Technology Stack Enumeration

### Via HTTP Headers

```bash
# Extract server, powered-by, x-* headers
curl -v http://<RHOST> 2>&1 | grep -i '^<'

# Common informative headers:
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3
# X-AspNet-Version: 4.0.30319
# X-Frame-Options, X-Content-Type-Options, etc.
```

### SSL/TLS Certificate Analysis

```bash
# Extract certificate details
openssl s_client -connect <RHOST>:443 </dev/null | openssl x509 -text

# Certificate Subject Alt Names often reveal subdomains
# CN=example.com, Subject Alternative Name: DNS:www.example.com, DNS:api.example.com
```

### JavaScript Source Code Review

Many modern apps load API endpoints, config, or internal paths in JS:

```bash
# Extract URLs from JS files
# 1. Fuzz for common paths: /js, /api, /static, /assets
# 2. Download and grep for API calls:
grep -ro 'https\?://[^"\ ]*' *.js | sort -u
grep -ro '/api/[^"\ ]*' *.js | sort -u
```

---

## 7. WordPress-Specific Enumeration

### WPScan

```bash
# Enumerate users, themes, plugins
wpscan --url https://<RHOST> \
  --enumerate u,t,p \
  --plugins-detection aggressive

# Check for known vulnerabilities
wpscan --url https://<RHOST> --api-token <TOKEN> --detection passive
```

### Manual WordPress Checks

```bash
# Default WordPress paths
/wp-admin/ /wp-content/ /wp-includes/
/wp-json/ (REST API)

# User enumeration
curl -s http://<RHOST>/wp-json/wp/v2/users | jq '.[] | .name, .slug'
```

---

## 8. Application-Specific Notes

### PHP Applications

- Look for `.php`, `.php3`, `.php4`, `.php5` extensions
- `.phar`, `.phtml`, `.pht` also executable
- Check for debug info in errors (database, file paths)
- `phpinfo()` sometimes exposed

### ASP.NET Applications

- Look for `.aspx`, `.asmx`, `.ashx` files
- `web.config` often contains connection strings
- Check for version in headers: `X-AspNet-Version`
- `ViewState` encoded data in forms (can be decoded)

### Java Applications

- `.jar`, `.war`, `.jsp` files
- Look for exposed `.git` or source in `/src/`
- Serialized Java objects in requests
- Spring Boot actuator endpoints (`/actuator/`, `/admin/`)

---

## 📋 Enumeration Checklist

- [ ] All HTTP/HTTPS ports identified and probed
- [ ] Technology stack determined (framework, version, DB)
- [ ] All directories/files fuzzed (at least 2-3 wordlists)
- [ ] Virtual hosts/subdomains enumerated
- [ ] API endpoints discovered
- [ ] Hidden files checked (.git, .env, web.config)
- [ ] SSL certificate examined for info leaks
- [ ] JavaScript analyzed for URLs/endpoints
- [ ] Common misconfigurations tested (XXE, CORS, etc.)
- [ ] Default credentials attempted (if applicable)

---

## 🔗 Related Notes

- [[Exploitation/Web/SQL-Injection|SQL Injection]]
- [[Exploitation/Web/Local-File-Inclusion|LFI/RFI]]
- [[Exploitation/Web/Cross-Site-Scripting|XSS]]
- [[Exploitation/Web/File-Upload-Vulnerabilities|File Upload Bypasses]]

---

**Status**: Complete | **Last Updated**: 2026-10-07

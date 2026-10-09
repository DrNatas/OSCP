---
title: CCTV
type: htb-writeup
source: Hack The Box
platform: Linux
difficulty: Easy
tags: [htb, writeup, linux, web, csrf, command-injection, cve]
---

# CCTV

> **Partial notes:** recon, default-credential login, and CSRF/token analysis up to the CVE-2023-26035 entry point. Exploitation and flags were not recorded.

## Fast lookup

- Start with [web discovery and access control](../../OSCP/03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md).
- If a request reaches a privileged parser or command path, review [file upload and execution](../../OSCP/03-Initial-Access/Techniques/Web/03-File-Upload-and-Execution.md).
- Command syntax: [web reference](../../OSCP/Reference/Web.md).

## Enumeration

```bash
sudo nmap 10.129.2.222 -Pn -T5 -sV -sC -p- --reason --open -oN cctv
```
```
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp open  http  Apache httpd 2.4.58
|_http-title: SecureVision CCTV & Security Solutions
```
The web app is a **ZoneMinder** CCTV platform (`/zm/`).

## Default credentials

ZoneMinder accepts default `admin : admin`.

## CSRF token analysis (Burp)

The login POST carries ZoneMinder's `__csrf_magic` token:
```
POST /zm/index.php?view=login HTTP/1.1
Host: cctv.htb
Content-Type: application/x-www-form-urlencoded
Cookie: ZMSESSID=...; zmSkin=classic; zmCSS=base

__csrf_magic=key%3A91bdbc3dc965630188b68bcd7fa7e8b1c7c5b996%2C1779596740&action=login&postLoginQuery=view%3Dwatch%26cycle%3Dtrue&username=admin&password=admin
```
URL-decoded body:
```
__csrf_magic=key:91bdbc3dc965630188b68bcd7fa7e8b1c7c5b996,1779596740
action=login
postLoginQuery=view=watch&cycle=true
username=admin
password=admin
```

`__csrf_magic` anatomy:

| Part | Value | Meaning |
|---|---|---|
| `key:` | prefix | token type — "key" = HMAC-based (vs `sid:` session-based) |
| `91bdbc3d...` | SHA1 HMAC | server-generated hash tied to the session |
| `1779596740` | Unix timestamp | token expiry — rejected after this time |

## Exploitation entry point

ZoneMinder is vulnerable to **CVE-2023-26035** (unauthenticated-to-RCE via missing permission check on the `snapshot` action / command injection). PoC: <https://github.com/rvizx/CVE-2023-26035>

*Steps beyond this point were not recorded in the source notes.*

---
*Migrated from local Obsidian lab notes (incomplete). Review evidence before reuse.*

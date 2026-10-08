# Reactor

OS: Linux\
Difficulty: Easy

> **Partial notes:** recon and vulnerability identification only. Exploitation and flags were not recorded.

**Tags:** `#htb` `#linux` `#easy` `#nextjs` `#middleware-auth-bypass` `#cve-2025-29927`

## Enumeration

```bash
sudo nmap 10.129.245.214 -sV -sC -T5 --reason --open -p- -Ao reactor
```
```
22/tcp   open  ssh   OpenSSH 9.6p1 Ubuntu
3000/tcp open  http  Next.js (X-Powered-By: Next.js)
```
Port 3000 is a **Next.js** application (ReactorWatch dashboard).

## Vulnerability scan (Nuclei)

> Always add `-headless` when running Nuclei headless templates, or they are excluded by default and output can be misleading.

```bash
nuclei -u http://reactor.htb:3000 -headless
```
```
[CVE-2025-29927-HEADLESS] [critical] http://reactor.htb:3000/ ["Vulnerable Next.js => 15.0.3"]
[js-libraries-detect:nextjs] [info] http://reactor.htb:3000/ ["15.0.3"]
```

**CVE-2025-29927** — Next.js middleware authorization bypass. Supplying the internal `x-middleware-subrequest` header causes the middleware (which enforces auth/redirects) to be skipped, giving access to protected routes.

*Steps beyond this point were not recorded in the source notes.*

---
*Migrated from local Obsidian lab notes (incomplete). Review evidence before reuse.*

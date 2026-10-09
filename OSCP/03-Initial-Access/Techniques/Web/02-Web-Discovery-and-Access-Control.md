---
title: Web discovery and access-control testing
description: Find the application surface, then test how it handles identity and input
tags: [oscp, techniques, web, access-control, enumeration]
---

# Web discovery and access-control testing

## When to use it

Start here when HTTP or HTTPS is open, when a service redirects to a hostname, or when an application exposes a login, upload, API, or administrative function.

## Method

1. Establish the baseline: status, size, redirects, headers, cookies, technologies, and the response for a random path.
2. Enumerate paths, extensions, virtual hosts, JavaScript, source comments, backups, robots, sitemaps, and configuration files.
3. Map every input: query string, form, JSON, cookie, header, path identifier, upload name, and hidden field.
4. Compare the same request as anonymous, as a normal account, and as an administrator where authorized.
5. Test whether the server enforces ownership and role checks server-side. Client-side controls and hidden fields are not authorization.
6. Preserve the smallest request that proves the behavior before moving to code execution.

## Technique signals

| Signal | Testable hypothesis |
| --- | --- |
| Numeric or predictable object identifier | IDOR: another user's object is returned without an ownership check |
| Writable role or nested parameter | Mass assignment: a model field outside the intended form is accepted |
| Hash/token comparison and `0e...` values | Type confusion or loose comparison changes authentication behavior |
| Protected route controlled by middleware/header | Authorization is enforced in one layer and bypassed in another |
| Default-looking application login | Default credentials or deployment documentation may still be active |
| CSRF token with state/time/session fields | Understand validation and expiry before attempting to automate a state-changing request |
| Version and reachable feature | A CVE applies only if the version, endpoint, configuration, and auth state match |

Use [web reference](../../../Reference/Web.md), [database reference](../../../Reference/Databases.md), and [SQL injection path](SQL-Injection-Path.md) for syntax and deeper payloads.

## HTB examples

- [MonitorsFour](../../../../Writeups/HTB-Machines/MonitorsFour-Writeup.md): exposed `.env` → hidden `token` parameter → IDOR → PHP type juggling → Cacti command injection.
- [Facts](../../../../Writeups/HTB-Machines/Facts-Writeup.md): an authenticated profile update accepted `password[role]=admin`, demonstrating mass assignment and broken access control.
- [CCTV](../../../../Writeups/HTB-Machines/CCTV-Writeup.md): default credentials and Burp analysis of a session-bound CSRF token preceded the ZoneMinder CVE entry point.
- [Reactor](../../../../Writeups/HTB-Machines/Reactor-Writeup.md): a framework version and middleware behavior led to a specific authorization-bypass hypothesis.

## Stop conditions

Do not escalate a web lead until you can state: the endpoint, the input, the identity, the expected control, the observed violation, and the exact request that reproduces it.

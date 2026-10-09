# Custom scripts

## KeePass password attempts

The original `keepass4brute.sh` script is not present in this checkout. The note records the intended usage:

```bash
bash keepass4brute.sh database.kdbx wordlist.txt
```

## LDAP account investigation

The original `memberOf.py` script is not present in this checkout. It queried account attributes, including group memberships, using Python's `ldap3` package. `--target` is an account name; `--domain` is also used to construct the LDAP server connection. The recorded version did not implement CSV export or recursive group traversal.

```bash
python3 memberOf.py -u USER -p 'PASSWORD' --domain DOMAIN --target ACCOUNT
```

Review the source and prerequisites before using these lab scripts; they were not executed during the notes cleanup.

[Credentials](../../../Reference/Credentials.md) · [AD workflow](../../../06-Active-Directory/README.md)

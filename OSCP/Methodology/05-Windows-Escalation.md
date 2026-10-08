# 5. Windows privilege escalation

[Methodology](../Practice-Exam-Methodology.md) · [Windows commands](../Reference/Windows.md)

## First pass

Run these in a Windows command prompt:

```bat
whoami /all
hostname
systeminfo
ipconfig /all
route print
net user
net localgroup
netstat -ano
schtasks /query /fo LIST /v
```

Determine domain membership, token privileges, group membership, installed software, service paths, and accessible configuration. Match listening ports to processes. A group membership or disabled privilege alone does not prove an escalation path.

## Build the prerequisite chain

| Finding | Validate before acting |
| --- | --- |
| Writable service executable/configuration | ACL permits the needed change, service runs with useful rights, and you can trigger execution |
| Unquoted service path | A candidate path component is writable and restart/start conditions are achievable |
| DLL loading behavior | Actual search/load path, writable location, architecture, and privileged trigger |
| Scheduled task | Execution account, action, writable dependency, and next trigger |
| Token privilege | Specific technique's token, service, OS, and session prerequisites |
| Installer policy | Both relevant user and machine policy settings before considering AlwaysInstallElevated |
| Credentials/configuration/history | Correct identity and local/domain context; reuse against a specific service |

Use [Windows reference](../Reference/Windows.md) for service, DLL, token, and credential commands. Use [AD workflow](06-Active-Directory.md) when the path depends on directory permissions.

Record any service, task, ACL, account, or file changes with a cleanup action. Confirm the resulting identity and privilege level before marking success.

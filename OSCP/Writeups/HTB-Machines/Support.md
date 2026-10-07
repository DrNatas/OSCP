# Support
OS: Windows\
Difficulty: Easy

## Steps
> I will be following *Guided Mode*
>> It is just like the starting point with 10 questions instead of just the flags

---
### Task 1
> **How many shares is Support showing on SMB?**

```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-p614afj62u]─[~]
└──╼ [★]$ nmap -p- -T5 -Pn -sV --open --min-rate=1500 support.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-17 11:43 CST
Nmap scan report for support.htb (10.10.11.174)
Host is up (0.066s latency).
Not shown: 65517 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-17 17:44:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 119.86 seconds
```
Trying SMBMAP first.
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-p614afj62u]─[~]
└──╼ [★]$ smbmap -H 10.10.11.174
[+] IP: 10.10.11.174:445	Name: support.htb
```
Failed to give info.\
Trying to do SMBCLIENT now:
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-p614afj62u]─[~]
└──╼ [★]$ smbclient -L \\\\10.10.11.174\\
Password for [WORKGROUP\gntsqid]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.174 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
> ANSWER: **6 shares**

---
### Task 2
> **Which share is not a default share for a Windows domain controller?**
>> Answer: **support-tools**

why?\
It is lowercase for starters.\
In addition, it is logically designated to a "support staff" custom group.

---
### Task 3
> **Almost all of the files in this share are publicly available tools, but one is not. What is the name of that file?**
>> Look into *support-tools*

```Bash
─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-p614afj62u]─[~]
└──╼ [★]$ smbclient \\\\10.10.11.174\\support-tools
Password for [WORKGROUP\gntsqid]:
Try "help" to get a list of possible commands.
smb: \> 
```
```Bash
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!
```
```Bash
smb: \> dir
  .                                   D        0  Wed Jul 20 12:01:06 2022
  ..                                  D        0  Sat May 28 06:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 06:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 06:19:55 2022
  putty.exe                           A  1273576  Sat May 28 06:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 06:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 12:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 06:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 06:19:43 2022

		4026367 blocks of size 4096. 971319 blocks available
```
> ANSWER: **UserInfo.exe.zip**

---
### Task 4
> **What is the hardcoded password used for LDAP in the UserInfo.exe binary?**

```Bash
smb: \> get UserInfo.exe.zip 
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (463.2 KiloBytes/sec) (average 463.2 KiloBytes/sec)
smb: \> exit
```
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-p614afj62u]─[~/sand]
└──╼ [★]$ unzip UserInfo.exe.zip 
Archive:  UserInfo.exe.zip
  inflating: UserInfo.exe            
  inflating: CommandLineParser.dll   
  inflating: Microsoft.Bcl.AsyncInterfaces.dll  
  inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll  
  inflating: Microsoft.Extensions.DependencyInjection.dll  
  inflating: Microsoft.Extensions.Logging.Abstractions.dll  
  inflating: System.Buffers.dll      
  inflating: System.Memory.dll       
  inflating: System.Numerics.Vectors.dll  
  inflating: System.Runtime.CompilerServices.Unsafe.dll  
  inflating: System.Threading.Tasks.Extensions.dll  
  inflating: UserInfo.exe.config     
```
```Bash
┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-p614afj62u]─[~/sand]
└──╼ [★]$ file UserInfo.exe
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```
This is a .NET application, which isn't exactly designed for Linux.\
We need to use a dissassembler: [Avalonia](https://github.com/icsharpcode/AvaloniaILSpy)
```Baash
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip
unzip ILSpy-linux-x64-Release.zip

┌─[us-vip-2]─[10.10.14.28]─[gntsqid@htb-p614afj62u]─[~/sand/artifacts/linux-x64]
└──╼ [★]$ ./ILSpy 
```
After unzipping and running:\
![image](https://github.com/user-attachments/assets/65c7bb99-2184-4b9c-8316-bdafa9e476b9)\
Load the file:\
![image](https://github.com/user-attachments/assets/9b7c7b90-a705-4690-b601-99efc8b4574e)\
![image](https://github.com/user-attachments/assets/5a922f32-9042-45cb-895d-8c5e9d95d369)

We can see a few functions available to us.\
One in particular seems promising and that is LdapQuery:\
![image](https://github.com/user-attachments/assets/11ac2045-cbed-4a8c-b80a-92fbbd958ee1)
```CS
public LdapQuery()
	{
		//IL_0018: Unknown result type (might be due to invalid IL or missing references)
		//IL_0022: Expected O, but got Unknown
		//IL_0035: Unknown result type (might be due to invalid IL or missing references)
		//IL_003f: Expected O, but got Unknown
		string password = Protected.getPassword();
		entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
		entry.set_AuthenticationType((AuthenticationTypes)1);
		ds = new DirectorySearcher(entry);
	}
```
We can see that it gets the password from *Protected* class.\
Let us find it:\
![image](https://github.com/user-attachments/assets/3c99597f-f135-48e6-878e-4a523e563857)
We get **0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E**, but it is encoded!\
Time to break it:
```Python
import base64
from itertools import cycle
enc_password = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E")
key = b"armando"
key2 = 223
res = ''
for e,k in zip(enc_password, cycle(key)):
res += chr(e ^ k ^ key2)
print(res)
```
> ANSWER: **nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz**

---
### Task 5
> **Which field in the LDAP data for the user named support stands out as potentially holding a password?**

> ***TOOK A BREAK HERE***







































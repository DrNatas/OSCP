# Exam rules

Checked **2026-10-08** against the [OffSec OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide). Recheck the full guide and your control-panel instructions before an attempt.

- Time: **23 hours 45 minutes**, then **24 hours** to upload documentation.
- Passing score: **70/100**. Three standalone machines total 60 points; the three-machine AD set totals 40. AD starting credentials are supplied.
- Prohibited categories include spoofing, commercial tools, automatic exploitation, mass vulnerability scanners, and AI chatbot assistance. SQLmap, Nessus, and OpenVAS are explicitly prohibited; a “manual” mode is not an exemption.
- Nmap/NSE, Nikto, and Burp Free are explicitly permitted examples. Other tools must comply with the same functional restrictions.
- Metasploit auxiliary/exploit/post modules and Meterpreter are limited to **one chosen target**, including unsuccessful attempts and `check`. No Metasploit pivoting. `msfvenom` and `multi/handler` have broader exceptions; Meterpreter still has the one-target limit.
- Reports must reproduce the attack steps. Consult the guide for proof, screenshot, exploit-code, packaging, and submission requirements.

Older lab writeups and the general command collection are not tool-permission guides.

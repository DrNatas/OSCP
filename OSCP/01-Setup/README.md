# 1. Setup

[Main guide](../README.md) · [Next: enumeration](../02-Enumeration/README.md)

- [ ] Record the authorized targets, starting credentials, objective, and end time.
- [ ] Confirm the VPN address and route; use the VPN address for callbacks.
- [ ] Create a target note from the [machine template](../08-Evidence-and-Reporting/Writeup-Templates/Writeup-Template.md).
- [ ] Keep a terminal session for scans, one for the listener, and one for interaction.
- [ ] Reserve breaks and time to assemble evidence. Record a Metasploit target choice if you make one.

Run on Kali, replacing the example address and interface:

```bash
export TARGET=192.0.2.10
export LHOST=192.0.2.20
export LPORT=4444
mkdir -p "practice/$TARGET"/{scans,loot,exploits,images}
cd "practice/$TARGET"
ip -brief addr show tun0
ip route get "$TARGET"
script -q -a session.log
```

`exit` ends the recorded shell. Treat session logs and recovered credentials as private practice evidence. Before a new target, update the variables and working directory.

Use `DOMAIN`, `DC_IP`, and `DC_FQDN` in domain notes. Record the exact hostname separately from its IP; virtual hosts, TLS, and Kerberos can depend on names.

References: [tmux, transfers, and shells](../Reference/Access-and-Transfers.md), [exam rules](../OSCP-Exam-Rules.md).

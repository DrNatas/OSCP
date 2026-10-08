# 3. Initial access

[Methodology](../Practice-Exam-Methodology.md) · Next: [Linux](04-Linux-Escalation.md), [Windows](05-Windows-Escalation.md), or [AD](06-Active-Directory.md)

## Choose a supported path

| Evidence | Hypothesis to validate | Reference |
| --- | --- | --- |
| Disclosed credentials or keys | Credentials work for this service and account | [Credentials](../Reference/Credentials.md), [access](../Reference/Access-and-Transfers.md) |
| Input affects a query, command, or template | A controlled input changes server-side behavior | [SQL](../Reference/Databases.md#sql-injection), [web](../Reference/Web.md) |
| User-controlled path or upload | Readable files or executable upload behavior follow from the observed permissions | [LFI and uploads](../Reference/Web.md), [upload study notes](../../Exploitation/Web/Academy-Notes/FILE-UPLOAD-ATTACKS.md) |
| Exposed application/version | A specific issue matches the version, configuration, endpoint, and authentication level | [CVE reference](../Reference/CVE-Reference.md) |

1. Record the endpoint, parameter, identity, and minimum reproducible request.
2. Confirm the prerequisite with a small observable test before attempting a shell.
3. Read any exploit source. Record its origin, dependencies, target options, and edits.
4. Start the listener, then check callback address, port, route, and payload architecture.
5. Execute once, inspect the response and listener, and record the outcome.

## Stabilize and record

Confirm `id` or `whoami`, hostname, network interfaces, and working directory. Determine whether the session is on the host or inside a container. Upgrade the terminal if needed, and save the exact method used to reconnect.

If the shell fails, separate **request reached the application**, **code execution occurred**, and **callback reached the listener**. Diagnose each boundary before changing payloads.

**Checkpoint:** a usable session with a documented access chain. Capture evidence now, then begin local enumeration.

References: [shells](../Reference/Shells.md), [transfer and terminal handling](../Reference/Access-and-Transfers.md), [evidence](08-Evidence-and-Reporting.md).

---
title: File upload and execution chains
description: Analyze upload processing and turn a trusted file workflow into a controlled execution test
tags: [oscp, techniques, web, file-upload, execution]
---

# File upload and execution chains

## The important question

An upload is not automatically code execution. Identify who processes the file, where it is stored, what parser opens it, what identity performs the action, and whether the resulting behavior is observable.

## Workflow

1. Capture the complete upload request and identify validation on extension, MIME type, archive contents, filename, and size.
2. Determine whether the file is stored, unpacked, previewed, indexed, or opened by another process.
3. Identify the processing identity and trigger: immediate request, scheduled task, login, admin review, desktop shell, or service poll.
4. Build the least dangerous proof first: a controlled file read, DNS/SMB callback, or benign command that proves the parser/identity.
5. Match the payload architecture and callback route to the target. Record delivery, trigger, listener, and resulting identity separately.
6. Save the original file and exact package structure; document cleanup and scope.

## Reusable patterns

| Pattern | Prerequisites to prove |
| --- | --- |
| Archive or document causes an outbound authentication | The backend opens the file and can reach the attacker over the chosen protocol |
| Extension/package is trusted by a loader | Write access to the consumed location, accepted manifest, and a trigger that runs under a useful identity |
| Upload reaches an executable web directory | Server-side execution is enabled and the uploaded path is predictable |
| Application input reaches a command or template | The vulnerable feature is reachable and the controlled output can be observed |

## HTB examples

- [NanoCorp](../../../../Writeups/HTB-Machines/NanoCorp-Writeup.md): a `.library-ms` file inside a ZIP caused Windows Explorer to authenticate to Responder as `web_svc`; the upload was a credential-capture primitive, not a shell by itself.
- [Checkpoint](../../../../Writeups/HTB-Machines/Checkpoint-Writeup.md): a writable `DevDrop` share accepted a malicious `.vsix`; VS Code loaded its activation code as `ryan.brooks`.
- [MonitorsFour](../../../../Writeups/HTB-Machines/MonitorsFour-Writeup.md): authenticated Cacti input reached `rrdtool`, which was used to write a webshell and then fetch a reverse shell.
- [Logging](../../../../Writeups/HTB-Machines/Logging-Writeup.md): a writable staging directory and a scheduled task created a DLL search/load hijack as `jaylee.clifton`.

## Evidence checklist

- [ ] Original request and response saved.
- [ ] Validation bypass, if any, recorded.
- [ ] Storage path and processing identity confirmed.
- [ ] Trigger and callback route confirmed.
- [ ] Resulting identity verified with `id`, `whoami`, hostname, or equivalent.

# 8. Evidence and reporting

[Main guide](../README.md) · [Machine template](Writeup-Templates/Writeup-Template.md) · [Exam rules](../OSCP-Exam-Rules.md)

Use the [HTB writeup index](../../Writeups/00-HTB-Solutions-Index.md) to compare attack chains, and add reusable lessons to the relevant [technique note](../00-TECHNIQUE-INDEX.md) instead of copying them into another general reference.

## Collect as you work

Save the access conditions, command, result, and screenshot for each identity transition. Use descriptive local filenames such as `images/01-initial-access.png` and `images/02-privilege-escalation.png` beside the target note.

For exam-style proof, show the proof file at its original path in an interactive target shell together with the target IP. Submit proof through the control panel before the exam ends. See the [official guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) and the [rules summary](../OSCP-Exam-Rules.md).

Capture Linux context:

```bash
id
hostname
ip addr
date -u
```

Capture Windows context:

```bat
whoami
hostname
ipconfig
```

Then display the exercise's actual proof path using `cat` or `type`; do not substitute a copied local file. Keep enough terminal context to associate the result with the correct target.

## Write the reproducible chain

- Starting state: target, services, supplied access, and attacker's network context.
- Enumeration: the observation that justified the chosen technique.
- Initial access: request/command, exploit source, edits, listener, and resulting identity.
- Escalation or lateral movement: prerequisites, commands, identity changes, and evidence.
- Result: objective achieved, evidence paths, and relevant cleanup.
- Lessons: missed clue, failed assumption, and one change for the next practice run.

## Final review

- [ ] Commands are in execution order and identify where they ran.
- [ ] IPs, hostnames, users, and ports agree across notes and screenshots.
- [ ] Screenshots are readable and correctly captioned.
- [ ] Modified exploit code and reasons for the changes are recorded.
- [ ] Each local image link renders without network access.
- [ ] Required objectives and submission steps have been checked against the current guide.

The screenshot inventory is in [Image audit](../Image-Audit.md). Missing historical images are marked in their original context until the originals can be restored.

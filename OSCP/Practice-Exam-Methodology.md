# Practice exam methodology

Work one evidence-backed hypothesis at a time. For each attempt record **observation → hypothesis → command → result → next step**. Re-enumerate whenever your identity, permissions, credentials, or network reach changes.

## Run order

| Phase | What to do | Checkpoint before moving on |
| --- | --- | --- |
| [1. Setup](Methodology/01-Setup.md) | Prepare scope, notes, targets, and evidence folders | Each target has a working note and known IP |
| [2. Enumeration](Methodology/02-Enumeration.md) | Map ports, names, applications, and accessible data | Each service has a result and a next action |
| [3. Initial access](Methodology/03-Initial-Access.md) | Validate a specific weakness and obtain a usable session | Record identity, host, access path, and evidence |
| [4. Linux escalation](Methodology/04-Linux-Escalation.md) | Follow permissions, configuration, and credentials | Demonstrate the new privilege level |
| [5. Windows escalation](Methodology/05-Windows-Escalation.md) | Follow token rights, services, tasks, and credentials | Demonstrate the new privilege level |
| [6. Active Directory](Methodology/06-Active-Directory.md) | Map identities, access, and object permissions | Record each identity transition and prerequisite |
| [7. Pivoting](Methodology/07-Pivoting.md) | Reach internal services through an existing foothold | Confirm the route and one known service |
| [8. Evidence and reporting](Methodology/08-Evidence-and-Reporting.md) | Save proof and explain the reproducible chain | Evidence and commands agree with the result |

Start with the AD phase when the exercise supplies domain credentials. Enumeration and evidence collection continue throughout every phase.

## Target tracker

Copy this table into the practice session note. Track only evidence-backed progress.

| Target / role | Services / names | Current identity | Best lead | Next action | Evidence saved | Done |
| --- | --- | --- | --- | --- | --- | --- |
| TARGET | | None / provided account | | | | No |

## When stuck

1. State the exact prerequisite your current idea needs. Confirm it is present.
2. Read the error and raw response; distinguish network, authentication, authorization, and payload failures.
3. Revisit unopened ports, virtual hosts, downloaded files, configuration, and newly discovered credentials.
4. After roughly 30–45 minutes without new evidence, write the blocker and switch leads or hosts. This is a personal practice timebox, not an exam rule.
5. Return after a break with one new test. Repeating the same command without changing a relevant condition does not advance the hypothesis.

## Session finish

- [ ] Every successful access path has commands and evidence.
- [ ] Failed leads have a short reason, so they are not repeated.
- [ ] Useful general lessons are linked to a reference, rather than copied into multiple indexes.
- [ ] Temporary lab changes and files are recorded for cleanup.
- [ ] Screenshots render from relative local paths.
- [ ] The report can be followed from the initial access conditions.

Use the [quick checklist](Quick-Reference.md) during a run and the [command reference](Reference/00-Reference-Index.md) for syntax. Review [exam rules](OSCP-Exam-Rules.md) before simulating exam conditions; historical writeups may use different tools.

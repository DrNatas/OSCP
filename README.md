# OSCP preparation guide

This repository is a community study resource for preparing for the OffSec Certified Professional (OSCP/OSCP+) exam. It brings together an exam-day guide, fast triage, technique paths, a practice workflow, command references, and machine writeups.

Use these notes only for authorized labs, practice targets, and systems you are allowed to test. This repository is independent of OffSec and does not guarantee a passing result. Exam requirements can change, so the current [official OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide), [OSCP+ Exam FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ), and your exam control panel take precedence over this summary.

## Start here

1. Read the [exam rules](#exam-rules) before choosing tools or planning a mock exam.
2. Follow the [exam-day start checklist](#exam-day-start) to establish scope, connectivity, and evidence.
3. Use [fast triage](#fast-triage) to choose a branch from an observation.
4. Open the [technique index](#technique-index) for the relevant reusable method.
5. Use the [practice exam workflow](#practice-exam-workflow) to rehearse the full assessment and reporting process.

## Exam rules

**Verified October 9, 2026** against the official guide, last updated April 20, 2026, and the official FAQ, last updated July 31, 2026. Read the full live guide and control-panel instructions again before your attempt.

### Format, time, and scoring

- The exam is proctored and gives you **23 hours and 45 minutes** to complete the assessment, followed by **24 hours** to submit the report.
- The current structure is three standalone targets worth **20 points each** (60 total) and one three-machine Active Directory set worth **40 points**. Starting AD credentials are provided. The target objectives and point values appear in the exam control panel.
- You need **70 out of 100 points** to pass. The official guide lists valid combinations, including all 40 AD points plus three local proofs, 20 AD points plus three local proofs and two proof files, or 10 AD points plus three completed standalone targets.
- The order in which targets appear in your report determines their grading order and point allocation. Choose that order deliberately.
- The control panel allows up to 24 machine reverts, and this limit can be reset once. Targets start freshly reverted. Wait for a revert to finish and click once; reverting discards changes on that machine.

### Proof and reporting

- Write a professional report that records the full, reproducible attack path for each target: steps, commands, relevant output, and proof.
- Treat the first report upload as final. The guide says missing screenshots or other information cannot be added afterward.
- Retrieve each required local.txt or proof.txt from its original location through an interactive shell on the target. Use the target's shell to display the file; a web shell or another method does not satisfy the stated proof requirement.
- Capture a screenshot for every required proof file. It must show the file contents and the target IP address in the same screenshot. The guide names ipconfig, ifconfig, or ip addr for showing the address.
- Submit proof-file contents in the exam control panel before the exam ends. The panel does not confirm whether the submitted value is correct.
- Full points require an administrative shell: root on Linux, or SYSTEM, Administrator, or a user with Administrator privileges on Windows.
- Document exploit code correctly. For an unmodified exploit, provide its URL rather than copying the full source. For a modified exploit, include the changed code, original URL, shellcode-generation command if relevant, highlighted changes, and why they were made.
- Submit a PDF report inside a .7z archive within the 24-hour upload window. Name the PDF OSCP-OS-XXXXX-Exam-Report.pdf and the archive OSCP-OS-XXXXX-Exam-Report.7z, replacing OS-XXXXX with your OSID; the names are case-sensitive. Keep the archive under 200 MB, do not password-protect it, and include scripts or proof-of-concept code as text inside the PDF. Verify the upload hash and final submission confirmation.

### Tool and conduct restrictions

The exam guide prohibits:

- Spoofing, including IP, ARP, DNS, and NBNS spoofing.
- Commercial tools or services such as Metasploit Pro and Burp Pro.
- Automatic exploitation tools such as SQLmap and SQLninja.
- Mass vulnerability scanners such as Nessus, NeXpose, OpenVAS, Canvas, Core Impact, and SAINT.
- AI chatbots and LLMs, including OffSec KAI, ChatGPT, DeepSeek, and Gemini, and any feature or external utility that performs a prohibited or restricted function.

Nmap and its scripting engine, Nikto, Burp Free, and DirBuster are examples the guide permits. A tool name alone does not make every feature permissible; you are responsible for knowing what the tool and its dependencies do. The guide is the authority for tool questions.

Metasploit and Meterpreter may be used on **one target machine of your choice**. The restriction applies to Auxiliary, Exploit, and Post modules, Meterpreter payloads, unsuccessful attempts, and the check function. Choose the target before using them; do not test them across several targets first. Metasploit cannot be used for pivoting. The guide permits msfvenom and multi/handler across targets, while the Meterpreter one-target limit still applies. Interfaces that use Metasploit inherit these restrictions.

Do not seek or receive help about exam objectives, or share exam information with others during the exam. The official guide allows Discord as a general research resource, but not to ask for or receive assistance. Download software or source code from the exam environment to your local machine only when necessary to compromise a target, and delete it after completing the objectives.

The official FAQ describes the exam as open book: personal notes and online resources are permitted, except AI chatbots and LLMs with direct prompt access. Exam activities must remain on the host machine running the proctoring application.

For an issue during the exam, use the official proctoring support channel; support can help with technical problems, not exam objectives or hints. See the [official exam guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) and [FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ) for the complete, current requirements.

## Exam-day start

### Before the scheduled start

- Read the complete official guide, proctoring instructions, and reporting requirements. Plan to arrive at the proctoring session early and follow the current instructions.
- Prepare your permitted Kali environment, report template, note structure, screenshot location, and a way to back up your work. Plan for food, rest, power, and a backup internet connection during the long session.
- Keep this repository or your personal notes available as permitted by the exam instructions. Do not use AI or ask another person for exam help.

### At the start

1. Read the exam email and control panel. Record the end time, report deadline, in-scope targets, target objectives, point values, and proof-file requirements.
2. Start the proctored session and connect from Kali Linux with OpenVPN, using the connection pack and the current guide's instructions. The pack is sent by email at the scheduled start.
3. Create an evidence folder and one working note per target. Record the target IP, starting identity, scope, and time.
4. Start high-level enumeration across all assigned targets. Map reachable ports, services, versions, hostnames, and the AD environment before spending a long block on one lead.
5. Use the points and objectives shown in the control panel to decide where to spend time. Keep proof capture and report writing current as you work.

Do not rely on a fixed plan such as “finish one target in eight hours” or a stale point target. The actual target objectives and their values are shown in your control panel.

## Fast triage

Use one evidence-backed loop:

> Observation → hypothesis → prerequisite → smallest confirming test → result → next identity or route

For each lead, record:

- Observation
- Hypothesis
- Prerequisite to prove
- Smallest test
- Result
- Next action
- Evidence path

### First 15 minutes on a new target

1. Confirm the target IP, scope, hostname clues, and evidence note.
2. Run a full TCP port scan, then identify versions and useful default-script results on open ports.
3. Record names from DNS, TLS certificates, redirects, SMB, and Kerberos.
4. For a web service, capture a baseline response before fuzzing: status, size, headers, cookies, technology, and behavior for a random path.
5. Test anonymous access to relevant services and record the exact identity used.
6. Turn findings into specific hypotheses. Park a lead if you cannot name its prerequisite or a way to observe success.

### Choose the next branch

| Observation | Start with | Then consult |
| --- | --- | --- |
| New port, banner, hostname, or unusual service | [Recon and service enumeration](OSCP/02-Enumeration/Techniques/Cross-Platform/01-Recon-and-Service-Enumeration.md) | [Network enumeration reference](OSCP/Reference/Network-Enumeration.md) |
| HTTP/HTTPS, login, API, hidden path, or hostname redirect | [Web discovery and access control](OSCP/03-Initial-Access/Techniques/Web/02-Web-Discovery-and-Access-Control.md) | [Web reference](OSCP/Reference/Web.md) |
| Upload, preview, parser, archive, or admin review | [File upload and execution](OSCP/03-Initial-Access/Techniques/Web/03-File-Upload-and-Execution.md) | [Web reference](OSCP/Reference/Web.md) |
| SQL behavior or database credentials | [SQL injection attack path](OSCP/03-Initial-Access/Techniques/Web/SQL-Injection-Path.md) | [Database reference](OSCP/Reference/Databases.md) |
| Linux shell, container, SUID, sudo, cron, or writable service | [Linux privilege escalation](OSCP/04-Linux-Escalation/Techniques/Linux/04-Linux-Privilege-Escalation.md) | [Linux reference](OSCP/Reference/Linux.md) |
| Windows shell, service, task, DLL, installer, or token privilege | [Windows privilege escalation](OSCP/05-Windows-Escalation/Techniques/Windows/05-Windows-Privilege-Escalation.md) | [Windows reference](OSCP/Reference/Windows.md) |
| Domain account, group, ACL edge, or machine-account permission | [AD identity and ACL abuse](OSCP/06-Active-Directory/Techniques/Active-Directory/06-AD-Identity-and-ACL-Abuse.md) | [Active Directory reference](OSCP/Reference/Active-Directory.md) |
| SPN, TGT, certificate template, delegation, or time error | [Kerberos, certificates, and delegation](OSCP/06-Active-Directory/Techniques/Active-Directory/07-Kerberos-Certificates-and-Delegation.md) | [Active Directory reference](OSCP/Reference/Active-Directory.md) |
| Internal subnet, second interface, or service reachable only from a foothold | [Pivoting and lateral movement](OSCP/07-Pivoting/Techniques/Cross-Platform/08-Pivoting-and-Lateral-Movement.md) | [Pivoting reference](OSCP/Reference/Pivoting.md) |

### Reset after a state change

Re-enumerate after every new credential, identity, host, route, or privilege level.

| Current state | Next check |
| --- | --- |
| New target | Ports → services → names → accessible content |
| Web application | Baseline → inputs → authenticated behavior → specific hypothesis |
| Credentials found | Identity → service access → effective rights → reuse clues |
| Linux shell | Identity → sudo → services and tasks → writable dependencies → secrets |
| Windows shell | Token and groups → services and tasks → writable dependencies → secrets |
| Domain identity | DNS and time → shares, users, and groups → verified permission path |
| Internal service | Reachability → tunnel → one known service → enumeration |
| Objective reached | Identity and IP → proof file → screenshot → reproducible commands |

If a lead stops producing evidence, revisit prerequisites, read the raw error or response, check unopened services and newly found credentials, then switch leads or targets. During practice, use a 30–45 minute no-progress timebox as a personal rule, not as an OffSec requirement.

## Technique index

The detailed techniques are organized by phase in [OSCP/](OSCP/README.md). Use a technique page for prerequisites, validation, execution, evidence, cleanup, and worked examples. Use the [command and tool indexes](#repository-map) for syntax after selecting a technique.

| Phase or technique | Start here |
| --- | --- |
| Setup and scope | [Setup](OSCP/01-Setup/README.md) |
| Enumeration and service mapping | [Enumeration](OSCP/02-Enumeration/README.md) |
| Initial access | [Initial access](OSCP/03-Initial-Access/README.md) |
| Linux privilege escalation | [Linux escalation](OSCP/04-Linux-Escalation/README.md) |
| Windows privilege escalation | [Windows escalation](OSCP/05-Windows-Escalation/README.md) |
| Active Directory | [Active Directory](OSCP/06-Active-Directory/README.md) |
| Pivoting and lateral movement | [Pivoting](OSCP/07-Pivoting/README.md) |
| Evidence and reporting | [Evidence and reporting](OSCP/08-Evidence-and-Reporting/README.md) |

For each new technique note, capture the trigger observation, prerequisite chain, validation test, execution outline, identity or boundary crossed, evidence, cleanup, and a link to a machine writeup.

## Practice exam workflow

Practice one evidence-backed hypothesis at a time. Re-enumerate whenever identity, permissions, credentials, or network reachability changes. Use the official tool restrictions during a mock exam so your practice builds compliant habits.

| Phase | Work | Checkpoint |
| --- | --- | --- |
| Setup | Prepare scope, target notes, report, and evidence folders | Each target has a note, known IP, and starting conditions |
| Enumeration | Map ports, names, applications, and accessible data | Each service has a result and next action |
| Initial access | Validate one observed weakness and obtain a usable session | Record identity, host, access path, and evidence |
| Privilege escalation | Follow permissions, configuration, services, tasks, and credentials | Demonstrate the new privilege level |
| Active Directory | Map identities, access, and object permissions | Record each identity transition and prerequisite |
| Pivoting | Reach internal services through an existing foothold | Confirm the route and enumerate a known service |
| Evidence and reporting | Save proof and explain the reproducible chain | Report, commands, screenshots, and proof agree |

Start the AD work from the supplied credentials when the practice scenario provides them. The phases are iterative; return to enumeration when you discover a new identity, service, or route.

Copy this tracker into a practice note:

| Target / role | Services / names | Current identity | Best lead | Next action | Evidence saved | Complete |
| --- | --- | --- | --- | --- | --- | --- |
| Target | | None / provided account | | | | No |

### When stuck

1. State the exact prerequisite your current idea needs and confirm whether it is present.
2. Read the raw error or response. Separate network, authentication, authorization, and payload failures.
3. Revisit unopened ports, virtual hosts, downloaded files, configuration, and newly discovered credentials.
4. After roughly 30–45 minutes without new evidence, record the blocker and switch leads or targets. This is a practice timebox, not an exam rule.
5. Return after a break with a changed condition or a new test; repeating the same command without a relevant change does not advance the hypothesis.

### Practice session finish

- Every successful access path has commands and evidence.
- Failed leads have a short reason so you do not repeat them blindly.
- Useful general lessons point to a reference or technique note instead of being copied into several indexes.
- Temporary lab changes and files are recorded for cleanup.
- Screenshots resolve from their relative paths.
- The report can be followed from the initial access conditions through each proof.

Use the [writeup template](OSCP/08-Evidence-and-Reporting/Writeup-Templates/Writeup-Template.md) and the [HTB machine index](Writeups/00-HTB-Solutions-Index.md) for practice documentation and worked examples.

## Repository map

- [Detailed phase and methodology guide](OSCP/README.md)
- [Technique index](OSCP/00-TECHNIQUE-INDEX.md)
- [Tools index](OSCP/Tools-Reference/00-Tools-Index.md)
- [Command reference index](OSCP/Reference/00-Reference-Index.md)
- [Machine writeups](Writeups/00-HTB-Solutions-Index.md)
- [Machine note template](OSCP/08-Evidence-and-Reporting/Writeup-Templates/Writeup-Template.md)
- [Image inventory and missing screenshots](OSCP/Image-Audit.md)

Open the repository root as the Obsidian vault so the OSCP notes and writeups are available together. Markdown links also work in VS Code and GitHub. Keep machine-specific output in the relevant writeup, reusable attack patterns in the technique notes, and shared command syntax in the reference folder.

## Code of conduct

### Our pledge

In the interest of creating an open and welcoming environment, contributors and maintainers pledge to make participation in this project and its community a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our standards

Examples of behavior that contributes to a positive environment include:

- Using welcoming and inclusive language.
- Being respectful of differing viewpoints and experiences.
- Gracefully accepting constructive criticism.
- Focusing on what is best for the community.
- Showing empathy towards other community members.

Examples of unacceptable behavior include:

- Sexualized language or imagery and unwelcome sexual attention or advances.
- Trolling, insulting or derogatory comments, and personal or political attacks.
- Public or private harassment.
- Publishing others' private information, such as a physical or electronic address, without explicit permission.
- Other conduct that could reasonably be considered inappropriate in a professional setting.

### Maintainer responsibilities

Project maintainers are responsible for clarifying the standards of acceptable behavior and taking appropriate, fair corrective action in response to unacceptable behavior. Maintainers may remove, edit, or reject comments, commits, code, wiki edits, and issues that are not aligned with this Code of Conduct. They may temporarily or permanently ban contributors for other behavior they deem inappropriate, threatening, offensive, or harmful.

### Scope and enforcement

This Code of Conduct applies in all project spaces and when someone represents the project or its community in public. Representation includes using an official project email address, posting through an official social media account, or acting as an appointed representative at an online or offline event.

Report abusive, harassing, or otherwise unacceptable behavior to the project team at [syr0@protonmail.com](mailto:syr0@protonmail.com). Reports will be reviewed and investigated, with a response appropriate to the circumstances. The project team will keep the reporter's identity confidential. Maintainers who do not follow or enforce this Code in good faith may face temporary or permanent repercussions as determined by other project leaders.

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant, version 1.4](https://www.contributor-covenant.org/version/1/4/code-of-conduct.html). For common questions, see the [Contributor Covenant FAQ](https://www.contributor-covenant.org/faq).

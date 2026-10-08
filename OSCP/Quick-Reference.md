# Practice quick checklist

[Full workflow](Practice-Exam-Methodology.md) · [Commands](Reference/00-Reference-Index.md)

| Current state | Next check | Commands |
| --- | --- | --- |
| New target | Ports → services → names → accessible content | [Network](Reference/Network-Enumeration.md) |
| Web application | Baseline → inputs → authenticated behavior → specific hypothesis | [Web](Reference/Web.md), [SQL](Reference/Databases.md) |
| Credentials found | Identity → service access → effective rights → reuse clues | [Credentials](Reference/Credentials.md), [access](Reference/Access-and-Transfers.md) |
| Linux shell | Identity → sudo → services/tasks → writable dependencies → secrets | [Linux](Reference/Linux.md) |
| Windows shell | Token/groups → services/tasks → writable dependencies → secrets | [Windows](Reference/Windows.md) |
| Domain identity | DNS/time → shares/users/groups → verified permission path | [AD](Reference/Active-Directory.md) |
| Internal service | Reachability → tunnel → one known service → enumeration | [Pivoting](Reference/Pivoting.md) |
| Objective reached | Identity/IP/proof → screenshot → reproducible commands | [Evidence](Methodology/08-Evidence-and-Reporting.md) |
| No progress | Record blocker → revisit assumptions → switch lead → break | [Reset checklist](Practice-Exam-Methodology.md#when-stuck) |

Keep this page as a decision aid. Detailed commands have a single home in the reference pages. Check [exam rules](OSCP-Exam-Rules.md) before choosing tools for a simulated exam.

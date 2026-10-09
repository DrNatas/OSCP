# Image audit

Checked 2026-10-08. Screenshots stay at the point in each note where they were originally referenced. No replacement or evidence image was fabricated.

## Repaired local links

- Two exploit README images now use the existing `screenshots/1.png` and `screenshots/2.png` files.
- Seven screenshot embeds in the local HTB notes now use explicit relative image paths, so they resolve in Markdown previews as well as Obsidian.
- Removed one malformed duplicate image embed in TombWatcher; the adjacent intended placement remains marked for restoration.
- No image files were deleted or moved.

## Missing local originals

Nine distinct files are absent from the checkout. They were also not found in repository history or a filename search of Documents and Downloads. Eleven original placements are marked in the notes because two images appeared at more than one relevant step. Restore each original to its destination below, then replace the missing-image notice with a relative image embed.

| Note | Original reference | Restore destination relative to note |
| --- | --- | --- |
| [Voleur](../Writeups/HTB-Machines/Voleur.md) | `/Images/voleur/svc_ldap_to_restore_users.png` | `images/svc_ldap_to_restore_users.png` |
| [Voleur](../Writeups/HTB-Machines/Voleur.md) | `/Images/voleur/generic-write-lacey.png` | `images/generic-write-lacey.png` |
| [TombWatcher](../Writeups/HTB-Machines/TombWatcher.md) | `/Images//TombWatcher.png` | `images/TombWatcher.png` |
| [TombWatcher](../Writeups/HTB-Machines/TombWatcher.md) | `/Images/alfred-tombwatcher.png` | `images/alfred-tombwatcher.png` |
| [TombWatcher](../Writeups/HTB-Machines/TombWatcher.md) | `/Images/WriteSPN.png` | `images/WriteSPN.png` |
| [TombWatcher](../Writeups/HTB-Machines/TombWatcher.md) | `Images/infra-to-ansible.png` | `images/infra-to-ansible.png` |
| [TombWatcher](../Writeups/HTB-Machines/TombWatcher.md) | `/Images/sam-to-john.png` | `images/sam-to-john.png` |
| [Puppy](../Writeups/HTB-Machines/Puppy.md) | `/Images/puppy.htb/puppy-to-developers.png` | `images/puppy-to-developers.png` |
| [Puppy](../Writeups/HTB-Machines/Puppy.md) | `/Images/puppy.htb/puppy-dpapi.png` | `images/puppy-dpapi.png` |

## Unavailable remote attachments

All 62 unique GitHub attachment URLs returned HTTP 404 to the download request. Their original URLs remain linked at the exact screenshot positions in the notes. They could not be made available offline; an original export or accessible copy is needed. A 404 does not establish whether an attachment was deleted or requires different access.

| Note | Unavailable image placements |
| --- | --- |
| [FILE-UPLOAD-ATTACKS](03-Initial-Access/Academy/BUG-BOUNTY-HUNTER/FILE-UPLOAD-ATTACKS.md) | 2 |
| [WEB-APPLICATIONS](03-Initial-Access/Academy/BUG-BOUNTY-HUNTER/WEB-APPLICATIONS.md) | 1 |
| [Administrator](../Writeups/HTB-Machines/Administrator.md) | 14 |
| [Alert](../Writeups/HTB-Machines/Alert.md) | 9 |
| [Chemistry](../Writeups/HTB-Machines/Chemistry.md) | 3 |
| [Code](../Writeups/HTB-Machines/Code.md) | 3 |
| [LinkVortex](../Writeups/HTB-Machines/LinkVortex.md) | 3 |
| [Nocturnal](../Writeups/HTB-Machines/Nocturnal.md) | 1 |
| [Planning](../Writeups/HTB-Machines/Planning.md) | 1 |
| [Sightless](../Writeups/HTB-Machines/Sightless.md) | 11 |
| [Support](../Writeups/HTB-Machines/Support.md) | 5 |
| [UnderPass](../Writeups/HTB-Machines/UnderPass.md) | 9 |

## Reconnected screenshots

Five previously unembedded screenshots were visually inspected and placed in the matching local notes:

- NanoCorp: hiring form beside web enumeration; HTB completion confirmation at the end.
- Checkpoint: HTB completion confirmation at the end.
- Reactor: ReactorWatch dashboard after the scan notes.
- Pirate: HTB completion confirmation at the end.

HTB completion confirmations are labeled as such; they do not substitute for terminal proof. Canvas and HTML-export assets retain their original paths. Website assets under `HTB/facts.htb/randomfacts/` and the Kali SVG are not target evidence screenshots.

## New screenshots

Use an `images/` folder beside the machine note and a caption that names the event. Example: `![Privilege escalation](images/02-privilege-escalation.png)`. Keep the note and its image directory together when moving or exporting. Screenshots can be reused at multiple relevant steps without duplicating the underlying file.

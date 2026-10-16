# Windows Security event-ID notes

A short reference for this lab, not a complete Windows event catalog. Read the
recording host, time, account, outcome, and relevant fields together. Windows
event IDs and Wazuh rule IDs identify different things.

## Present in the first investigation

| Windows ID | Meaning | Useful caution | Microsoft reference |
| --- | --- | --- | --- |
| 4624 | Successful logon session on the recording host | Check LogonType and account; success does not establish unauthorized access. | [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) |
| 4625 | Failed logon on the recording host | Read both Status and SubStatus, plus LogonType and source context. | [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) |
| 4768 | Kerberos TGT request on a domain controller | Check the result; a request alone does not establish a completed logon. | [4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768) |
| 4769 | Kerberos service-ticket request on a domain controller | A ticket request does not prove access to the target service. | [4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769) |
| 4776 | NTLM credential validation | Domain accounts are validated by a DC; local accounts by their local computer. Source workstation is not the destination server. | [4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776) |

## Useful related IDs, not included in this case

| Windows ID | Meaning | Useful caution | Microsoft reference |
| --- | --- | --- | --- |
| 4771 | Kerberos pre-authentication failure on a DC | Read FailureCode; these are Kerberos codes, not NTLM status codes. | [4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771) |
| 4648 | Logon attempt using explicit credentials | Can appear with RunAs or scheduled tasks; it is not itself a successful logon or an attack verdict. | [4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648) |
| 4672 | Sensitive privileges assigned to a new logon | Correlate LogonId with the session; this does not itself prove privilege escalation. | [4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672) |
| 4688 | Process creation | Command-line collection depends on audit configuration. | [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) |
| 4740 | Account lockout | CallerComputerName can help investigate the source. | [4740](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740) |

Their absence from this selected dataset does not establish that no such
activity occurred. Reference notes do not create new evidence or audit coverage.

## Quick field reminders

LogonType on [4624/4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625):

- `2`: interactive.
- `3`: network.
- `10`: Remote Desktop / remote interactive.

For 4625 these describe the attempted logon, not a successful session.

Common [4776 status codes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776):

- `0xC000006A`: incorrect password.
- `0xC0000064`: unknown username.
- `0xC0000234`: account locked.
- `0x0`: successful validation.

[4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
may report generic `Status: 0xC000006D` alongside a more specific SubStatus,
such as `0xC000006A`. Read both instead of assuming every failure means the
same thing.

[4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
uses a separate Kerberos code set. `0x18` means invalid pre-authentication
information and commonly indicates an incorrect password; do not interpret it
using the NTLM status table.

The same notes are available from **Context → Windows event IDs** and the
investigation Guide. The notes explain event semantics; they do not classify
this exercise as malicious or benign.

# Failed Kerberos domain sign-in

Route: `routes/ad-authentication/kerberos-logon-failure.yaml`.

Alice enters a wrong domain password during an online interactive sign-in on
WS01. DC01 rejects password pre-authentication. This is one failed sign-in,
not a password spray or a packet-level Kerberos implementation.

| Observation | Host | Required failure auditing |
| --- | --- | --- |
| 4771: pre-authentication failure, status `0x18`, type `2` | DC01 | Kerberos Authentication Service |
| 4625: interactive failure, logon type `2`, status/substatus `0xC000006D`/`0xC000006A` | WS01 | Logon |

The audit gates are independent. Disabling either removes that observation;
unchanged scenario expectations then fail validation. No successful 4768, 4769,
or 4624 is generated for this attempt.

## Fidelity boundary

- Event schemas: 4771 v0 and 4625 v0 in `windows-security-2025-01`.
  Microsoft documents these schemas from Windows Server 2008 / Vista-era
  systems onward; the lab does not assert a tested OS build or patch level.
- Known domain account; online DC; password pre-authentication type 2.
  FAST, disabled pre-authentication, smart cards, cached/offline sign-in,
  NTLM fallback, expired passwords, and lockout are not modeled.
- User, SID, host, and address values derive from the environment. Ports,
  timing, record IDs, ticket flags, and SimLab correlation are synthetic.
- SYSTEM/User32/winlogon and explicit `Kerberos` in 4625 are synthetic baseline
  choices, not observed samples. A real sign-in can report `Negotiate`.
  Unavailable workstation network/process details retain placeholders.
- SimLab links the two observations through separately labeled ground truth;
  it does not invent a shared Windows correlation field or issued ticket.

Schema and field references: Microsoft [4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
and [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).
These are documentation references, not validation against captured telemetry.

## Inspect and analyze

In `uv run simlab tui`, start a new simulation and select **Failed Kerberos
domain logon**. Inspect both events, their field origins, and XML.

Detect displays **Not assessed**: the current profile covers NTLM, not Kerberos.
Running it still creates the usual analysis artifact with zero findings; the
workflow locks and artifact schemas are unchanged.

Wazuh support is unchanged: export includes 4625 but omits unsupported 4771,
recording both counts. This partial export is not Kerberos detection parity.
Direct Kerberos spray and Kerberos-aware detection remain deferred.

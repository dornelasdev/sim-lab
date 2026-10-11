# SOC L1 exercise: suspected password spray

## Objective and current tool coverage

Identify a pattern of failed domain authentication, relate the DC and file-server
observations, and write an evidence-based escalation note.

Today this exercise supports Wazuh rule evaluation through `wazuh-logtest`, plus
inspection of the original telemetry. It does not yet provide dashboard searches,
an alert queue, or endpoint response. A logtest match is a rule-engine result;
it is not a persisted dashboard alert or a real incident.

## Prepare the evidence

Run `uv run simlab tui`, start a new simulation, select `corp-lab`, then choose
**Internal password spray**. Generate and inspect the six events, then choose
**Next: Export**. Reference analysis is optional.

For the CLI path:

```bash
uv run simlab generate authentication \
  --environment environments/corp-lab.yaml \
  --route routes/ad-authentication/password-spray.yaml

uv run simlab export wazuh \
  --telemetry outputs/internal-password-spray/<telemetry-id>
```

Replace `<telemetry-id>` with the generated bundle's directory name. Follow
[Wazuh replay](wazuh-replay.md) to submit the exported `events.jsonl` to a fresh
logtest session. Record the matched rule IDs and supporting fields.

The simulation uses known accounts and bad-password failures. No live AD systems
or compromised endpoints are involved. Scenario labels and SimLab correlation
IDs are author context; base the investigation on the event fields.

## Triage checklist

1. Identify the source, affected accounts, destination, and authentication type.
2. Compare 4776 on DC01 with 4625 on FS01. Explain what each system observed.
3. Count distinct usernames and establish the time span. Check whether source
   names and addresses agree across the observations.
4. Explain why this resembles a spray. Distinguish evidence of a multi-account
   pattern from proof that an attacker reused one password.
5. Assess what is missing: successful authentication, endpoint process context,
   account history, and whether the source activity was authorized.
6. Write a short escalation note with evidence, confidence, and requested checks.

Embedded event timestamps describe the simulated sequence. Wazuh logtest
correlation uses ingestion time: submit the lines continuously in one session.
The two time bases should be identified in your notes.

## Comparison exercise

Repeat with **Repeated password failure** (`repeated-password-failure.yaml`) in
a new logtest session. Both cases contain six failure events; the comparison
targets only Alice. The distinct-user spray rules should not fire for it.

That result demonstrates a detection threshold. It does not establish that
single-account failures are harmless; they can still warrant investigation.

## Expected observations and example note

Review this after attempting the checklist:

- WS01 targets Alice, Bob, and Carol over SMB on FS01 within about 19 seconds.
- Each attempt produces NTLM validation failure 4776 on DC01 and network-logon
  failure 4625 on FS01 (type 3, `0xC000006D` / `0xC000006A`).
- Wazuh spray rules 100101 and 100111 match independently on the third distinct
  username when replayed within their ingestion window.
- The supplied evidence contains failures only. It cannot establish whether an
  account was subsequently compromised, or whether WS01 was already compromised.

> Suspected multi-account authentication attack from WS01 (10.10.0.101).
> Three domain accounts—Alice, Bob, and Carol—have failed NTLM authentication
> associated with SMB access to FS01 between approximately 09:15:00 and 09:15:19
> UTC on 2026-09-14. DC credential-validation and FS01 network-logon records
> support the same pattern. Escalate for review of WS01 endpoint activity,
> authentication successes, and authorized activity. Evidence supports suspected
> password spraying; password reuse and account compromise are unconfirmed.

## Record your work

Keep a short personal report with the bundle/replay IDs, tool version, rule
results, relevant event excerpts, your reasoning, and the final escalation note.
Generated data lives under ignored `outputs/`; local notes can remain under
ignored `local-notes/`. Sanitize real captures before publishing any examples.

The same investigation questions can later be used in another SIEM, including
Splunk. Tool ingestion, searches, and detection behavior require their own
implementation and validation.

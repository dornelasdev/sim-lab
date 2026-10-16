# First investigation: suspected password spray

This exercise covers preparation, real Wazuh rule-test evaluation, evidence
investigation, and a saved analyst assessment. It uses reproducible simulated
Windows records, not a live AD deployment or captured endpoint evidence.

Cases and assessments are generated locally; none are needed in a fresh
checkout. The first preparation creates the investigation. Report refinements
remain deferred until after the rework PR merge. See the
[rework scope](soc-rework.md) for final validation checkpoints.

## Prepare the investigation

With Docker Desktop running, start the existing temporary manager if needed:

```bash
docker compose -f integrations/wazuh/compose.yaml up -d
```

The primary entry is now:

```bash
uv run simlab tui
```

Choose **Start investigation**, review the exercise/runtime brief, and choose
**Prepare case**. Merely opening this page does not evaluate anything. Preparation
runs in the background while the UI remains responsive; repeated runs and Back
are disabled until completion. Keep the application open until it finishes.
Normal quit actions are also blocked while preparation runs, even with the Guide
or command palette open. Forced terminal closure is not a supported cancellation
mechanism.
Then **Open investigation** opens that exact saved evaluation directly, even
when newer or older evaluations also exist. Opening still verifies artifact
identities and checksums. Afterward, Back to cases lets you choose other saved
evaluations, and Main menu returns to the entry screen.

Errors stay visible with a retry option. There is no local-detector fallback;
evidence already generated is retained, and previous cases/reports are not
deleted. The UI does not start/stop the manager, alter runtime configuration,
or add credentials, ports, or Docker mounts. Opening and reviewing a saved
investigation remain independent of Docker.

The same backend is available through the CLI:

```bash
uv run simlab prepare password-spray
```

Preparation generates the evidence, submits the supported events automatically,
collects the engine results, and saves the case and evaluation separately. The
CLI prints both locations; the TUI shows the saved evaluation identity. It
waits briefly for the logtest socket; if the manager is still starting, retry
after it is ready. An unavailable manager, changed rule files, or unexpected
detection behavior is an error, not a substitute local result.

Expected result: 15 evidence events, 12 evaluated failures, three context-only
Kerberos events, and two independent spray matches (100101 and 100111). No spray
alert should arise from the earlier Alice-only sequence.

Evidence is stable under `outputs/cases/password-spray/<case-id>/`. Actual
evaluation results are stored separately under
`outputs/evaluations/<case-id>/<evaluation-id>/`; detection timestamps can differ
on every run. The original case is not overwritten. The saved `alerts.json`
contains only matches returned by Wazuh, with evidence references resolved from
its `full_log` and `previous_output`. `results.json` retains all twelve results.

Generation-only attempt/correlation labels live in separate `author-context.json`
for verification. They are not part of the analyst evidence in `events.jsonl`.
The environment snapshot supports hostname/IP context. Both artifact directories
include manifests and checksums for the stored files.

## Open and investigate

```bash
uv run simlab tui
```

Choose **Open prepared investigation** on the main menu, select the saved
evaluation, then **Open case**. Each preparation run is listed separately by
detection time. Opening verifies the case and evaluation identities, checksums,
and links between engine output and evidence. A corrupt artifact is rejected.
No Docker access is needed for reviewing saved cases.

Keyboard shortcuts in an open case:

- `1` Alert, `2` Evidence, `3` Context, `4` Assessment. Evidence focuses the table;
  use arrows to inspect rows and `Space` to select/remove the current reference.
- `/` opens Evidence and focuses the account filter; it does not apply filters.
- `[` / `]` selects the previous/next Wazuh match, stopping at either end. This
  uses the same filter behavior as the match dropdown and preserves picked evidence.

These shortcuts are inactive while typing in fields or using dropdowns, and do
not operate beneath overlays. The footer shows shortcuts relevant to the current
focus. TAB navigation, visible buttons, and clicking tabs remain available.

The **Alert** tab displays each independent Wazuh match with its processing time
and supporting event range. **View supporting events** opens **Evidence** narrowed
to that match's returned correlation records. **Clear filters** restores the
full fifteen-event context; selecting another match does not clear picked
evidence.

Evidence filters combine with AND: account text, event host text, source IP,
event ID, and inclusive event-time bounds. Clock-only times such as `09:15`
use the case date in UTC. ISO datetimes can supply a different date or an explicit
offset. Event host means the observer, such as DC01 or FS01. Source IP resolution
can use inventory when the event contains only a workstation name; `*` marks
those derived addresses. The event details preserve the original Windows fields
and their simulation provenance.

Text fields apply with **Apply** or Enter. Changing Event ID or a checkbox
applies the current form immediately, including its text fields. Clear filters
and context pivots refresh once after setting their controls. The current event
stays highlighted when it still matches; otherwise the first matching event is
shown, or the empty state if none match. These view changes do not alter marked
evidence or assessment notes.

Frames group the Filters, Evidence, Current event, and Assessment panels. Evidence
captions show visible/total records and the number selected for assessment. The
reverse-highlighted row is the event currently being inspected, not necessarily
selected evidence; its highlight remains when focus moves to another control.
The Pick marker identifies assessment selections. A left `|` marker indicates
keyboard focus on a control, while underline indicates mouse hover. Disabled
buttons are dimmed and struck through. The terminal background is retained by
the default SimLab theme.

Inside dropdowns, hovered rows use a blue-gray fill and the keyboard-highlighted
row uses a stronger muted-teal fill. Moving over or highlighting an option does
not select it; click or press Enter to confirm, or Escape to dismiss.

Select rows and choose **Select evidence** to collect references for your
assessment. **Selected only** reviews that set. Saving an assessment retains
those references; filters and selection do not modify the source artifacts or rerun
Wazuh. Out-of-range searches explicitly distinguish unavailable evidence from
an absence of activity. Use `g` for the investigation Guide and Escape to return
to the case picker or main menu.

## Assess and save

Before writing the assessment, use the **Context** tab between Evidence and
Assessment. It combines the saved domain/host/service inventory with a short
analyst brief, useful questions, and L1 decision guidance. Inventory is context,
not proof of a user's activity or authorization. This is not a normal-activity
baseline, a scenario answer, or newly collected evidence.

Its pivot buttons open Evidence with fresh filters while preserving picked
events and draft notes:

- **Source timeline:** all supplied events tied to the active match's source IP,
  including inventory-based resolution. Disabled if that source is ambiguous.
- **Earlier activity:** all supplied records before the active match's evaluation
  window begins, using original event time. Both observer matches use the same
  window boundary; synthetic host offsets do not shift this comparison.
- **Successful logons:** all case-wide 4624 records. Compare time, host, account,
  and logon type before relating a successful logon to failed attempts.

These pivots reuse the existing fifteen events; they do not query a SIEM,
generate more records, or restore unavailable logs. Ownership, expected account
access, authorized tasks/tickets, initiating processes, and later activity remain
explicit requests or gaps. Closure needs corroborating context, not assumptions
based on missing data. The guide supports a proportionate recommendation rather
than prescribing a verdict.

**Windows event IDs** opens a focused reference overlay. The same notes appear
in the investigation Guide, with [Microsoft source links in the reference
document](windows-event-reference.md). IDs present in this case are distinguished
from other useful IDs that are not part of its evidence. The reference includes
logon-type reminders and the distinction between Status/SubStatus and Kerberos
failure codes.

After selecting relevant evidence, open **Assessment**. Its scope is the whole
case and the selected evaluation, not only the match currently shown in Alert.
Both engine matches remain independent; relating them is your analysis.

Write the five notes in your own words:

- **Observed facts:** what the logs establish, with useful times, accounts,
  event IDs, hosts, and source context.
- **Working hypothesis:** your explanation of those facts, not a confirmed
  identity, password reuse, or compromise inferred without evidence.
- **Evidence gaps / uncertainty:** what the available records cannot establish.
- **Decision rationale:** why the evidence supports your chosen disposition.
- **Recommended next steps:** the collection, validation, or escalation you
  would request. If no further action is recommended, explicitly say so.

Choose **Escalate for further investigation**, **Pending: more evidence needed**,
**Close: explained benign activity**, or **Close: false positive**. Benign means
the observed pattern has an authorized explanation; false positive means the
detection does not substantiate the suspected behavior. Neither conclusion is
selected automatically, and the form does not grade your reasoning or prove
your hypothesis. All five notes, a decision, and at least one selected event
are required to save. Note fields accept up to 12000 characters each.

TAB moves between note fields; Enter inserts a new line. Use **Save assessment**
or Ctrl+S. This saves an analyst-authored snapshot separately from the evidence:

```text
outputs/reports/<case-id>/<evaluation-id>/<assessment-id>/
  assessment.json   Notes, decision, selected references, exact artifact links
  report.md         Readable report with Windows/Wazuh IDs and time context
  SHA256SUMS        Checksums for both files
```

The report includes selected event references, observer hosts, Windows record
IDs, accounts, and source addresses with their event/inventory basis. It keeps
original event time distinct from Wazuh processing time, records coverage limits,
and links to the exact case/evaluation manifests. It does not include author
answers. Each changed save creates a new snapshot without overwriting earlier
reports. Saving rechecks the source artifacts; failed validation or writes leave
your draft open.

**View saved report** opens the last saved report in a scrollable, read-only
overlay; unsaved edits are not included. The path is also displayed in the form.
Reopening the same evaluation restores its latest saved assessment and evidence
selection. A new evaluation of the same case has its own reports. Corrupt reports
are not silently restored: the form reports the problem and starts blank without
altering existing files.

Back to cases / Escape prompts before discarding unsaved notes or selection.
Quit (`q` outside text fields, Ctrl+Q, or Quit in the command palette) uses the
same protection, including when a Guide or report overlay is open. Choose
**Keep working** to return and save, or explicitly **Discard draft and quit**.
Cases with no unsaved changes do not prompt. There is no background autosave, and
forced terminal closure can still lose unsaved work. No SIEM case, ticket, message,
account lock, or containment action is created by an escalation recommendation.
Generated reports remain under the Git-ignored `outputs/` directory; review and
sanitize a report before intentionally sharing it as a portfolio artifact.

The command palette's Theme command remains available. Built-in themes use
fallback colors for SimLab-specific controls and headings; switching themes
does not modify evidence, evaluation results, or your assessment draft.

## Environment

Reuse `environments/corp-lab.yaml`:

| System | Address | Relevant role |
| --- | --- | --- |
| WS01 | 10.10.0.101 | Source workstation |
| FS01 | 10.10.0.20 | SMB destination |
| DC01 | 10.10.0.10 | Domain credential validation |

Known domain accounts are Alice, Bob, and Carol in CORP. An account name in a log
identifies the credential used, not necessarily the person initiating activity.

## Evidence timeline

All event times are UTC on 2026-09-14. Each attempt's records retain the existing
documented synthetic millisecond offsets and independent audit-policy gates.

| Attempt times | Activity represented | Evidence |
| --- | --- | --- |
| 09:10:00, 09:10:07, 09:10:19 | WS01 fails authentication as Alice over SMB to FS01 | Three 4776 records on DC01 and three 4625 records on FS01 |
| 09:12:00 | Successful fresh interactive domain logon as Bob on WS01 | 4768 and 4769 on DC01, plus 4624 on WS01 |
| 09:15:00, 09:15:07, 09:15:19 | WS01 fails authentication as Alice, Bob, then Carol over SMB to FS01 | Three 4776 records on DC01 and three 4625 records on FS01 |

This produces 15 Windows records. The earlier activity gives the analyst a
comparison and context. It is not automatically evidence of benign activity.
Bob's earlier interactive success is not evidence of a successful spray or SMB
access after the alert.

The supplied event coverage ends just after 09:15:19. A search beyond that range
must explain that later evidence is unavailable, rather than asserting that no
successful authentication occurred after the suspected spray.

## Wazuh evaluation behavior

The qualifying pattern is three distinct target accounts from the same observed
source within 60 seconds. The existing FS01 4625 and DC01 4776 detection signals
are independent. An investigation may relate their results; it must not imply
that Wazuh itself merged them into one alert.

The pinned rule chains are:

- 4625: stock 60122 → hidden 100100 → spray 100101.
- 4776: stock 60104 → hidden 100110 → spray 100111.

The hidden level-1 rules qualify bad-password NTLM failures and use `no_log`.
The level-10 spray rules correlate different usernames while keeping the
observer and source fixed. For 4625, the source is the event IP; for 4776, it is
the recorded workstation name. Repeated failures against Alice alone do not
satisfy the distinct-account requirement.

The selected detector is the real Wazuh 4.14.7 analysis engine. The bridge runs
inside the existing manager and uses its installed framework's logtest socket.
Its embedded interpreter supplies the installed Wazuh package; the bridge does
not override the package search path with the top-level framework directory.
No API credentials or new exposed ports are needed. It verifies the running
version and both mounted rule files. Framework calls are pinned to this version;
upgrades require renewed compatibility checks.

Each saved alert-producing result identifies its detector, rule ID, processing
mode, actual detection time, and supporting event times. It is labeled as a
rule-test result, rather than being described as a persisted SIEM alert.

For Wazuh replay, the 60-second rule window uses ingestion time. Embedded event
times are not a substitute for that clock. The earlier single-account sequence
and the later spray use separate fresh sessions, which are closed afterward.
Within each session, events are submitted continuously, with a guard against
exceeding 60 seconds of processing. This checks correlation in isolated
historical windows; it is not a full paced replay of the five-minute timeline.

The successful Kerberos events remain investigation context and are not
evaluated by the existing 4625/4776 adapter. Lack of a Wazuh result for them must
not be interpreted as an assessment of that activity.

The isolated manager mounts a test-only copy of the pinned Windows base rules.
Only entry rule 60000 is adapted: its `ossec` category condition is removed and
its decoder identity becomes `json`, because logtest labels the submitted JSON
that way rather than as `windows_eventchannel`. The remaining base rules and
downstream Security rules retain the pinned stock lineage. This mapping is not
verified against a sanitized native agent capture. Do not use the patched mount
for live Windows-agent ingestion; remove it before that separate validation.

## Analyst tasks

- Open the alert and identify source, destination, target accounts, and time span.
- Filter related evidence by event time, account, host, and observed source IP.
- Relate DC credential validation to the file server's failed network logons.
- Compare the earlier Alice-only failures with the multi-account pattern.
- Distinguish Bob's interactive success from the suspected spray activity.
- Record observed facts, a working hypothesis, unavailable evidence, and an
  escalation recommendation with selected event references.

Simulation-only attempt labels, correlation IDs, and scenario descriptions belong
in a separate author/verification view, not the initial investigation evidence.

## Implemented scope

- Reproducible fifteen-event evidence with provenance and coverage boundaries.
- Actual Wazuh evaluation in two isolated sessions, saved separately from evidence.
- Alert, Evidence, Context, and Assessment tabs with filters, pivots, selection,
  keyboard navigation, and focused guidance.
- Separate assessment/report snapshots linked to the exact case and evaluation;
  reopening restores the latest verified saved assessment.
- Explicit TUI preparation with retryable failures and manual Docker lifecycle.
- Unsaved-draft exit guards and a retired legacy generation/export workflow.

Real-engine preparation and the investigation/report flow have previously been
user-validated. Automated tests mock the Wazuh transport and cover behavior,
failure handling, and artifact integrity; they do not replace real-engine
validation. Final checks must include the latest TUI changes.

The acceptance checkpoint remains one complete investigation. Additional
scenarios, reporting refinements, a full SIEM dashboard, and broad frameworks
are deferred.

The Docker vulnerability-feed storage cleanup remains deferred. Preparation
uses the existing manager and does not start/stop containers or modify their
configuration.

References: [Wazuh rule testing and session behavior](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
and [the pinned framework bridge](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/wazuh/core/logtest.py).

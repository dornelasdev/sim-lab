# SimLab

A SOC L1 practice lab with reproducible simulated Windows telemetry and real
Wazuh rule-test evaluation. Practice alert triage, evidence correlation, and
assessment without running a complete Active Directory environment.

## Setup

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/), and Docker Desktop for
preparing a case. Reviewing saved investigations does not require Docker.

```bash
uv sync
docker compose -f integrations/wazuh/compose.yaml up -d
uv run simlab tui
```

## Investigation workflow

Choose **Start investigation → Prepare case → Open investigation**.

The first exercise combines repeated single-account failures, a successful
interactive logon, and a suspected NTLM password spray. Preparation supplies
15 Windows events and collects two independent matches from the real Wazuh
4.14.7 engine. Generation and submission happen behind the interface; no manual
export or log pasting is needed.

Work through **Alert → Evidence → Context → Assessment**:

- Review each Wazuh match and its supporting events.
- Filter evidence by time, account, observer host, source IP, or event ID.
- Use inventory context and Windows event-ID notes to guide investigative pivots.
- Select evidence and save your reasoning as a separate assessment and report.

Choose **Open prepared investigation** to resume without preparing again.
Saved evidence and engine results are read-only. Reopening the same evaluation
restores its latest saved assessment; changed saves retain earlier snapshots.

For command-line preparation:

```bash
uv run simlab prepare password-spray
```

Docker startup/shutdown stays manual. When finished evaluating:

```bash
docker compose -f integrations/wazuh/compose.yaml down
```

See [first investigation](docs/first-investigation.md) for the timeline,
expected results, filtering, runtime boundaries, and reporting behavior.

## Fidelity and limits

Windows events are simulated, not captured endpoint evidence. Values are
classified as documented, derived, synthetic, or unavailable. Host audit policies
are lab monitoring profiles, not Windows defaults.

Wazuh results come from its real rule-test engine, not persisted dashboard
alerts. Only the 12 NTLM failure records are evaluated; the three successful
Kerberos/logon records remain context. The test-only JSON decoder adaptation is
not suitable for live Windows-agent ingestion. There is no local-detector
fallback when evaluation fails.

Saved recommendations do not create real tickets or perform endpoint response.
Unavailable evidence is explicit; the exercise does not supply a verified
normal-activity baseline or prove compromise.

## Layout

```text
environments/   Lab inventory and audit policies
routes/         Authentication inputs used by the first case
src/simlab/     Case preparation, Wazuh evaluation, investigation UI, reports
integrations/   Pinned Wazuh manager, rules, and evaluation bridge
docs/           Investigation walkthrough, event reference, and rework scope
tests/          Behavior, integrity, UI, and fidelity checks
outputs/        Saved cases, evaluations, and reports (Git-ignored)
```

The active CLI exposes only `tui` and `prepare password-spray`.
Failed-Kerberos generator coverage remains under `tests/fixtures/`; it is not
another selectable investigation.

Cases, evaluations, and analyst assessments are generated locally, not shipped
with the project. A fresh checkout starts with no saved investigations. Prepare
the first case through the TUI or CLI. `outputs/` and `local-notes/` are Git-ignored;
personal exercise notes and saved answers are not required to run the lab.

## Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest
```

## Status

The first end-to-end SOC investigation is implemented. Final validation and
PR review precede v0.1; see [rework scope](docs/soc-rework.md).

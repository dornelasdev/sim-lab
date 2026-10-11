# SimLab

A SOC L1 practice lab using reproducible simulated telemetry and real security
tools, with Wazuh as the first integration.

## Scope

Practice alert triage, event searches, evidence correlation, and escalation
notes without running a complete Active Directory environment. SimLab supplies
the scenario data; Wazuh supplies the rule evaluation and, once deployed, the
analyst workspace.

The current integration exports telemetry for a temporary Wazuh manager and
`wazuh-logtest`. Dashboard ingestion and investigation are the next milestone.
See the [password-spray exercise](docs/soc-l1-password-spray.md) for the available
practice workflow and its limits.

## Current baseline

- Corporate domain with a domain controller, workstation, and SMB file server.
- Fresh Kerberos interactive logon producing events 4768, 4769, and 4624.
- Failed Kerberos interactive logon producing 4771 on DC01 and 4625 on WS01.
- NTLM password spray over SMB producing event 4776 on the domain controller
  and 4625 on the file server.
- Versioned Windows Security event schemas and native Event XML serialization.
- Content-addressed JSONL and XML bundles with reproducibility metadata.
- Reference NTLM password-spray detection over independent 4776 and 4625 signals.
- Wazuh EventChannel replay exports and native password-spray rules.
- Host audit policies controlling which activity becomes observable.
- Scenario expectations validating generated event counts and locations.

## Fidelity

Generated values are classified as documented, derived, synthetic, or
unavailable. Timestamps, record IDs, client ports, and simulation correlation
identifiers are deterministic. The included audit policies are SimLab monitoring
profiles, not Windows defaults.

Real systems may later supply sanitized reference telemetry for validation; they
are not permanent runtime dependencies.

The [failed Kerberos sign-in](docs/kerberos-logon-failure.md) documents its audit
requirements, field assumptions, and current detection limits.

## Project layout

```text
environments/   Shared lab topology and audit policies
routes/         Declarative security scenarios
src/simlab/     Validation, telemetry generation, detection, and artifacts
detections/     Optional SimLab reference detection profiles
integrations/   Wazuh rules and replay runtime configuration
docs/           SOC exercises, tool workflows, and fidelity notes
tests/          Behavioral and schema tests
```

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Generate authentication artifacts

```bash
uv run simlab generate authentication \
  --environment environments/corp-lab.yaml \
  --route routes/ad-authentication/password-spray.yaml
```

Each content-addressed telemetry bundle under `outputs/<scenario-id>/` contains:

```text
manifest.json   Scenario, environment, profile, policy, and artifact context
events.jsonl    Self-contained event records with SimLab provenance
xml/            Matching native Windows Event XML files
SHA256SUMS      Exact SHA-256 checksums for every file above
```

The manifest's source-host aliases are a derived environment snapshot used to
resolve hostname and IP observations. They are analysis context, not event
evidence.

## Guided terminal workflow

```bash
uv run simlab tui
```

Start a new simulation or open existing telemetry. The main path is:

**Environment → Route → Acquire → Inspect → Wazuh export**.

Reference analysis is optional and remains accessible from Inspect or the
sidebar. Export requires a verified telemetry bundle; no SimLab detection result
is required. Export prepares files for the separate Wazuh replay workflow.

Each page explains the relevant security context. Scenario expectations remain
separate from verified telemetry and detection findings. Existing telemetry is
inspectable from its recorded manifest even when its local environment or route
definition has changed or is unavailable.

Open the stage-aware Guide with its visible control or the `g` key. The Guide is
read-only, and `g` or Escape closes it without changing workflow state.

Environment and route choices become read-only provenance after telemetry is
acquired. Starting a new simulation resets only the TUI workflow. Detection
profiles similarly lock to their result; a new analysis can reuse the same
telemetry without modifying previous artifacts.

The interface displays the equivalent CLI commands for every available stage.
Docker startup and `wazuh-logtest` remain in the separate workflow documented in
[docs/wazuh-replay.md](docs/wazuh-replay.md).

## Export to Wazuh

```bash
uv run simlab export wazuh \
  --telemetry outputs/<scenario-id>/<telemetry-id>
```

The export contains Wazuh EventChannel input plus separate provenance linking
every replay line to its SimLab event. A temporary manager-only Wazuh 4.14.7
workflow and its positive and negative validation cases are documented in
[docs/wazuh-replay.md](docs/wazuh-replay.md).

## Optional reference analysis

SimLab's reference detector is a supporting check. Its findings are separate
from alerts produced by Wazuh's rules.

```bash
uv run simlab detect authentication \
  --telemetry outputs/<scenario-id>/<telemetry-id> \
  --profile detections/authentication/password-spray.yaml
```

Analysis is stored separately under
`outputs/analyses/<source-telemetry-id>/<analysis-id>/`. Its `findings.jsonl`
contains analyst-facing hypotheses; `manifest.json` records the exact telemetry
bundle and detection profile. Its `SHA256SUMS` covers both files.

CLI and TUI detection views explain the reference profile's coverage. Kerberos
activity is not assessed by this NTLM profile; zero findings do not imply benign
activity. Coverage messaging is derived from event evidence, not stored as a new
analysis schema field.

Verify the exact stored files from inside either bundle:

```bash
shasum -a 256 -c SHA256SUMS
```

Manifest fields ending in `canonical_sha256` identify normalized validated
definitions. They are semantic provenance digests, not raw file checksums.

## Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest
```

## Status

Version 0.1 is under incremental development through small, reviewable routes
and implementation sections. The immediate goal is one complete Wazuh
password-spray investigation, followed by additional SOC L1 exercises.

# SimLab

A lightweight, data-centered cybersecurity lab for deterministic scenarios and
internally consistent security telemetry.

## Scope

SimLab models security-relevant infrastructure and activity without requiring
the complete environment to run continuously. Initial development focuses on
Active Directory authentication and Windows Security events, with later room
for SOC operations, adversary emulation, cryptography, and red-team scenarios.

## Current baseline

- Corporate domain with a domain controller, workstation, and SMB file server.
- Fresh Kerberos interactive logon producing events 4768, 4769, and 4624.
- NTLM password spray over SMB producing event 4776 on the domain controller
  and 4625 on the file server.
- Versioned Windows Security event schemas and native Event XML serialization.
- Content-addressed JSONL and XML bundles with reproducibility metadata.
- Reference password-spray detection over independent 4776 and 4625 signals.
- Host audit policies controlling which activity becomes observable.
- Scenario expectations validating generated event counts and locations.

## Fidelity

Generated values are classified as documented, derived, synthetic, or
unavailable. Timestamps, record IDs, client ports, and simulation correlation
identifiers are deterministic. The included audit policies are SimLab monitoring
profiles, not Windows defaults.

Real systems may later supply sanitized reference telemetry for validation; they
are not permanent runtime dependencies.

## Project layout

```text
environments/   Shared lab topology and audit policies
routes/         Declarative security scenarios
src/simlab/     Validation, telemetry generation, detection, and artifacts
detections/     Versioned reference detection profiles
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
  --route routes/ad-authentication/normal.yaml
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

## Analyze authentication artifacts

```bash
uv run simlab detect authentication \
  --telemetry outputs/<scenario-id>/<telemetry-id> \
  --profile detections/authentication/password-spray.yaml
```

Analysis is stored separately under
`outputs/analyses/<source-telemetry-id>/<analysis-id>/`. Its `findings.jsonl`
contains analyst-facing hypotheses; `manifest.json` records the exact telemetry
bundle and detection profile. Its `SHA256SUMS` covers both files.

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
and implementation sections.

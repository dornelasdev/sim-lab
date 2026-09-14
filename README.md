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
src/simlab/     Validation and telemetry generation
tests/          Behavioral and schema tests
```

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest
```

## Status

Version 0.1 is under incremental development through small, reviewable routes
and implementation sections.

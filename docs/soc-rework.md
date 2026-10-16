# SOC investigation rework

## Intended experience

Start one exercise, open an alert, investigate related evidence, and save an
assessment or escalation. The analyst should spend the session working with
timestamps, accounts, IP addresses, workstations, domain controllers, and
authentication evidence.

Generation, storage, and platform adaptation support the exercise behind the
interface. They should not require a sequence of manual preparation stages
before each investigation.

## First exercise

A suspected password spray is the starting use case. The existing corporate
environment and three authentication routes supply the reproducible timeline,
background activity, and investigative evidence.

The [first investigation](first-investigation.md) defines the timeline, analyst
tasks, runtime boundaries, and reporting behavior. The complete flow is
implemented: prepare evidence, evaluate with real Wazuh rules, investigate,
save an assessment, and reopen the exact case/evaluation later.

The main menu exposes starting or resuming an investigation and its Guide.
Preparation opens that run's saved evaluation. Docker startup/shutdown remain
manual; there is no fallback detector. Saved cases can be reviewed offline.

No real escalation or response actions are performed by the reporting flow.
Report refinements, including classification versus disposition, remain deferred
until after PR merge.

Acceptance criteria for that exercise:

- An alert identifies its trigger time, detection origin, and supporting events.
- Evidence can be filtered by time and relevant accounts, hosts, or IPs.
- The analyst can distinguish observed facts from simulation ground truth and
  hypotheses; unavailable evidence remains explicitly unavailable.
- Assessment and escalation can be written in the same investigation flow and
  saved with the relevant evidence references.
- The exercise has a reproducible outcome and documented fidelity limitations.

Real Wazuh rule-test evaluation is the selected alert source. It is identified
as rule testing, not persisted dashboard alerts. There is no local-detector
fallback when the manager or evaluation fails.

## Repository boundary

The repository contains reusable code, environment/route definitions, Wazuh
integration files, tests, and investigation documentation. Personal exercise
notes, generated evidence, actual evaluation runs, and authored assessments are
local artifacts, not prerequisites or shipped examples.

A fresh checkout has no prepared cases or saved assessments. Preparation creates
`outputs/cases/` and `outputs/evaluations/`; saving an assessment creates
`outputs/reports/`. These outputs and `local-notes/` are Git-ignored. Local backups
are not another runnable installation and are not read by the application.

The previous generation/reference-analysis/export CLI and TUI are retired;
active commands are `simlab tui` and `simlab prepare password-spray`.
Shared environment definitions, Windows schemas, provenance, generation, and
real Wazuh evaluation remain dependencies of the investigation. The unused
failed-Kerberos route is now an unchanged test fixture, preserving coverage
without presenting another exercise. Docker configuration and runtime state
are unchanged.

## Boundaries

- One well-constructed investigation first; no general case-management framework.
- A compact analyst interface; no complete SIEM dashboard required.
- No continuously running simulated AD machines.
- No deletion of the repository or unrelated local work.
- No claim of live endpoint or EDR response experience from replay alone.

The existing Docker vulnerability-feed storage issue is separate follow-up work.
This preparation does not change the running manager, Docker images, or volumes.

## Pre-merge validation

- Run formatting, lint, and the active tests, including the latest keyboard
  shortcuts and dropdown behavior.
- With no local outputs, check that the saved-case picker is empty and Start
  investigation still offers preparation. With the existing manager running,
  prepare the case and confirm 15 events and two independent spray matches.
- Review both matches, filter/select evidence, save an assessment, return to the
  main menu, and reopen that evaluation with its notes and selections restored.
- Check Guide/report overlays and the unsaved-draft quit guard. Preparing again
  must not overwrite earlier cases or assessments.
- Review the Git changes before staging, including deletions of retired files.
  Ignore rules do not remove files that were previously tracked or staged.

The user runs validation and Git/PR commands. The rework can be reviewed and
merged once those checks pass. New exercises, report refinements, and additional
TUI polish are not requirements for this baseline.

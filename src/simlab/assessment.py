"""Analyst-authored assessment snapshots, separate from case and engine evidence."""

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StringConstraints

from simlab.definition import Definition, Identifier
from simlab.investigation import evidence_account, evidence_source_ip
from simlab.storage import (
    content_address,
    pretty_json,
    sha256sums,
    verify_directory,
    write_verified_directory,
)
from simlab.wazuh_evaluation import SavedInvestigation, load_saved_investigation

Disposition = Literal[
    "escalate", "needs_evidence", "close_benign", "close_false_positive"
]
DISPOSITION_LABELS: dict[str, str] = {
    "escalate": "Escalate for further investigation",
    "needs_evidence": "Pending: more evidence needed",
    "close_benign": "Close: explained benign activity",
    "close_false_positive": "Close: false positive",
}
NOTE_LABELS = {
    "observed_facts": "Observed facts",
    "working_hypothesis": "Working hypothesis",
    "evidence_gaps": "Evidence gaps / uncertainty",
    "decision_rationale": "Decision rationale",
    "next_steps": "Recommended next steps",
}
NoteText = Annotated[str, StringConstraints(min_length=1, max_length=12000)]


class AssessmentNotes(Definition):
    """Reasoning authored by the analyst, not an automated verdict."""

    disposition: Disposition
    observed_facts: NoteText
    working_hypothesis: NoteText
    evidence_gaps: NoteText
    decision_rationale: NoteText
    next_steps: NoteText


class InvestigationAssessment(AssessmentNotes):
    """One immutable saved assessment of an exact case and Wazuh evaluation."""

    schema_version: Literal[1] = 1
    kind: Literal["analyst_assessment"] = "analyst_assessment"
    assessment_id: Identifier
    case_id: Identifier
    evaluation_id: Identifier
    case_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: Literal["whole_case_and_evaluation"] = "whole_case_and_evaluation"
    created_at: AwareDatetime
    selected_event_ids: tuple[Identifier, ...] = Field(min_length=1)


@dataclass(frozen=True)
class SavedAssessment:
    """Location and validated contents of a saved report snapshot."""

    path: Path
    assessment: InvestigationAssessment


def save_assessment(
    investigation: SavedInvestigation,
    output_root: str | Path,
    notes: AssessmentNotes,
    selected_event_ids: set[str],
    *,
    created_at: datetime | None = None,
) -> SavedAssessment:
    """Save a new snapshot without changing evidence or previous reports."""

    # Recheck evidence at the save boundary, not just when the screen was opened.
    verified = load_saved_investigation(
        investigation.case.path, investigation.evaluation_path
    )
    known = {item.event_instance_id for item in verified.case.evidence}
    if not selected_event_ids or not selected_event_ids <= known:
        raise ValueError("Select at least one event from this case as evidence.")
    saved_at = created_at if created_at is not None else datetime.now(UTC)
    if saved_at.tzinfo is None or saved_at.utcoffset() is None:
        raise ValueError("Assessment save time must include a timezone.")
    metadata = {
        **notes.model_dump(),
        "schema_version": 1,
        "kind": "analyst_assessment",
        "case_id": verified.case.manifest.case_id,
        "evaluation_id": verified.evaluation_path.name,
        **_manifest_hashes(verified),
        "scope": "whole_case_and_evaluation",
        "created_at": saved_at.astimezone(UTC),
        "selected_event_ids": tuple(
            item.event_instance_id
            for item in verified.case.evidence
            if item.event_instance_id in selected_event_ids
        ),
    }
    # The report doesn't contain its own ID, avoiding a self-referential hash.
    provisional = InvestigationAssessment(
        assessment_id="assessment-pending", **metadata
    )
    markdown = render_assessment_report(provisional, verified).encode("utf-8")
    identifier = content_address("assessment", metadata, {"report.md": markdown})
    assessment = InvestigationAssessment(assessment_id=identifier, **metadata)
    path = _report_root(output_root, verified) / identifier
    files = {"assessment.json": pretty_json(assessment), "report.md": markdown}
    write_verified_directory(path, {**files, "SHA256SUMS": sha256sums(files)})
    return SavedAssessment(path, assessment)


def load_assessment(
    path: str | Path, investigation: SavedInvestigation
) -> SavedAssessment:
    """Verify report integrity, evidence references, and exact evaluation scope."""

    investigation = load_saved_investigation(
        investigation.case.path, investigation.evaluation_path
    )
    root = Path(path)
    files = {
        name: (root / name).read_bytes() for name in ("assessment.json", "report.md")
    }
    assessment = InvestigationAssessment.model_validate_json(files["assessment.json"])
    identifier = content_address(
        "assessment",
        assessment.model_dump(exclude={"assessment_id"}),
        {"report.md": files["report.md"]},
    )
    if root.name != assessment.assessment_id or identifier != root.name:
        raise ValueError("Assessment identity does not match its saved report.")
    verify_directory(root, {**files, "SHA256SUMS": sha256sums(files)})
    hashes = _manifest_hashes(investigation)
    if (
        assessment.case_id != investigation.case.manifest.case_id
        or assessment.evaluation_id != investigation.evaluation_path.name
        or assessment.case_manifest_sha256 != hashes["case_manifest_sha256"]
        or assessment.evaluation_manifest_sha256 != hashes["evaluation_manifest_sha256"]
    ):
        raise ValueError("Assessment belongs to a different case or evaluation.")
    selected = set(assessment.selected_event_ids)
    known = {item.event_instance_id for item in investigation.case.evidence}
    if len(selected) != len(assessment.selected_event_ids) or not selected <= known:
        raise ValueError("Assessment has duplicate or unknown evidence references.")
    expected = render_assessment_report(assessment, investigation).encode("utf-8")
    if files["report.md"] != expected:
        raise ValueError("Readable report does not match its assessment and evidence.")
    return SavedAssessment(root, assessment)


def load_latest_assessment(
    investigation: SavedInvestigation, output_root: str | Path
) -> SavedAssessment | None:
    """Restore the latest verified snapshot for this evaluation, if one exists."""

    reports = [
        load_assessment(path, investigation)
        for path in _report_root(output_root, investigation).glob("assessment-*")
    ]
    return max(
        reports,
        key=lambda saved: (saved.assessment.created_at, saved.assessment.assessment_id),
        default=None,
    )


def render_assessment_report(
    assessment: InvestigationAssessment, investigation: SavedInvestigation
) -> str:
    """Render analyst reasoning plus traceable Windows and Wazuh context."""

    manifest = investigation.case.manifest
    lines = [
        f"# Analyst assessment: {manifest.title}",
        "",
        f"Saved (UTC): {assessment.created_at.astimezone(UTC).isoformat()}",
        f"Case: `{assessment.case_id}`",
        f"Evaluation: `{assessment.evaluation_id}`",
        "Scope: the whole case and this evaluation, not just the active UI match.",
        f"Environment: `{manifest.environment_id}`",
        "",
        f"Decision: {DISPOSITION_LABELS[assessment.disposition]}",
        "This is an analyst recommendation, not an automated verdict or a "
        "performed escalation/containment action.",
        "",
    ]
    for field, label in NOTE_LABELS.items():
        lines.extend((f"## {label}", "", getattr(assessment, field), ""))
    lines.extend(
        (
            "## Detection and coverage context",
            "",
            f"Wazuh {investigation.manager_version}; saved rule-test results, "
            "not persisted SIEM alerts. The engine matches below are independent; "
            "any relationship between them is analyst reasoning.",
            f"Supplied event times: {manifest.evidence_started_at.isoformat()} "
            f"to {manifest.evidence_ended_at.isoformat()}.",
            "Correlation used manager processing time, not original event time.",
            "",
        )
    )
    for alert in investigation.alerts:
        lines.extend(
            (
                f"- Wazuh rule {alert.rule_id}, level {alert.level}: "
                f"{alert.description}",
                f"  - Actual detection time: {alert.detected_at.isoformat()}",
                f"  - Supporting event times: {alert.evidence_started_at.isoformat()} "
                f"to {alert.evidence_ended_at.isoformat()}",
                "  - Engine evidence references: "
                + ", ".join(f"`{ref}`" for ref in alert.supporting_event_ids),
            )
        )
    lines.extend(("", "Coverage limitations:", ""))
    lines.extend(f"- {limitation}" for limitation in manifest.limitations)
    lines.extend(
        (
            "- Successful Kerberos context was not evaluated by the failure adapter.",
            "- Inventory-derived addresses are context, not direct IP observations.",
            "",
            "## Selected evidence",
            "",
            "| Event time (UTC) | Observer | Windows ID | Record ID | Account | "
            "Source IP / basis | Evidence reference |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        )
    )
    selected = set(assessment.selected_event_ids)
    for item in investigation.case.evidence:
        if item.event_instance_id not in selected:
            continue
        source, derived = evidence_source_ip(investigation.case, item)
        source_context = (
            f"{source} ({'inventory-derived' if derived else 'event field'})"
            if source
            else "Unavailable"
        )
        cells = (
            item.event.occurred_at.astimezone(UTC).isoformat(),
            item.event.computer,
            str(item.event.event_id),
            str(item.event.record_id),
            evidence_account(item),
            source_context,
            item.event_instance_id,
        )
        lines.append("| " + " | ".join(_table_cell(value) for value in cells) + " |")
    lines.extend(
        (
            "",
            "## Artifact linkage",
            "",
            f"Case manifest SHA-256: `{assessment.case_manifest_sha256}`",
            f"Evaluation manifest SHA-256: `{assessment.evaluation_manifest_sha256}`",
            "Selected references resolve to the original case's events.jsonl; "
            "Windows fields and simulation provenance remain in that read-only case.",
            "",
        )
    )
    return "\n".join(lines)


def _report_root(output_root: str | Path, investigation: SavedInvestigation) -> Path:
    return (
        Path(output_root)
        / "reports"
        / investigation.case.manifest.case_id
        / investigation.evaluation_path.name
    )


def _manifest_hashes(investigation: SavedInvestigation) -> dict[str, str]:
    return {
        "case_manifest_sha256": sha256(
            (investigation.case.path / "manifest.json").read_bytes()
        ).hexdigest(),
        "evaluation_manifest_sha256": sha256(
            (investigation.evaluation_path / "manifest.json").read_bytes()
        ).hexdigest(),
    }


def _table_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ")

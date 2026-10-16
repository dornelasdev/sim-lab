from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from simlab.assessment import (
    AssessmentNotes,
    load_assessment,
    load_latest_assessment,
    save_assessment,
)
from simlab.storage import content_address, pretty_json, sha256sums
from simlab.wazuh_evaluation import load_saved_investigation
from tests.test_investigation_tui import prepared as prepared

SAVED_AT = datetime(2026, 10, 12, 13, 0, tzinfo=UTC)


def example_notes(**changes):
    return AssessmentNotes(
        **{
            "disposition": "escalate",
            "observed_facts": "Failed logons appear on DC01 and FS01.",
            "working_hypothesis": "Multi-account attempts warrant investigation.",
            "evidence_gaps": "Later activity and the initiating process are missing.",
            "decision_rationale": "The source and time span need corroboration.",
            "next_steps": "Request later authentication and source endpoint logs.",
            **changes,
        }
    )


def source_files(investigation):
    return {
        path: path.read_bytes()
        for root in (investigation.case.path, investigation.evaluation_path)
        for path in root.rglob("*")
        if path.is_file()
    }


def test_assessment_save_links_evidence_and_exports_readable_report(prepared, tmp_path):
    investigation = load_saved_investigation(
        prepared.case.path, prepared.evaluation_path
    )
    original = source_files(investigation)
    assert load_latest_assessment(investigation, tmp_path) is None
    references = {
        investigation.alerts[0].supporting_event_ids[0],
        investigation.alerts[1].supporting_event_ids[0],
    }
    saved = save_assessment(
        investigation, tmp_path, example_notes(), references, created_at=SAVED_AT
    )
    assert load_assessment(saved.path, investigation) == saved
    assert load_latest_assessment(investigation, tmp_path) == saved
    assert saved.path.parent == (
        tmp_path
        / "reports"
        / investigation.case.manifest.case_id
        / investigation.evaluation_path.name
    )
    assert saved.assessment.scope == "whole_case_and_evaluation"
    assert set(saved.assessment.selected_event_ids) == references
    report = (saved.path / "report.md").read_text()
    assert "4776" in report and "4625" in report
    assert "100111" in report and "100101" in report
    assert "inventory-derived" in report and "event field" in report
    assert "not persisted SIEM alerts" in report
    assert "2026-09-14" in report and "2026-10-12" in report
    assert example_notes().evidence_gaps in report
    assert all(reference in report for reference in references)
    assert "author-context" not in report
    assert "source_attempt_id" not in report
    assert str(tmp_path) not in report
    assert source_files(investigation) == original


def test_assessment_edits_create_new_snapshots_without_overwriting(prepared, tmp_path):
    investigation = load_saved_investigation(
        prepared.case.path, prepared.evaluation_path
    )
    references = {investigation.case.evidence[0].event_instance_id}
    first = save_assessment(
        investigation, tmp_path, example_notes(), references, created_at=SAVED_AT
    )
    original = {path: path.read_bytes() for path in first.path.iterdir()}
    second = save_assessment(
        investigation,
        tmp_path,
        example_notes(disposition="needs_evidence", next_steps="Request more logs."),
        references,
        created_at=SAVED_AT + timedelta(minutes=1),
    )
    assert first.path != second.path
    assert load_latest_assessment(investigation, tmp_path) == second
    assert {path: path.read_bytes() for path in first.path.iterdir()} == original
    identical = save_assessment(
        investigation, tmp_path, example_notes(), references, created_at=SAVED_AT
    )
    assert identical == first


@pytest.mark.parametrize(
    "changes",
    [
        {"observed_facts": " "},
        {"evidence_gaps": ""},
        {"working_hypothesis": "x" * 12001},
        {"disposition": "confirmed_compromise"},
    ],
)
def test_assessment_requires_reasoning_and_explicit_supported_decision(changes):
    with pytest.raises(ValidationError):
        example_notes(**changes)


@pytest.mark.parametrize("references", [set(), {"evidence-unknown"}])
def test_assessment_rejects_missing_or_unrelated_evidence(
    prepared, tmp_path, references
):
    investigation = load_saved_investigation(
        prepared.case.path, prepared.evaluation_path
    )
    with pytest.raises(ValueError, match="Select at least one"):
        save_assessment(investigation, tmp_path, example_notes(), references)
    assert not (tmp_path / "reports").exists()


def test_assessment_rejects_naive_save_time(prepared, tmp_path):
    investigation = load_saved_investigation(
        prepared.case.path, prepared.evaluation_path
    )
    with pytest.raises(ValueError, match="timezone"):
        save_assessment(
            investigation,
            tmp_path,
            example_notes(),
            {investigation.case.evidence[0].event_instance_id},
            created_at=datetime(2026, 10, 12, 13, 0),
        )


@pytest.mark.parametrize("artifact", ["report.md", "assessment.json", "SHA256SUMS"])
def test_assessment_rejects_corruption_instead_of_restoring_it(
    prepared, tmp_path, artifact
):
    investigation = load_saved_investigation(
        prepared.case.path, prepared.evaluation_path
    )
    saved = save_assessment(
        investigation,
        tmp_path,
        example_notes(),
        {investigation.case.evidence[0].event_instance_id},
        created_at=SAVED_AT,
    )
    (saved.path / artifact).write_text("invalid\n")
    with pytest.raises((ValueError, OSError)):
        load_assessment(saved.path, investigation)
    with pytest.raises((ValueError, OSError)):
        load_latest_assessment(investigation, tmp_path)


def test_assessment_rechecks_case_integrity_when_saving_or_loading(prepared, tmp_path):
    investigation = load_saved_investigation(
        prepared.case.path, prepared.evaluation_path
    )
    references = {investigation.case.evidence[0].event_instance_id}
    saved = save_assessment(
        investigation, tmp_path, example_notes(), references, created_at=SAVED_AT
    )
    (investigation.case.path / "events.jsonl").write_text("[]\n")
    with pytest.raises((ValueError, OSError)):
        save_assessment(investigation, tmp_path, example_notes(), references)
    with pytest.raises((ValueError, OSError)):
        load_assessment(saved.path, investigation)


def test_assessment_for_other_evaluation_is_rejected(prepared, tmp_path):
    investigation = load_saved_investigation(
        prepared.case.path, prepared.evaluation_path
    )
    references = {investigation.case.evidence[0].event_instance_id}
    saved = save_assessment(
        investigation, tmp_path, example_notes(), references, created_at=SAVED_AT
    )
    # Re-sign the report with a different evaluation ID to exercise the scope boundary,
    # rather than merely failing its checksum check.
    metadata = saved.assessment.model_dump(exclude={"assessment_id"})
    metadata["evaluation_id"] = "evaluation-other"
    report = (saved.path / "report.md").read_bytes()
    identifier = content_address("assessment", metadata, {"report.md": report})
    changed = saved.assessment.model_copy(
        update={"assessment_id": identifier, "evaluation_id": "evaluation-other"}
    )
    path = saved.path.parent / identifier
    path.mkdir()
    files = {"assessment.json": pretty_json(changed), "report.md": report}
    for name, content in {**files, "SHA256SUMS": sha256sums(files)}.items():
        (path / name).write_bytes(content)
    with pytest.raises(ValueError, match="different case or evaluation"):
        load_assessment(path, investigation)

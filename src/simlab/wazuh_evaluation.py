"""Actual Wazuh rule-test results for the first prepared investigation."""

import json
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from pydantic import AwareDatetime, Field

from simlab.definition import Definition, Identifier
from simlab.investigation import (
    InvestigationCase,
    InvestigationEvidence,
    failure_evaluation_windows,
    load_investigation_case,
    prepare_password_spray_evidence,
)
from simlab.storage import (
    canonical_json,
    content_address,
    pretty_json,
    sha256sums,
    verify_directory,
    write_verified_directory,
)
from simlab.wazuh import WAZUH_MANAGER_VERSION, to_wazuh_event


class WazuhRuleTestResult(Definition):
    """One actual engine result, with its host-side evidence reference."""

    event_instance_id: Identifier
    processed_at: AwareDatetime
    would_alert: bool
    output: dict[str, Any]


class _BridgeResponse(Definition):
    """Validate the structured boundary returned by the container-side bridge."""

    manager_version: Literal["4.14.7"]
    results: tuple[WazuhRuleTestResult, ...]


class InvestigationAlert(Definition):
    """An alert-producing rule-test match, not a persisted SIEM alert."""

    detection_origin: Literal["wazuh"] = "wazuh"
    processing_mode: Literal["rule_test"] = "rule_test"
    rule_id: str
    level: int = Field(ge=0)
    description: str
    detected_at: AwareDatetime
    evidence_started_at: AwareDatetime
    evidence_ended_at: AwareDatetime
    triggering_event_id: Identifier
    supporting_event_ids: tuple[Identifier, ...]
    evidence_basis: Literal["engine_full_log_and_previous_output"] = (
        "engine_full_log_and_previous_output"
    )
    mitre_attack_ids: tuple[str, ...] = ()


class WazuhEvaluationWindow(Definition):
    """A bounded historical sequence evaluated in its own fresh session."""

    window_id: str
    evidence_started_at: AwareDatetime
    evidence_ended_at: AwareDatetime
    results: tuple[WazuhRuleTestResult, ...]


@dataclass(frozen=True)
class PreparedInvestigation:
    """Prepared evidence and saved real-engine evaluation for the next UI slice."""

    case: InvestigationCase
    evaluation_path: Path
    alerts: tuple[InvestigationAlert, ...]


@dataclass(frozen=True)
class SavedInvestigation:
    """Integrity-checked case and engine results, usable without Docker."""

    case: InvestigationCase
    evaluation_path: Path
    alerts: tuple[InvestigationAlert, ...]
    windows: tuple[WazuhEvaluationWindow, ...]
    manager_version: str


def load_saved_investigation(
    case_path: str | Path, evaluation_path: str | Path
) -> SavedInvestigation:
    """Check saved artifact identities and every engine-to-evidence reference."""

    case = load_investigation_case(case_path)
    root = Path(evaluation_path)
    files = {
        name: (root / name).read_bytes()
        for name in ("manifest.json", "results.json", "alerts.json")
    }
    manifest = json.loads(files["manifest.json"])
    if not isinstance(manifest, dict):
        raise ValueError("evaluation manifest must be an object")
    metadata = {key: value for key, value in manifest.items() if key != "evaluation_id"}
    content = {name: data for name, data in files.items() if name != "manifest.json"}
    if (
        root.name != manifest.get("evaluation_id")
        or content_address("evaluation", metadata, content) != root.name
    ):
        raise ValueError("evaluation identity does not match the saved results")
    verify_directory(root, {**files, "SHA256SUMS": sha256sums(files)})
    if (
        manifest.get("case_id") != case.manifest.case_id
        or root.parent.name != case.manifest.case_id
    ):
        raise ValueError("evaluation belongs to a different case")
    if (
        manifest.get("case_manifest_sha256")
        != sha256((case.path / "manifest.json").read_bytes()).hexdigest()
    ):
        raise ValueError("evaluation does not refer to this exact case manifest")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("detection_origin") != "wazuh"
        or manifest.get("processing_mode") != "rule_test"
        or manifest.get("manager_version") != WAZUH_MANAGER_VERSION
        or manifest.get("correlation_time_basis") != "manager_ingestion_time"
    ):
        raise ValueError("unsupported evaluation origin, version, or processing mode")
    windows = tuple(
        WazuhEvaluationWindow.model_validate(item)
        for item in json.loads(files["results.json"])
    )
    alerts = tuple(
        InvestigationAlert.model_validate(item)
        for item in json.loads(files["alerts.json"])
    )
    evidence_windows = failure_evaluation_windows(case)
    if len(windows) != len(evidence_windows):
        raise ValueError("evaluation window count does not match the case")
    reconstructed = []
    for window, evidence in zip(windows, evidence_windows, strict=True):
        if (
            tuple(result.event_instance_id for result in window.results)
            != tuple(item.event_instance_id for item in evidence)
            or window.evidence_started_at != evidence[0].event.occurred_at
            or window.evidence_ended_at != evidence[-1].event.occurred_at
        ):
            raise ValueError("evaluation window does not match its case evidence")
        for result, item in zip(window.results, evidence, strict=True):
            if json.loads(result.output.get("full_log", "null")) != to_wazuh_event(
                item.event
            ):
                raise ValueError("saved Wazuh output does not match its evidence")
        reconstructed.extend(_alerts_from_results(evidence, window.results))
    evaluated_count = sum(len(window.results) for window in windows)
    if (
        alerts != tuple(reconstructed)
        or len(alerts) != manifest.get("alert_count")
        or evaluated_count != manifest.get("evaluated_event_count")
        or len(case.evidence) - evaluated_count
        != manifest.get("context_only_event_count")
    ):
        raise ValueError(
            "evaluation alerts or counts disagree with the saved engine results"
        )
    return SavedInvestigation(case, root, alerts, windows, manifest["manager_version"])


def prepare_password_spray_investigation(
    project_root: str | Path,
    output_root: str | Path,
) -> PreparedInvestigation:
    """Prepare evidence, evaluate actual Wazuh rules, and save exact results."""

    root = Path(project_root).resolve()
    case = prepare_password_spray_evidence(root, output_root)
    runtime_files = {
        "/var/ossec/etc/rules/simlab_password_spray.xml": (
            root / "integrations/wazuh/rules/simlab_password_spray.xml"
        ),
        "/var/ossec/ruleset/rules/0575-win-base_rules.xml": (
            root / "integrations/wazuh/ruleset/0575-win-base_rules.xml"
        ),
    }
    bridge_code = (root / "integrations/wazuh/evaluate.py").read_text(encoding="utf-8")
    runtime_sha256 = {
        runtime_path: sha256(local_path.read_bytes()).hexdigest()
        for runtime_path, local_path in runtime_files.items()
    }
    windows = []
    alerts = []
    for index, evidence in enumerate(failure_evaluation_windows(case), start=1):
        results = _evaluate_window(root, evidence, runtime_sha256, bridge_code)
        windows.append(
            WazuhEvaluationWindow(
                window_id=f"window-{index}",
                evidence_started_at=evidence[0].event.occurred_at,
                evidence_ended_at=evidence[-1].event.occurred_at,
                results=results,
            )
        )
        alerts.extend(_alerts_from_results(evidence, results))

    # Fail visibly if actual engine behavior differs from the agreed case.
    if len(windows) != 2:
        raise ValueError("the first case requires two isolated failure windows")
    earlier_ids = {item.event_instance_id for item in windows[0].results}
    if any(alert.triggering_event_id in earlier_ids for alert in alerts):
        raise ValueError(
            "earlier single-account failures unexpectedly produced an alert"
        )
    if {alert.rule_id for alert in alerts} != {"100101", "100111"}:
        raise ValueError("Wazuh did not produce both expected spray rule-test matches")

    metadata = {
        "schema_version": 1,
        "case_id": case.manifest.case_id,
        "detection_origin": "wazuh",
        "processing_mode": "rule_test",
        "manager_version": WAZUH_MANAGER_VERSION,
        "correlation_time_basis": "manager_ingestion_time",
        "replay_strategy": "isolated_historical_windows_compressed_within_60s",
        "runtime_file_sha256": runtime_sha256,
        "bridge_sha256": sha256(bridge_code.encode()).hexdigest(),
        "case_manifest_sha256": sha256(
            (case.path / "manifest.json").read_bytes()
        ).hexdigest(),
        "evaluated_event_count": sum(len(window.results) for window in windows),
        "context_only_event_count": 3,
        "alert_count": len(alerts),
        "limitations": (
            "Rule-test results are not persisted Wazuh dashboard alerts.",
            "Each historical failure sequence has independent correlation state.",
            "Within-window events are compressed; original spacing is not replayed.",
            "The three Kerberos context events are not evaluated by this adapter.",
        ),
    }
    content = {
        "results.json": pretty_json(windows),
        "alerts.json": pretty_json(alerts),
    }
    evaluation_id = content_address("evaluation", metadata, content)
    files = {
        "manifest.json": pretty_json({"evaluation_id": evaluation_id, **metadata}),
        **content,
    }
    path = (
        Path(output_root).resolve()
        / "evaluations"
        / case.manifest.case_id
        / evaluation_id
    )
    write_verified_directory(path, {**files, "SHA256SUMS": sha256sums(files)})
    return PreparedInvestigation(case, path, tuple(alerts))


def _evaluate_window(
    project_root: Path,
    evidence: tuple[InvestigationEvidence, ...],
    runtime_sha256: dict[str, str],
    bridge_code: str,
) -> tuple[WazuhRuleTestResult, ...]:
    request = {
        "expected_version": WAZUH_MANAGER_VERSION,
        "runtime_file_sha256": runtime_sha256,
        "events": [
            {
                "event_instance_id": item.event_instance_id,
                "event": to_wazuh_event(item.event),
            }
            for item in evidence
        ],
    }
    command = [
        "docker",
        "compose",
        "-f",
        str(project_root / "integrations/wazuh/compose.yaml"),
        "exec",
        "-T",
        "manager",
        "/var/ossec/framework/python/bin/python3",
        "-c",
        bridge_code,
    ]
    try:
        completed = subprocess.run(
            command,
            input=canonical_json(request).decode(),
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError(
            "Wazuh evaluation timed out; check the manager's readiness"
        ) from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(
            "Wazuh evaluation failed. Start/recreate the project manager with "
            "docker compose -f integrations/wazuh/compose.yaml up -d. "
            f"Details: {detail}"
        )
    results = _BridgeResponse.model_validate_json(completed.stdout).results
    if tuple(item.event_instance_id for item in results) != tuple(
        item.event_instance_id for item in evidence
    ):
        raise ValueError("Wazuh results do not match the submitted evidence sequence")
    for item, result in zip(evidence, results, strict=True):
        full_log = result.output.get("full_log")
        if not isinstance(full_log, str) or json.loads(full_log) != to_wazuh_event(
            item.event
        ):
            raise ValueError(
                "Wazuh returned evidence different from the submitted event"
            )
    return results


def _alerts_from_results(
    evidence: tuple[InvestigationEvidence, ...],
    results: tuple[WazuhRuleTestResult, ...],
) -> list[InvestigationAlert]:
    by_log = {canonical_json(to_wazuh_event(item.event)): item for item in evidence}
    alerts = []
    for result in results:
        if not result.would_alert:
            continue
        output = result.output
        required_rule_fields = {"id", "level", "description"}
        rule = output.get("rule")
        if not isinstance(rule, dict) or not required_rule_fields.issubset(rule):
            raise ValueError("Wazuh alert result lacks required rule details")
        if "timestamp" not in output:
            raise ValueError("Wazuh alert result lacks its actual processing timestamp")
        previous = output.get("previous_output", "")
        if not isinstance(previous, str):
            raise ValueError("Wazuh correlation history has an unexpected format")
        logs = previous.splitlines() + [output["full_log"]]
        supporting = {}
        for log in logs:
            if not log.strip():
                continue
            try:
                item = by_log[canonical_json(json.loads(log))]
            except (KeyError, ValueError) as error:
                raise ValueError(
                    "Wazuh correlation refers to unknown case evidence"
                ) from error
            supporting[item.event_instance_id] = item
        records = sorted(supporting.values(), key=lambda item: item.event.occurred_at)
        if (
            str(rule["id"]) in {"100101", "100111"}
            and len({item.event.data.target_user_name.casefold() for item in records})
            < 3
        ):
            raise ValueError(
                "Wazuh spray match lacks three-account correlation evidence"
            )
        alerts.append(
            InvestigationAlert(
                rule_id=str(rule["id"]),
                level=rule["level"],
                description=rule["description"],
                detected_at=output["timestamp"],
                evidence_started_at=records[0].event.occurred_at,
                evidence_ended_at=records[-1].event.occurred_at,
                triggering_event_id=result.event_instance_id,
                supporting_event_ids=tuple(item.event_instance_id for item in records),
                mitre_attack_ids=tuple(rule.get("mitre", {}).get("id", [])),
            )
        )
    return alerts

import importlib.util
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from simlab.cli import main
from simlab.investigation import (
    failure_evaluation_windows,
    prepare_password_spray_evidence,
)
from simlab.storage import canonical_json
from simlab.wazuh_evaluation import prepare_password_spray_investigation

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _engine_response(request, missing_rule=None):
    """Synthetic transport fixture; it is not proof of actual Wazuh behavior."""

    results = []
    history = defaultdict(list)
    for item in request["events"]:
        event = item["event"]
        event_id = event["win"]["system"]["eventID"]
        history[event_id].append(event)
        usernames = {
            earlier["win"]["eventdata"]["targetUserName"]
            for earlier in history[event_id]
        }
        spray_rule = "100111" if event_id == "4776" else "100101"
        would_alert = len(usernames) == 3 and spray_rule != missing_rule
        rule_id = (
            spray_rule
            if would_alert
            else ("100110" if event_id == "4776" else "100100")
        )
        output = {
            "timestamp": "2026-10-12T10:00:00.000000Z",
            "full_log": canonical_json(event).decode(),
            "rule": {
                "id": rule_id,
                "level": 10 if would_alert else 1,
                "description": "Fixture rule result",
                "mitre": {"id": ["T1110.003"]} if would_alert else {},
            },
        }
        if would_alert:
            output["previous_output"] = "\n".join(
                canonical_json(earlier).decode() for earlier in history[event_id][:-1]
            )
        results.append(
            {
                "event_instance_id": item["event_instance_id"],
                "processed_at": "2026-10-12T10:00:00.010000Z",
                "would_alert": would_alert,
                "output": output,
            }
        )
    return {"manager_version": "4.14.7", "results": results}


def test_case_evidence_is_reproducible_and_keeps_author_answers_separate(
    tmp_path,
) -> None:
    first = prepare_password_spray_evidence(PROJECT_ROOT, tmp_path)
    second = prepare_password_spray_evidence(PROJECT_ROOT, tmp_path)
    assert first == second
    assert first.manifest.event_count == 15
    assert first.manifest.evidence_started_at.minute == 10
    assert first.manifest.evidence_ended_at.minute == 15
    assert first.manifest.evidence_ended_at.second == 19
    assert len({item.event_instance_id for item in first.evidence}) == 15
    assert [
        (item.event.event_id, item.event.data.target_user_name)
        for item in first.evidence[6:9]
    ] == [
        (4768, "bob"),
        (4769, "bob@CORP.LAB"),
        (4624, "bob"),
    ]
    records_by_host = defaultdict(list)
    for item in first.evidence:
        records_by_host[item.host_id].append(item.event.record_id)
    for records in records_by_host.values():
        assert records == list(range(1001, 1001 + len(records)))
    serialized = (first.path / "events.jsonl").read_text()
    assert "source_attempt_id" not in serialized
    assert "synthetic_correlation_id" not in serialized
    assert "case-spray-window" not in serialized
    author = json.loads((first.path / "author-context.json").read_text())
    assert len(author) == 15
    assert any(item["scenario_id"] == "case-spray-window" for item in author)


def test_historical_windows_are_isolated_and_context_is_not_replayed(tmp_path) -> None:
    case = prepare_password_spray_evidence(PROJECT_ROOT, tmp_path)
    windows = failure_evaluation_windows(case)
    assert [len(window) for window in windows] == [6, 6]
    assert {item.event.data.target_user_name for item in windows[0]} == {"alice"}
    assert {item.event.data.target_user_name for item in windows[1]} == {
        "alice",
        "bob",
        "carol",
    }
    assert windows[0][0].event.occurred_at.minute == 10
    assert windows[1][0].event.occurred_at.minute == 15


def test_collects_engine_evidence_with_distinct_detection_and_event_times(
    tmp_path, monkeypatch
) -> None:
    requests = []

    def run(command, **kwargs):
        request = json.loads(kwargs["input"])
        requests.append(request)
        assert command[:2] == ["docker", "compose"]
        assert "-T" in command
        assert kwargs["timeout"] == 45
        return SimpleNamespace(
            returncode=0, stderr="", stdout=json.dumps(_engine_response(request))
        )

    monkeypatch.setattr("simlab.wazuh_evaluation.subprocess.run", run)
    prepared = prepare_password_spray_investigation(PROJECT_ROOT, tmp_path)
    assert len(requests) == 2
    assert all(len(request["events"]) == 6 for request in requests)
    assert {alert.rule_id for alert in prepared.alerts} == {"100101", "100111"}
    for alert in prepared.alerts:
        assert alert.detection_origin == "wazuh"
        assert alert.processing_mode == "rule_test"
        assert len(alert.supporting_event_ids) == 3
        assert alert.detected_at.month == 10
        assert alert.evidence_started_at.month == 9
        assert alert.evidence_started_at.minute == 15
    manifest = json.loads((prepared.evaluation_path / "manifest.json").read_text())
    assert manifest["evaluated_event_count"] == 12
    assert manifest["context_only_event_count"] == 3
    assert manifest["correlation_time_basis"] == "manager_ingestion_time"
    assert set(manifest["runtime_file_sha256"]) == {
        "/var/ossec/etc/rules/simlab_password_spray.xml",
        "/var/ossec/ruleset/rules/0575-win-base_rules.xml",
    }


@pytest.mark.parametrize(
    "problem", ["missing_signal", "missing_history", "wrong_event", "wrong_version"]
)
def test_rejects_incomplete_or_inconsistent_engine_results(
    tmp_path, monkeypatch, problem
) -> None:
    def run(command, **kwargs):
        response = _engine_response(
            json.loads(kwargs["input"]),
            missing_rule="100111" if problem == "missing_signal" else None,
        )
        if problem == "wrong_version":
            response["manager_version"] = "4.12.0"
        for result in response["results"]:
            if problem == "wrong_event":
                result["output"]["full_log"] = "{}"
            if problem == "missing_history":
                result["output"].pop("previous_output", None)
        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(response))

    monkeypatch.setattr("simlab.wazuh_evaluation.subprocess.run", run)
    with pytest.raises(ValueError):
        prepare_password_spray_investigation(PROJECT_ROOT, tmp_path)
    assert not (tmp_path / "evaluations").exists()


@pytest.mark.parametrize("timeout", [False, True])
def test_runtime_failure_does_not_create_fake_evaluation(
    tmp_path, monkeypatch, timeout
) -> None:
    def run(command, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return SimpleNamespace(returncode=1, stderr="manager is stopped", stdout="")

    monkeypatch.setattr("simlab.wazuh_evaluation.subprocess.run", run)
    with pytest.raises(ValueError, match="Wazuh evaluation"):
        prepare_password_spray_investigation(PROJECT_ROOT, tmp_path)
    assert not (tmp_path / "evaluations").exists()


def test_prepare_cli_hides_generation_and_replay_steps(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "simlab.wazuh_evaluation.subprocess.run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=json.dumps(_engine_response(json.loads(kwargs["input"]))),
        ),
    )
    assert (
        main(
            [
                "prepare",
                "password-spray",
                "--project-root",
                str(PROJECT_ROOT),
                "--output-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.err == ""
    assert "Evidence: 15 events; Wazuh spray rule-test matches: 2" in output.out


def test_bridge_preserves_session_token_and_closes_on_failure(tmp_path, monkeypatch):
    original_import_path = tuple(sys.path)
    script_path = PROJECT_ROOT / "integrations/wazuh/evaluate.py"
    spec = importlib.util.spec_from_file_location("evaluation_bridge", script_path)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    socket_path = tmp_path / "logtest"
    socket_path.touch()
    common = ModuleType("wazuh.core.common")
    common.LOGTEST_SOCKET = str(socket_path)
    logtest = ModuleType("wazuh.core.logtest")
    calls = []

    def send(command, parameters):
        calls.append((command, parameters))
        if command == "remove_session":
            return {"error": 0}
        if len(calls) == 1:
            return {
                "error": 0,
                "data": {"token": "fresh-token", "output": {}, "alert": False},
            }
        return {"error": 1, "message": "fixture engine failure"}

    logtest.send_logtest_msg = send
    monkeypatch.setitem(sys.modules, "wazuh", ModuleType("wazuh"))
    monkeypatch.setitem(sys.modules, "wazuh.core", ModuleType("wazuh.core"))
    monkeypatch.setitem(sys.modules, "wazuh.core.common", common)
    monkeypatch.setitem(sys.modules, "wazuh.core.logtest", logtest)
    monkeypatch.setattr(
        bridge.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout='WAZUH_VERSION="v4.14.7"'),
    )
    with pytest.raises(ValueError, match="rejected"):
        bridge.evaluate(
            {
                "expected_version": "4.14.7",
                "runtime_file_sha256": {},
                "events": [
                    {"event_instance_id": "one", "event": {}},
                    {"event_instance_id": "two", "event": {}},
                ],
            }
        )
    assert "token" not in calls[0][1]
    assert calls[1][1]["token"] == "fresh-token"
    assert calls[-1] == ("remove_session", {"token": "fresh-token"})
    assert tuple(sys.path) == original_import_path

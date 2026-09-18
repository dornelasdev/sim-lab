import json
from hashlib import sha256
from pathlib import Path
from xml.etree import ElementTree

import pytest
import yaml

from simlab.artifacts import generate_authentication_bundle
from simlab.authentication import load_authentication_scenario
from simlab.environment import load_environment
from simlab.wazuh import (
    WAZUH_ADAPTER_ID,
    WAZUH_MANAGER_VERSION,
    export_wazuh_replay,
    load_wazuh_replay_bundle,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication"
WAZUH_PATH = PROJECT_ROOT / "integrations" / "wazuh"


def _export(tmp_path, route_name="password-spray.yaml"):
    environment = load_environment(ENVIRONMENT_PATH)
    scenario = load_authentication_scenario(ROUTE_PATH / route_name, environment)
    telemetry = generate_authentication_bundle(
        scenario,
        environment,
        tmp_path / "telemetry",
    )
    replay = export_wazuh_replay(telemetry.path, tmp_path / "wazuh")
    return telemetry, replay


def test_exports_only_supported_events_in_eventchannel_shape(tmp_path) -> None:
    telemetry, replay = _export(tmp_path)
    loaded = load_wazuh_replay_bundle(replay.path)

    assert replay.created is True
    assert replay.path.parent.name == telemetry.manifest.telemetry_id
    assert replay.manifest.adapter_id == WAZUH_ADAPTER_ID
    assert replay.manifest.wazuh_manager_version == WAZUH_MANAGER_VERSION
    assert replay.manifest.representation_status == ("derived_pending_observed_fixture")
    assert replay.manifest.intended_validation_mode == "wazuh_logtest"
    assert replay.manifest.correlation_time_basis == "manager_ingestion_time"
    assert replay.manifest.source_event_count == 6
    assert replay.manifest.exported_event_count == 6
    assert replay.manifest.omitted_event_count == 0
    assert len(loaded.events) == 6

    event_ids = [event["win"]["system"]["eventID"] for event in loaded.events]
    assert event_ids.count("4625") == 3
    assert event_ids.count("4776") == 3
    for event in loaded.events:
        assert event["win"]["system"]["channel"] == "Security"
        assert event["win"]["system"]["severityValue"] == "AUDIT_FAILURE"
        assert event["win"]["system"]["providerName"] == (
            "Microsoft-Windows-Security-Auditing"
        )

    event_4625 = next(
        event for event in loaded.events if event["win"]["system"]["eventID"] == "4625"
    )
    assert event_4625["win"]["eventdata"]["status"] == "0xC000006D"
    assert event_4625["win"]["eventdata"]["subStatus"] == "0xC000006A"
    assert event_4625["win"]["eventdata"]["logonType"] == "3"
    assert event_4625["win"]["eventdata"]["authenticationPackageName"] == "NTLM"

    event_4776 = next(
        event for event in loaded.events if event["win"]["system"]["eventID"] == "4776"
    )
    assert event_4776["win"]["eventdata"] == {
        "packageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        "status": "0xC000006A",
        "targetUserName": "alice",
        "workstation": "WS01",
    }


def test_provenance_maps_each_replay_line_to_one_source_event(tmp_path) -> None:
    telemetry, replay = _export(tmp_path)
    loaded = load_wazuh_replay_bundle(replay.path)
    source_event_ids = {
        json.loads(line)["event_instance_id"]
        for line in (telemetry.path / "events.jsonl").read_text().splitlines()
    }

    assert tuple(item.line_number for item in loaded.provenance) == tuple(range(1, 7))
    assert {item.source_event_instance_id for item in loaded.provenance} == (
        source_event_ids
    )
    assert all(item.value_origin == "derived" for item in loaded.provenance)
    assert len({item.replay_record_id for item in loaded.provenance}) == 6


def test_negative_control_exports_repeated_failures_for_only_one_user(
    tmp_path,
) -> None:
    _, replay = _export(tmp_path, "repeated-password-failure.yaml")
    loaded = load_wazuh_replay_bundle(replay.path)

    usernames = {event["win"]["eventdata"]["targetUserName"] for event in loaded.events}
    assert usernames == {"alice"}
    assert len(loaded.events) == 6


def test_reuses_content_addressed_replay_and_records_raw_source_hash(tmp_path) -> None:
    telemetry, first = _export(tmp_path)
    second = export_wazuh_replay(telemetry.path, tmp_path / "wazuh")

    assert first.created is True
    assert second.created is False
    assert first.path == second.path
    assert (
        first.manifest.source_manifest_sha256
        == sha256((telemetry.path / "manifest.json").read_bytes()).hexdigest()
    )
    assert set(path.name for path in first.path.iterdir()) == {
        "SHA256SUMS",
        "events.jsonl",
        "manifest.json",
        "provenance.jsonl",
    }


def test_loader_rejects_modified_replay_event(tmp_path) -> None:
    _, replay = _export(tmp_path)
    (replay.path / "events.jsonl").write_text("{}\n")

    with pytest.raises(ValueError):
        load_wazuh_replay_bundle(replay.path)


def test_manager_is_exactly_pinned_and_mounts_custom_rules() -> None:
    compose = yaml.safe_load((WAZUH_PATH / "compose.yaml").read_text())
    manager = compose["services"]["manager"]

    assert manager["image"] == "wazuh/wazuh-manager:4.14.7"
    assert manager["restart"] == "no"
    assert manager["volumes"] == [
        "./ruleset/0575-win-base_rules.xml:"
        "/var/ossec/ruleset/rules/0575-win-base_rules.xml:ro",
        "./rules/simlab_password_spray.xml:"
        "/var/ossec/etc/rules/simlab_password_spray.xml:ro",
    ]


def test_logtest_base_rules_patch_changes_only_the_windows_entry_conditions() -> None:
    root = ElementTree.parse(
        WAZUH_PATH / "ruleset" / "0575-win-base_rules.xml"
    ).getroot()
    rules = root.findall("rule")

    assert [rule.attrib["id"] for rule in rules] == [
        "60000",
        "60001",
        "60002",
        "60003",
        "60004",
        "60005",
        "60016",
        "60006",
        "60017",
        "60007",
        "60008",
        "60018",
        "60009",
        "60010",
        "60011",
        "60012",
        "60013",
        "60014",
        "60015",
    ]
    entry = rules[0]
    assert entry.attrib == {"id": "60000", "level": "0"}
    assert entry.find("category") is None
    assert entry.findtext("decoded_as") == "json"
    assert entry.find("field").attrib["name"] == "win.system.providerName"


def test_rules_use_hidden_stock_children_and_distinct_user_correlations() -> None:
    root = ElementTree.parse(
        WAZUH_PATH / "rules" / "simlab_password_spray.xml"
    ).getroot()
    rules = {rule.attrib["id"]: rule for rule in root.findall("rule")}

    assert set(rules) == {"100100", "100101", "100110", "100111"}
    assert rules["100100"].findtext("if_sid") == "60122"
    assert rules["100100"].attrib["level"] == "1"
    assert rules["100100"].findtext("options") == "no_log"
    assert rules["100110"].findtext("if_sid") == "60104"
    assert rules["100110"].attrib["level"] == "1"
    assert rules["100110"].findtext("options") == "no_log"

    assert rules["100101"].attrib == {
        "id": "100101",
        "level": "10",
        "frequency": "3",
        "timeframe": "60",
    }
    assert rules["100101"].findtext("if_matched_sid") == "100100"
    assert [field.text for field in rules["100101"].findall("same_field")] == [
        "win.eventdata.ipAddress",
        "win.system.computer",
    ]
    assert rules["100101"].findtext("different_field") == (
        "win.eventdata.targetUserName"
    )

    assert rules["100111"].attrib == {
        "id": "100111",
        "level": "10",
        "frequency": "3",
        "timeframe": "60",
    }
    assert rules["100111"].findtext("if_matched_sid") == "100110"
    assert [field.text for field in rules["100111"].findall("same_field")] == [
        "win.eventdata.workstation",
        "win.system.computer",
    ]
    assert rules["100111"].findtext("different_field") == (
        "win.eventdata.targetUserName"
    )

from pathlib import Path
from xml.etree import ElementTree

import pytest
import yaml

from simlab.investigation import prepare_password_spray_evidence
from simlab.wazuh import SUPPORTED_EVENT_IDS, WAZUH_MANAGER_VERSION, to_wazuh_event

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WAZUH_PATH = PROJECT_ROOT / "integrations" / "wazuh"


def test_adapter_preserves_supported_event_fields_without_bundle_exports(tmp_path):
    case = prepare_password_spray_evidence(PROJECT_ROOT, tmp_path)
    mapped = [
        to_wazuh_event(item.event)
        for item in case.evidence
        if item.event.event_id in SUPPORTED_EVENT_IDS
    ]
    assert len(mapped) == 12
    assert WAZUH_MANAGER_VERSION == "4.14.7"
    for record in mapped:
        system = record["win"]["system"]
        assert system["channel"] == "Security"
        assert system["severityValue"] == "AUDIT_FAILURE"
        assert system["providerName"] == "Microsoft-Windows-Security-Auditing"
        assert system["systemTime"].endswith("Z")
        assert system["eventRecordID"].isdigit()

    failure = next(
        record["win"]["eventdata"]
        for record in mapped
        if record["win"]["system"]["eventID"] == "4625"
    )
    assert failure["status"] == "0xC000006D"
    assert failure["subStatus"] == "0xC000006A"
    assert failure["logonType"] == "3"
    assert failure["authenticationPackageName"] == "NTLM"
    validation = next(
        record["win"]["eventdata"]
        for record in mapped
        if record["win"]["system"]["eventID"] == "4776"
    )
    assert validation == {
        "packageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        "status": "0xC000006A",
        "targetUserName": "alice",
        "workstation": "WS01",
    }


def test_adapter_does_not_silently_map_unsupported_kerberos_context(tmp_path):
    case = prepare_password_spray_evidence(PROJECT_ROOT, tmp_path)
    context = [
        item for item in case.evidence if item.event.event_id not in SUPPORTED_EVENT_IDS
    ]
    assert len(context) == 3
    for item in context:
        with pytest.raises(ValueError, match="no Wazuh rule-test mapping"):
            to_wazuh_event(item.event)


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

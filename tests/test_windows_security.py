from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree

from simlab.environment import load_environment
from simlab.telemetry.windows_security import (
    EVENT_NAMESPACE,
    WINDOWS_SECURITY_2025_01,
    Event4776Data,
    create_windows_security_event,
    to_event_xml,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_modern_profile_contains_initial_event_schemas() -> None:
    profile = WINDOWS_SECURITY_2025_01

    assert set(profile.schemas) == {4624, 4625, 4768, 4769, 4776}
    assert profile.schemas[4768].version == 2
    assert profile.schemas[4769].version == 2


def test_serializes_full_4776_event_to_windows_xml() -> None:
    event = create_windows_security_event(
        profile_id="windows-security-2025-01",
        event_id=4776,
        occurred_at=datetime(2026, 9, 14, 9, 15, tzinfo=UTC),
        record_id=1001,
        computer="DC01.corp.lab",
        process_id=696,
        thread_id=2564,
        data=Event4776Data(
            package_name="MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
            target_user_name="alice",
            workstation="WS01",
            status="0xC000006A",
        ),
    )

    root = ElementTree.fromstring(to_event_xml(event))
    namespace = {"event": EVENT_NAMESPACE}

    assert root.findtext("event:System/event:EventID", namespaces=namespace) == "4776"
    assert root.findtext("event:System/event:Computer", namespaces=namespace) == (
        "DC01.corp.lab"
    )

    event_data = {
        element.attrib["Name"]: element.text
        for element in root.findall("event:EventData/event:Data", namespace)
    }
    assert event_data == {
        "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        "TargetUserName": "alice",
        "Workstation": "WS01",
        "Status": "0xC000006A",
    }


def test_environment_hosts_select_versioned_event_profile() -> None:
    environment = load_environment(PROJECT_ROOT / "environments" / "corp-lab.yaml")

    assert {host.event_profile_id for host in environment.hosts} == {
        "windows-security-2025-01"
    }

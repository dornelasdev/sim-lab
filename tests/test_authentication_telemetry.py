from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from xml.etree import ElementTree

import pytest

from simlab.authentication import AuthenticationScenario, load_authentication_scenario
from simlab.definition import read_yaml
from simlab.environment import CorporateEnvironment, load_environment
from simlab.telemetry.authentication import generate_authentication_telemetry
from simlab.telemetry.windows_security import (
    Event4624Data,
    Event4625Data,
    Event4768Data,
    Event4769Data,
    Event4771Data,
    Event4776Data,
    to_event_xml,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication"


@pytest.fixture
def environment():
    return load_environment(ENVIRONMENT_PATH)


def test_generates_correlated_kerberos_interactive_logon(environment) -> None:
    scenario = load_authentication_scenario(ROUTE_PATH / "normal.yaml", environment)

    telemetry = generate_authentication_telemetry(scenario, environment)

    assert [(item.event.event_id, item.host_id) for item in telemetry.events] == [
        (4768, "dc01"),
        (4769, "dc01"),
        (4624, "ws01"),
    ]
    assert [item.event.record_id for item in telemetry.events] == [1001, 1002, 1001]
    assert all(item.event.occurred_at > scenario.start_at for item in telemetry.events)
    assert len({item.synthetic_correlation_id for item in telemetry.events}) == 1

    tgt_request = telemetry.events[0].event.data
    service_ticket = telemetry.events[1].event.data
    workstation_logon = telemetry.events[2].event.data
    assert isinstance(tgt_request, Event4768Data)
    assert isinstance(service_ticket, Event4769Data)
    assert isinstance(workstation_logon, Event4624Data)
    assert tgt_request.status == "0x0"
    assert tgt_request.target_sid == workstation_logon.target_user_sid
    assert service_ticket.logon_guid == workstation_logon.logon_guid
    assert service_ticket.service_name == "WS01$"
    assert workstation_logon.authentication_package_name == "Kerberos"
    assert workstation_logon.logon_type == "2"


def test_generates_ntlm_spray_on_authority_and_destination(environment) -> None:
    scenario = load_authentication_scenario(
        ROUTE_PATH / "password-spray.yaml",
        environment,
    )

    telemetry = generate_authentication_telemetry(scenario, environment)

    assert [(item.event.event_id, item.host_id) for item in telemetry.events] == [
        (4776, "dc01"),
        (4625, "fs01"),
        (4776, "dc01"),
        (4625, "fs01"),
        (4776, "dc01"),
        (4625, "fs01"),
    ]
    records_by_host = defaultdict(list)
    correlations_by_attempt = defaultdict(set)
    for item in telemetry.events:
        records_by_host[item.host_id].append(item.event.record_id)
        correlations_by_attempt[item.source_attempt_id].add(
            item.synthetic_correlation_id
        )

    assert dict(records_by_host) == {
        "dc01": [1001, 1002, 1003],
        "fs01": [1001, 1002, 1003],
    }
    assert all(len(values) == 1 for values in correlations_by_attempt.values())
    assert len({next(iter(values)) for values in correlations_by_attempt.values()}) == 3

    credential_validation = telemetry.events[0].event.data
    failed_logon = telemetry.events[1].event.data
    assert isinstance(credential_validation, Event4776Data)
    assert isinstance(failed_logon, Event4625Data)
    assert credential_validation.workstation == "WS01"
    assert credential_validation.status == "0xC000006A"
    assert failed_logon.authentication_package_name == "NTLM"
    assert failed_logon.logon_type == "3"
    assert failed_logon.status == "0xC000006D"
    assert failed_logon.sub_status == "0xC000006A"
    assert failed_logon.ip_address == "10.10.0.101"
    assert telemetry.events[1].event.computer == "FS01.corp.lab"


@pytest.mark.parametrize("route_name", ["normal.yaml", "kerberos-logon-failure.yaml"])
def test_generation_is_deterministic_and_xml_compatible(
    environment, route_name
) -> None:
    scenario = load_authentication_scenario(ROUTE_PATH / route_name, environment)

    first = generate_authentication_telemetry(scenario, environment)
    second = generate_authentication_telemetry(scenario, environment)

    assert first == second
    for item in first.events:
        ElementTree.fromstring(to_event_xml(item.event))


def test_host_audit_policy_controls_observability() -> None:
    environment_data = deepcopy(read_yaml(ENVIRONMENT_PATH))
    dc_policy = next(
        policy
        for policy in environment_data["audit_policies"]
        if policy["id"] == "auth-monitoring-baseline-dc"
    )
    credential_validation = next(
        setting
        for setting in dc_policy["settings"]
        if setting["category"] == "credential_validation"
    )
    credential_validation["outcomes"] = ["success"]
    restricted_environment = CorporateEnvironment.model_validate(environment_data)
    scenario = load_authentication_scenario(
        ROUTE_PATH / "password-spray.yaml",
        restricted_environment,
    )

    with pytest.raises(ValueError, match="does not match scenario expectations"):
        generate_authentication_telemetry(scenario, restricted_environment)


@pytest.mark.parametrize(
    "route_name", ["password-spray.yaml", "kerberos-logon-failure.yaml"]
)
def test_every_windows_field_has_exactly_one_provenance_origin(
    environment, route_name
) -> None:
    scenario = load_authentication_scenario(
        ROUTE_PATH / route_name,
        environment,
    )

    telemetry = generate_authentication_telemetry(scenario, environment)

    for item in telemetry.events:
        origins = item.field_provenance
        fields = (
            origins.documented
            | origins.derived
            | origins.synthetic
            | origins.unavailable
        )
        assert "system.event_id" in fields
        assert "event_data.TargetUserName" in fields
        assert origins.documentation


def test_failed_interactive_logon_stops_before_ticket_issuance(environment) -> None:
    scenario = load_authentication_scenario(
        ROUTE_PATH / "kerberos-logon-failure.yaml", environment
    )
    telemetry = generate_authentication_telemetry(scenario, environment)

    assert [(item.event.event_id, item.host_id) for item in telemetry.events] == [
        (4771, "dc01"),
        (4625, "ws01"),
    ]
    dc, workstation = telemetry.events
    assert isinstance(dc.event.data, Event4771Data)
    assert dc.event.data.status == "0x18"
    assert dc.event.data.pre_auth_type == "2"
    assert dc.event.data.service_name == "krbtgt/CORP.LAB"
    assert dc.event.data.target_sid.endswith("-1101")
    assert dc.event.data.ip_address == "::ffff:10.10.0.101"
    assert dc.event.data.cert_issuer_name == ""
    assert isinstance(workstation.event.data, Event4625Data)
    assert workstation.event.data.logon_type == "2"
    assert workstation.event.data.authentication_package_name == "Kerberos"
    assert workstation.event.data.status == "0xC000006D"
    assert workstation.event.data.sub_status == "0xC000006A"
    assert workstation.event.data.ip_address == "-"
    assert dc.event.data.target_user_name == workstation.event.data.target_user_name
    assert dc.synthetic_correlation_id == workstation.synthetic_correlation_id
    assert dc.event.correlation_activity_id is None
    assert workstation.event.correlation_activity_id is None
    assert dc.event.occurred_at < workstation.event.occurred_at
    assert "event_data.TicketOptions" in dc.field_provenance.synthetic
    assert (
        "event_data.AuthenticationPackageName" in workstation.field_provenance.synthetic
    )


@pytest.mark.parametrize(
    ("policy_id", "category", "remaining_id"),
    [
        ("auth-monitoring-baseline-dc", "kerberos_authentication_service", 4625),
        ("auth-monitoring-baseline-member", "logon", 4771),
    ],
)
def test_failed_kerberos_observations_have_independent_audit_gates(
    policy_id, category, remaining_id
) -> None:
    environment_data = deepcopy(read_yaml(ENVIRONMENT_PATH))
    policy = next(p for p in environment_data["audit_policies"] if p["id"] == policy_id)
    setting = next(s for s in policy["settings"] if s["category"] == category)
    setting["outcomes"] = ["success"]
    environment = CorporateEnvironment.model_validate(environment_data)
    scenario_data = deepcopy(read_yaml(ROUTE_PATH / "kerberos-logon-failure.yaml"))
    scenario = AuthenticationScenario.model_validate(scenario_data)

    with pytest.raises(ValueError, match="does not match scenario expectations"):
        generate_authentication_telemetry(scenario, environment)

    scenario_data["expected_events"] = [
        expected
        for expected in scenario_data["expected_events"]
        if expected["event_id"] == remaining_id
    ]
    scenario = AuthenticationScenario.model_validate(scenario_data)
    telemetry = generate_authentication_telemetry(scenario, environment)
    assert [item.event.event_id for item in telemetry.events] == [remaining_id]

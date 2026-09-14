from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from simlab.authentication import (
    AuthenticationScenario,
    load_authentication_scenario,
)
from simlab.definition import read_yaml
from simlab.environment import load_environment

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication"


@pytest.fixture
def environment():
    return load_environment(ENVIRONMENT_PATH)


def test_loads_normal_authentication_scenario(environment) -> None:
    scenario = load_authentication_scenario(ROUTE_PATH / "normal.yaml", environment)

    assert scenario.id == "normal-domain-logon"
    assert scenario.protocol == "kerberos"
    assert len(scenario.attempts) == 1
    assert scenario.attempts[0].outcome == "success"


def test_password_spray_has_deterministic_timeline(environment) -> None:
    scenario = load_authentication_scenario(
        ROUTE_PATH / "password-spray.yaml",
        environment,
    )

    timeline = scenario.timeline()

    assert scenario.protocol == "ntlm"
    assert scenario.service_id == "fs01-smb"
    assert {attempt.destination_host_id for _, attempt in timeline} == {"fs01"}
    assert [attempt.identity_id for _, attempt in timeline] == [
        "alice",
        "bob",
        "carol",
    ]
    offsets = [
        (occurred_at - scenario.start_at).total_seconds() for occurred_at, _ in timeline
    ]
    assert offsets == [
        0,
        7,
        19,
    ]


def test_rejects_attempts_out_of_order() -> None:
    data = read_yaml(ROUTE_PATH / "password-spray.yaml")
    data["attempts"][1]["offset_seconds"] = 20

    with pytest.raises(ValidationError, match="ordered by offset_seconds"):
        AuthenticationScenario.model_validate(data)


def test_rejects_unknown_identity(environment) -> None:
    data = deepcopy(read_yaml(ROUTE_PATH / "normal.yaml"))
    data["attempts"][0]["identity_id"] = "unknown-user"
    scenario = AuthenticationScenario.model_validate(data)

    with pytest.raises(ValueError, match="references unknown identity"):
        scenario.validate_against(environment)


def test_rejects_service_destination_mismatch(environment) -> None:
    data = deepcopy(read_yaml(ROUTE_PATH / "password-spray.yaml"))
    data["attempts"][0]["destination_host_id"] = "dc01"
    scenario = AuthenticationScenario.model_validate(data)

    with pytest.raises(ValueError, match="destination does not host service"):
        scenario.validate_against(environment)

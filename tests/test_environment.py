from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from simlab.environment import CorporateEnvironment, load_environment

ENVIRONMENT_PATH = (
    Path(__file__).resolve().parents[1] / "environments" / "corp-lab.yaml"
)


def load_environment_data() -> dict:
    with ENVIRONMENT_PATH.open(encoding="utf-8") as file:
        return yaml.safe_load(file)


def test_loads_corporate_environment() -> None:
    environment = load_environment(ENVIRONMENT_PATH)

    assert environment.id == "corp-lab"
    assert {host.id for host in environment.hosts} == {"dc01", "fs01", "ws01"}
    assert environment.services[0].id == "fs01-smb"
    assert environment.services[0].host_id == "fs01"
    assert environment.identities[0].domain_id == "corp-domain"


def test_rejects_unknown_domain_reference() -> None:
    data = load_environment_data()
    data["hosts"][0]["domain_id"] = "missing-domain"

    with pytest.raises(ValidationError, match="references unknown domain"):
        CorporateEnvironment.model_validate(data)


def test_rejects_duplicate_entity_ids() -> None:
    data = load_environment_data()
    duplicate_host = deepcopy(data["hosts"][0])
    data["hosts"].append(duplicate_host)

    with pytest.raises(ValidationError, match="duplicate id 'dc01'"):
        CorporateEnvironment.model_validate(data)


def test_rejects_unknown_audit_policy_reference() -> None:
    data = load_environment_data()
    data["hosts"][0]["audit_policy_id"] = "missing-policy"

    with pytest.raises(ValidationError, match="references unknown audit policy"):
        CorporateEnvironment.model_validate(data)


def test_rejects_duplicate_domain_principal_rid() -> None:
    data = load_environment_data()
    data["identities"][0]["rid"] = data["hosts"][0]["account_rid"]

    with pytest.raises(ValidationError, match="duplicate RID"):
        CorporateEnvironment.model_validate(data)

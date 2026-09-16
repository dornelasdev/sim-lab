import json
from hashlib import sha256
from pathlib import Path
from xml.etree import ElementTree

import pytest

from simlab.artifacts import generate_authentication_bundle
from simlab.authentication import load_authentication_scenario
from simlab.environment import load_environment
from simlab.telemetry.windows_security import EVENT_NAMESPACE

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication"


def _normal_inputs():
    environment = load_environment(ENVIRONMENT_PATH)
    scenario = load_authentication_scenario(ROUTE_PATH / "normal.yaml", environment)
    return environment, scenario


def test_writes_self_contained_jsonl_and_matching_xml(tmp_path) -> None:
    environment, scenario = _normal_inputs()

    bundle = generate_authentication_bundle(
        scenario,
        environment,
        tmp_path,
    )

    records = [
        json.loads(line)
        for line in (bundle.path / "events.jsonl").read_text().splitlines()
    ]
    assert bundle.created is True
    assert len(records) == 3
    assert len({record["event_instance_id"] for record in records}) == 3

    for record in records:
        assert record["source_attempt_id"] == "alice-interactive-logon"
        assert record["field_provenance"]["documentation"]
        for origin in ("documented", "derived", "synthetic", "unavailable"):
            fields = record["field_provenance"][origin]
            assert fields == sorted(fields)
        xml_path = bundle.path / record["xml_path"]
        root = ElementTree.fromstring(xml_path.read_text())
        xml_event_id = root.findtext(
            "event:System/event:EventID",
            namespaces={"event": EVENT_NAMESPACE},
        )
        assert xml_event_id == str(record["event"]["event_id"])


def test_reuses_an_identical_content_addressed_bundle(tmp_path) -> None:
    environment, scenario = _normal_inputs()

    first = generate_authentication_bundle(scenario, environment, tmp_path)
    reloaded_environment, reloaded_scenario = _normal_inputs()
    second = generate_authentication_bundle(
        reloaded_scenario,
        reloaded_environment,
        tmp_path,
    )

    assert first.created is True
    assert second.created is False
    assert first.path == second.path
    assert first.manifest == second.manifest


def test_definition_change_produces_a_different_bundle_id(tmp_path) -> None:
    environment, scenario = _normal_inputs()
    changed_scenario = scenario.model_copy(
        update={"description": "The same activity with revised documentation."}
    )

    original = generate_authentication_bundle(
        scenario,
        environment,
        tmp_path,
    )
    changed = generate_authentication_bundle(
        changed_scenario,
        environment,
        tmp_path,
    )

    assert original.manifest.bundle_id != changed.manifest.bundle_id
    assert original.path != changed.path


def test_rejects_existing_bundle_with_mismatched_content(tmp_path) -> None:
    environment, scenario = _normal_inputs()
    bundle = generate_authentication_bundle(
        scenario,
        environment,
        tmp_path,
    )
    (bundle.path / "events.jsonl").write_text("changed\n")

    with pytest.raises(FileExistsError, match="does not match its ID"):
        generate_authentication_bundle(scenario, environment, tmp_path)


def test_manifest_describes_profiles_policies_and_artifact_digests(tmp_path) -> None:
    environment, scenario = _normal_inputs()

    bundle = generate_authentication_bundle(
        scenario,
        environment,
        tmp_path,
    )
    manifest = json.loads((bundle.path / "manifest.json").read_text())

    assert manifest["bundle_id"] == bundle.path.name
    assert manifest["environment_id"] == "corp-lab"
    assert manifest["scenario_id"] == "normal-domain-logon"
    assert manifest["event_count"] == 3
    assert manifest["event_profile_ids"] == ["windows-security-2025-01"]
    assert manifest["audit_policy_ids"] == [
        "auth-monitoring-baseline-dc",
        "auth-monitoring-baseline-member",
    ]
    assert len(manifest["jsonl"]["sha256"]) == 64
    assert len(manifest["xml"]["sha256"]) == 64
    assert (
        manifest["jsonl"]["sha256"]
        == sha256((bundle.path / "events.jsonl").read_bytes()).hexdigest()
    )
    assert len(manifest["environment_definition_sha256"]) == 64
    assert len(manifest["scenario_definition_sha256"]) == 64

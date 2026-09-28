import json
from pathlib import Path

from simlab.workflow import (
    DefinitionStatus,
    WorkflowCatalog,
    discover_workflow_catalog,
    inspect_telemetry_bundle,
    resolve_telemetry_definition_context,
    run_generation_stage,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication"


def test_discovers_guided_workflow_inputs_without_selecting_a_bundle(
    tmp_path,
) -> None:
    catalog = discover_workflow_catalog(PROJECT_ROOT, tmp_path / "outputs")

    assert catalog.environments == (ENVIRONMENT_PATH.resolve(),)
    assert {path.name for path in catalog.routes} == {
        "normal.yaml",
        "password-spray.yaml",
        "repeated-password-failure.yaml",
    }
    assert [path.name for path in catalog.detection_profiles] == ["password-spray.yaml"]
    assert catalog.telemetry_bundles == ()


def test_inspection_presents_focused_evidence_and_related_events(tmp_path) -> None:
    output_root = tmp_path / "outputs"
    generated = run_generation_stage(
        ENVIRONMENT_PATH,
        ROUTE_PATH / "password-spray.yaml",
        output_root,
    )

    inspection = inspect_telemetry_bundle(generated.path)

    assert inspection.overview.telemetry_id == generated.manifest.telemetry_id
    assert inspection.overview.event_count == 6
    assert inspection.overview.event_counts == ((4625, 3), (4776, 3))
    assert inspection.overview.host_counts == (("dc01", 3), ("fs01", 3))
    assert inspection.overview.host_event_counts == (
        ("dc01", 4776, 3),
        ("fs01", 4625, 3),
    )
    assert len(inspection.events) == 6

    credential_validation = inspection.events[0]
    assert credential_validation.event_id == 4776
    assert credential_validation.target_username == "alice"
    assert credential_validation.authentication_package == (
        "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
    )
    assert len(credential_validation.related_event_instance_ids) == 1
    assert credential_validation.xml.startswith("<?xml")
    assert {
        (field.name, field.value, field.origin)
        for field in credential_validation.fields
    } >= {
        ("TargetUserName", "alice", "derived"),
        ("Status", "0xC000006A", "documented"),
    }


def test_catalog_discovers_generated_bundle_by_its_exact_path(tmp_path) -> None:
    output_root = tmp_path / "outputs"
    generated = run_generation_stage(
        ENVIRONMENT_PATH,
        ROUTE_PATH / "normal.yaml",
        output_root,
    )

    catalog = discover_workflow_catalog(PROJECT_ROOT, output_root)

    assert catalog.telemetry_bundles == (generated.path.resolve(),)


def test_catalog_ignores_legacy_and_identity_mismatched_bundles(tmp_path) -> None:
    output_root = tmp_path / "outputs"
    generated = run_generation_stage(
        ENVIRONMENT_PATH,
        ROUTE_PATH / "normal.yaml",
        output_root,
    )
    current_manifest = json.loads((generated.path / "manifest.json").read_text())

    legacy_path = output_root / "legacy-scenario" / "bundle-legacy"
    legacy_path.mkdir(parents=True)
    legacy_manifest = {
        **current_manifest,
        "bundle_id": current_manifest["telemetry_id"].replace("telemetry-", "bundle-"),
    }
    del legacy_manifest["telemetry_id"]
    (legacy_path / "manifest.json").write_text(json.dumps(legacy_manifest))

    mismatched_path = output_root / "copied-scenario" / "telemetry-mismatched"
    mismatched_path.mkdir(parents=True)
    (mismatched_path / "manifest.json").write_text(json.dumps(current_manifest))

    catalog = discover_workflow_catalog(PROJECT_ROOT, output_root)

    assert catalog.telemetry_bundles == (generated.path.resolve(),)


def test_resolves_recorded_definition_status_without_blocking_inspection(
    tmp_path,
) -> None:
    generated = run_generation_stage(
        ENVIRONMENT_PATH,
        ROUTE_PATH / "password-spray.yaml",
        tmp_path / "outputs",
    )
    inspection = inspect_telemetry_bundle(generated.path)
    current_catalog = discover_workflow_catalog(PROJECT_ROOT, tmp_path / "outputs")

    matching = resolve_telemetry_definition_context(inspection, current_catalog)

    assert matching.environment.status is DefinitionStatus.MATCHING
    assert matching.scenario.status is DefinitionStatus.MATCHING

    changed_route = tmp_path / "routes" / "password-spray.yaml"
    changed_route.parent.mkdir()
    original_route = ROUTE_PATH / "password-spray.yaml"
    changed_route.write_text(
        original_route.read_text().replace(
            "name: Internal password spray",
            "name: Changed password spray",
        )
    )
    changed_catalog = WorkflowCatalog(
        environments=(),
        routes=(changed_route,),
        detection_profiles=(),
        telemetry_bundles=(generated.path,),
    )

    changed = resolve_telemetry_definition_context(inspection, changed_catalog)

    assert changed.environment.status is DefinitionStatus.UNAVAILABLE
    assert changed.environment.path is None
    assert changed.scenario.status is DefinitionStatus.CHANGED
    assert changed.scenario.path == changed_route

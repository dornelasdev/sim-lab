"""Shared orchestration and inspection for SimLab user interfaces."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from simlab.analysis import (
    AuthenticationAnalysisBundle,
    analyze_authentication_bundle,
)
from simlab.artifacts import (
    AuthenticationArtifactBundle,
    AuthenticationArtifactRecord,
    AuthenticationTelemetryManifest,
    generate_authentication_bundle,
    load_authentication_bundle,
)
from simlab.authentication import AuthenticationScenario, load_authentication_scenario
from simlab.definition import read_yaml
from simlab.environment import load_environment
from simlab.storage import model_digest
from simlab.wazuh import WazuhReplayBundle, export_wazuh_replay


@dataclass(frozen=True)
class WorkflowCatalog:
    """Definitions and existing telemetry available to a guided workflow."""

    environments: tuple[Path, ...]
    routes: tuple[Path, ...]
    detection_profiles: tuple[Path, ...]
    telemetry_bundles: tuple[Path, ...]


class DefinitionStatus(StrEnum):
    """Relationship between recorded provenance and a local definition."""

    MATCHING = "matching"
    CHANGED = "changed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class DefinitionContext:
    """One recorded definition and its optional local counterpart."""

    identifier: str
    canonical_sha256: str
    status: DefinitionStatus
    path: Path | None


@dataclass(frozen=True)
class TelemetryDefinitionContext:
    """Local-definition status for an existing telemetry bundle."""

    environment: DefinitionContext
    scenario: DefinitionContext


@dataclass(frozen=True)
class TelemetryFieldView:
    """One focused Windows event field and its SimLab value origin."""

    name: str
    value: str
    origin: str


@dataclass(frozen=True)
class TelemetryEventView:
    """A bounded analyst view of one verified authentication event."""

    event_instance_id: str
    occurred_at: datetime
    host_id: str
    computer: str
    event_id: int
    source_attempt_id: str
    target_username: str
    status: str
    authentication_package: str
    logon_type: str
    xml_path: str
    synthetic_correlation_id: str
    related_event_instance_ids: tuple[str, ...]
    fields: tuple[TelemetryFieldView, ...]
    xml: str


@dataclass(frozen=True)
class TelemetryOverview:
    """Run-wide facts displayed before inspecting individual events."""

    path: Path
    telemetry_id: str
    environment_id: str
    environment_definition_canonical_sha256: str
    scenario_id: str
    scenario_definition_canonical_sha256: str
    event_count: int
    event_counts: tuple[tuple[int, int], ...]
    host_counts: tuple[tuple[str, int], ...]
    host_event_counts: tuple[tuple[str, int, int], ...]
    event_profile_ids: tuple[str, ...]
    audit_policy_ids: tuple[str, ...]
    started_at: datetime | None
    ended_at: datetime | None


@dataclass(frozen=True)
class TelemetryInspection:
    """Verified telemetry prepared for the guided terminal interface."""

    overview: TelemetryOverview
    events: tuple[TelemetryEventView, ...]


_FOCUSED_FIELDS = {
    4624: (
        "TargetUserName",
        "TargetDomainName",
        "TargetUserSid",
        "LogonType",
        "AuthenticationPackageName",
        "WorkstationName",
        "IpAddress",
        "LogonGuid",
    ),
    4625: (
        "TargetUserName",
        "TargetDomainName",
        "Status",
        "SubStatus",
        "LogonType",
        "AuthenticationPackageName",
        "WorkstationName",
        "IpAddress",
        "IpPort",
    ),
    4768: (
        "TargetUserName",
        "TargetDomainName",
        "TargetSid",
        "ServiceName",
        "Status",
        "TicketEncryptionType",
        "PreAuthType",
        "IpAddress",
    ),
    4769: (
        "TargetUserName",
        "TargetDomainName",
        "ServiceName",
        "ServiceSid",
        "Status",
        "TicketEncryptionType",
        "IpAddress",
        "LogonGuid",
    ),
    4776: (
        "TargetUserName",
        "Workstation",
        "Status",
        "PackageName",
    ),
}


def discover_workflow_catalog(
    project_root: str | Path,
    output_root: str | Path | None = None,
) -> WorkflowCatalog:
    """Discover supported definitions and authentication telemetry bundles."""

    root = Path(project_root).resolve()
    artifacts_root = (
        Path(output_root).resolve() if output_root is not None else root / "outputs"
    )
    return WorkflowCatalog(
        environments=_yaml_files(root / "environments"),
        routes=_yaml_files(root / "routes" / "ad-authentication"),
        detection_profiles=_yaml_files(root / "detections" / "authentication"),
        telemetry_bundles=_telemetry_bundle_paths(artifacts_root),
    )


def run_generation_stage(
    environment_path: str | Path,
    route_path: str | Path,
    output_root: str | Path = "outputs",
) -> AuthenticationArtifactBundle:
    """Load definitions and generate one authentication telemetry bundle."""

    environment = load_environment(environment_path)
    scenario = load_authentication_scenario(route_path, environment)
    return generate_authentication_bundle(scenario, environment, output_root)


def run_detection_stage(
    telemetry_path: str | Path,
    profile_path: str | Path,
    output_root: str | Path = "outputs/analyses",
) -> AuthenticationAnalysisBundle:
    """Analyze one exact telemetry bundle with one detection profile."""

    return analyze_authentication_bundle(telemetry_path, profile_path, output_root)


def run_wazuh_export_stage(
    telemetry_path: str | Path,
    output_root: str | Path = "outputs/wazuh",
) -> WazuhReplayBundle:
    """Derive one Wazuh replay bundle from exact telemetry."""

    return export_wazuh_replay(telemetry_path, output_root)


def inspect_telemetry_bundle(path: str | Path) -> TelemetryInspection:
    """Integrity-check telemetry and build its bounded analyst view."""

    bundle = load_authentication_bundle(path)
    event_counts = Counter(record.event.event_id for record in bundle.records)
    host_counts = Counter(record.host_id for record in bundle.records)
    host_event_counts = Counter(
        (record.host_id, record.event.event_id) for record in bundle.records
    )
    occurred_at = tuple(record.event.occurred_at for record in bundle.records)
    related_by_attempt = {
        attempt_id: tuple(
            record.event_instance_id
            for record in bundle.records
            if record.source_attempt_id == attempt_id
        )
        for attempt_id in {record.source_attempt_id for record in bundle.records}
    }
    events = tuple(
        _event_view(bundle.path, record, related_by_attempt[record.source_attempt_id])
        for record in bundle.records
    )
    overview = TelemetryOverview(
        path=bundle.path,
        telemetry_id=bundle.manifest.telemetry_id,
        environment_id=bundle.manifest.environment_id,
        environment_definition_canonical_sha256=(
            bundle.manifest.environment_definition_canonical_sha256
        ),
        scenario_id=bundle.manifest.scenario_id,
        scenario_definition_canonical_sha256=(
            bundle.manifest.scenario_definition_canonical_sha256
        ),
        event_count=bundle.manifest.event_count,
        event_counts=tuple(sorted(event_counts.items())),
        host_counts=tuple(sorted(host_counts.items())),
        host_event_counts=tuple(
            (host_id, event_id, count)
            for (host_id, event_id), count in sorted(host_event_counts.items())
        ),
        event_profile_ids=bundle.manifest.event_profile_ids,
        audit_policy_ids=bundle.manifest.audit_policy_ids,
        started_at=min(occurred_at) if occurred_at else None,
        ended_at=max(occurred_at) if occurred_at else None,
    )
    return TelemetryInspection(overview=overview, events=events)


def resolve_telemetry_definition_context(
    inspection: TelemetryInspection,
    catalog: WorkflowCatalog,
) -> TelemetryDefinitionContext:
    """Compare recorded definition digests with available local definitions."""

    overview = inspection.overview
    return TelemetryDefinitionContext(
        environment=_match_environment_definition(
            overview.environment_id,
            overview.environment_definition_canonical_sha256,
            catalog.environments,
        ),
        scenario=_match_scenario_definition(
            overview.scenario_id,
            overview.scenario_definition_canonical_sha256,
            catalog.routes,
        ),
    )


def _yaml_files(root: Path) -> tuple[Path, ...]:
    if not root.exists():
        return ()
    return tuple(sorted(path.resolve() for path in root.rglob("*.yaml")))


def _telemetry_bundle_paths(output_root: Path) -> tuple[Path, ...]:
    if not output_root.exists():
        return ()

    bundles: list[Path] = []
    for manifest_path in sorted(output_root.glob("*/*/manifest.json")):
        try:
            manifest = AuthenticationTelemetryManifest.model_validate_json(
                manifest_path.read_bytes()
            )
        except (OSError, ValueError):
            continue
        bundle_path = manifest_path.parent.resolve()
        if bundle_path.name == manifest.telemetry_id:
            bundles.append(bundle_path)
    return tuple(bundles)


def _match_environment_definition(
    identifier: str,
    canonical_sha256: str,
    paths: tuple[Path, ...],
) -> DefinitionContext:
    changed_path: Path | None = None
    for path in paths:
        try:
            environment = load_environment(path)
        except (OSError, ValueError):
            continue
        if environment.id != identifier:
            continue
        if model_digest(environment) == canonical_sha256:
            return DefinitionContext(
                identifier=identifier,
                canonical_sha256=canonical_sha256,
                status=DefinitionStatus.MATCHING,
                path=path,
            )
        changed_path = changed_path or path
    return DefinitionContext(
        identifier=identifier,
        canonical_sha256=canonical_sha256,
        status=(
            DefinitionStatus.CHANGED
            if changed_path is not None
            else DefinitionStatus.UNAVAILABLE
        ),
        path=changed_path,
    )


def _match_scenario_definition(
    identifier: str,
    canonical_sha256: str,
    paths: tuple[Path, ...],
) -> DefinitionContext:
    changed_path: Path | None = None
    for path in paths:
        try:
            scenario = AuthenticationScenario.model_validate(read_yaml(path))
        except (OSError, ValueError):
            continue
        if scenario.id != identifier:
            continue
        if model_digest(scenario) == canonical_sha256:
            return DefinitionContext(
                identifier=identifier,
                canonical_sha256=canonical_sha256,
                status=DefinitionStatus.MATCHING,
                path=path,
            )
        changed_path = changed_path or path
    return DefinitionContext(
        identifier=identifier,
        canonical_sha256=canonical_sha256,
        status=(
            DefinitionStatus.CHANGED
            if changed_path is not None
            else DefinitionStatus.UNAVAILABLE
        ),
        path=changed_path,
    )


def _event_view(
    bundle_path: Path,
    record: AuthenticationArtifactRecord,
    related_ids: tuple[str, ...],
) -> TelemetryEventView:
    payload = record.event.data.model_dump(mode="json", by_alias=True)
    focused_names = _FOCUSED_FIELDS.get(record.event.event_id, tuple(payload))
    fields = tuple(
        TelemetryFieldView(
            name=name,
            value=str(payload[name]),
            origin=_field_origin(record, f"event_data.{name}"),
        )
        for name in focused_names
        if name in payload
    )
    return TelemetryEventView(
        event_instance_id=record.event_instance_id,
        occurred_at=record.event.occurred_at,
        host_id=record.host_id,
        computer=record.event.computer,
        event_id=record.event.event_id,
        source_attempt_id=record.source_attempt_id,
        target_username=str(payload.get("TargetUserName", "-")),
        status=str(payload.get("Status", "-")),
        authentication_package=str(
            payload.get("AuthenticationPackageName")
            or payload.get("PackageName")
            or _protocol_label(record.event.event_id)
        ),
        logon_type=str(payload.get("LogonType", "-")),
        xml_path=record.xml_path,
        synthetic_correlation_id=record.synthetic_correlation_id,
        related_event_instance_ids=tuple(
            event_id for event_id in related_ids if event_id != record.event_instance_id
        ),
        fields=fields,
        xml=(bundle_path / record.xml_path).read_text(encoding="utf-8"),
    )


def _field_origin(record: AuthenticationArtifactRecord, path: str) -> str:
    provenance = record.field_provenance
    for origin in ("documented", "derived", "synthetic", "unavailable"):
        if path in getattr(provenance, origin):
            return origin
    raise ValueError(f"event field {path!r} has no provenance classification")


def _protocol_label(event_id: int) -> str:
    if event_id in {4768, 4769}:
        return "Kerberos"
    if event_id == 4776:
        return "NTLM"
    return "-"

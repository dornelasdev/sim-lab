"""Deterministic artifact bundles for generated SimLab telemetry."""

import json
import shutil
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
from ipaddress import IPv4Address
from pathlib import Path
from tempfile import mkdtemp
from typing import Any, Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, Field

from simlab.authentication import AuthenticationScenario
from simlab.definition import Definition, Identifier
from simlab.environment import CorporateEnvironment
from simlab.telemetry.authentication import (
    EventFieldProvenance,
    GeneratedAuthenticationTelemetry,
    GeneratedWindowsEvent,
    generate_authentication_telemetry,
)
from simlab.telemetry.windows_security import WindowsSecurityEvent, to_event_xml

_ARTIFACT_NAMESPACE = UUID("8f992f7c-7102-5315-98e9-743d665c1f7c")


class AuthenticationArtifactRecord(Definition):
    """One self-contained JSONL record and its matching XML location."""

    schema_version: Literal[1] = 1
    event_instance_id: Identifier
    xml_path: str = Field(pattern=r"^xml/[a-zA-Z0-9.-]+\.xml$")
    source_attempt_id: Identifier
    host_id: Identifier
    synthetic_correlation_id: str
    event: WindowsSecurityEvent
    field_provenance: EventFieldProvenance


class ArtifactFileSummary(Definition):
    """Digest metadata for one bundle file."""

    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ArtifactCollectionSummary(Definition):
    """Digest metadata for an ordered collection of bundle files."""

    directory: str
    file_count: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuthenticationBundleManifest(Definition):
    """Run-wide context for a deterministic authentication artifact bundle."""

    schema_version: Literal[1] = 1
    kind: Literal["authentication_telemetry"] = "authentication_telemetry"
    bundle_id: Identifier
    environment_id: Identifier
    environment_definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_id: Identifier
    scenario_definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_count: int = Field(ge=0)
    event_profile_ids: tuple[Identifier, ...]
    audit_policy_ids: tuple[Identifier, ...]
    observability_source: Literal["host_audit_policy"]
    clock_assumption: Literal["synchronized_host_clocks"]
    timing_basis: Literal["attempt_start_plus_synthetic_event_delay"]
    jsonl: ArtifactFileSummary
    xml: ArtifactCollectionSummary


@dataclass(frozen=True)
class AuthenticationArtifactBundle:
    """Location and manifest returned after writing or reusing a bundle."""

    path: Path
    manifest: AuthenticationBundleManifest
    created: bool


def generate_authentication_bundle(
    scenario: AuthenticationScenario,
    environment: CorporateEnvironment,
    output_root: str | Path = "outputs",
) -> AuthenticationArtifactBundle:
    """Generate telemetry and write its deterministic artifact bundle."""

    if scenario.environment_id != environment.id:
        raise ValueError(
            f"scenario expects environment {scenario.environment_id!r}, not "
            f"{environment.id!r}"
        )

    telemetry = generate_authentication_telemetry(scenario, environment)
    records = _artifact_records(telemetry, scenario, environment)
    jsonl_bytes = b"".join(_canonical_json(record) + b"\n" for record in records)
    xml_files = {
        record.xml_path: to_event_xml(record.event).encode("utf-8")
        for record in records
    }
    xml_collection_digest = _collection_digest(xml_files)

    hosts = {host.id: host for host in environment.hosts}
    manifest_content = {
        "schema_version": 1,
        "kind": "authentication_telemetry",
        "environment_id": environment.id,
        "environment_definition_sha256": _model_digest(environment),
        "scenario_id": scenario.id,
        "scenario_definition_sha256": _model_digest(scenario),
        "event_count": len(records),
        "event_profile_ids": sorted({record.event.profile_id for record in records}),
        "audit_policy_ids": sorted(
            {hosts[record.host_id].audit_policy_id for record in records}
        ),
        "observability_source": telemetry.observability_source,
        "clock_assumption": telemetry.clock_assumption,
        "timing_basis": telemetry.timing_basis,
        "jsonl": {
            "path": "events.jsonl",
            "sha256": sha256(jsonl_bytes).hexdigest(),
        },
        "xml": {
            "directory": "xml",
            "file_count": len(xml_files),
            "sha256": xml_collection_digest,
        },
    }
    bundle_id = f"bundle-{sha256(_canonical_json(manifest_content)).hexdigest()}"
    manifest = AuthenticationBundleManifest(
        bundle_id=bundle_id,
        **manifest_content,
    )
    manifest_bytes = _pretty_json(manifest)
    expected_files = {
        "manifest.json": manifest_bytes,
        "events.jsonl": jsonl_bytes,
        **xml_files,
    }

    scenario_root = Path(output_root) / scenario.id
    bundle_path = scenario_root / bundle_id
    scenario_root.mkdir(parents=True, exist_ok=True)
    if bundle_path.exists():
        _verify_existing_bundle(bundle_path, expected_files)
        return AuthenticationArtifactBundle(
            path=bundle_path,
            manifest=manifest,
            created=False,
        )

    temporary_path = Path(mkdtemp(prefix=f".{bundle_id}-", dir=scenario_root))
    try:
        _write_files(temporary_path, expected_files)
        temporary_path.rename(bundle_path)
    except Exception:
        if temporary_path.exists():
            shutil.rmtree(temporary_path)
        if bundle_path.exists():
            _verify_existing_bundle(bundle_path, expected_files)
            return AuthenticationArtifactBundle(
                path=bundle_path,
                manifest=manifest,
                created=False,
            )
        raise

    return AuthenticationArtifactBundle(
        path=bundle_path,
        manifest=manifest,
        created=True,
    )


def _artifact_records(
    telemetry: GeneratedAuthenticationTelemetry,
    scenario: AuthenticationScenario,
    environment: CorporateEnvironment,
) -> list[AuthenticationArtifactRecord]:
    occurrences: Counter[tuple[str, str, int]] = Counter()
    records: list[AuthenticationArtifactRecord] = []

    for sequence, generated in enumerate(telemetry.events, start=1):
        occurrence_key = (
            generated.source_attempt_id,
            generated.host_id,
            generated.event.event_id,
        )
        occurrences[occurrence_key] += 1
        instance_id = _event_instance_id(
            environment_id=environment.id,
            scenario_id=scenario.id,
            generated=generated,
            occurrence=occurrences[occurrence_key],
        )
        xml_path = (
            f"xml/{sequence:06d}-{generated.host_id}-"
            f"{generated.event.record_id}-{generated.event.event_id}-"
            f"{instance_id}.xml"
        )
        records.append(
            AuthenticationArtifactRecord(
                event_instance_id=instance_id,
                xml_path=xml_path,
                source_attempt_id=generated.source_attempt_id,
                host_id=generated.host_id,
                synthetic_correlation_id=generated.synthetic_correlation_id,
                event=generated.event,
                field_provenance=generated.field_provenance,
            )
        )

    return records


def _event_instance_id(
    *,
    environment_id: str,
    scenario_id: str,
    generated: GeneratedWindowsEvent,
    occurrence: int,
) -> str:
    identity = ":".join(
        (
            environment_id,
            scenario_id,
            generated.source_attempt_id,
            generated.host_id,
            str(generated.event.event_id),
            str(occurrence),
        )
    )
    return f"event-{uuid5(_ARTIFACT_NAMESPACE, identity)}"


def _write_files(root: Path, files: dict[str, bytes]) -> None:
    for relative_path, content in files.items():
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)


def _verify_existing_bundle(root: Path, expected: dict[str, bytes]) -> None:
    if not root.is_dir():
        raise FileExistsError(f"bundle path exists but is not a directory: {root}")

    actual = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    if actual != expected:
        raise FileExistsError(
            f"bundle path exists with content that does not match its ID: {root}"
        )


def _collection_digest(files: dict[str, bytes]) -> str:
    entries = [
        {"path": path, "sha256": sha256(content).hexdigest()}
        for path, content in sorted(files.items())
    ]
    return sha256(_canonical_json(entries)).hexdigest()


def _model_digest(model: BaseModel) -> str:
    return sha256(_canonical_json(model)).hexdigest()


def _canonical_json(value: Any) -> bytes:
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    normalized = _normalize(value)
    return (
        json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return {
            field.serialization_alias or name: _normalize(getattr(value, name))
            for name, field in type(value).model_fields.items()
        }
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=_canonical_json)
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (IPv4Address, Path)):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    return value

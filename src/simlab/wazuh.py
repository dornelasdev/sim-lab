"""Deterministic Wazuh replay exports derived from SimLab telemetry."""

import json
from datetime import UTC
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid5

from pydantic import Field

from simlab.artifacts import (
    ArtifactFileReference,
    AuthenticationArtifactRecord,
    load_authentication_bundle,
)
from simlab.definition import Definition, Identifier
from simlab.storage import (
    canonical_json,
    content_address,
    pretty_json,
    sha256sums,
    write_verified_directory,
)
from simlab.telemetry.windows_security import Event4625Data, Event4776Data

WAZUH_ADAPTER_ID = "wazuh-windows-eventchannel-v1"
WAZUH_MANAGER_VERSION = "4.14.7"
SUPPORTED_EVENT_IDS = (4625, 4776)
_REPLAY_NAMESPACE = UUID("58ac94bf-52e4-555a-9448-99758be1edb8")


class WazuhReplayProvenance(Definition):
    """Trace one Wazuh input line back to its source telemetry event."""

    schema_version: Literal[1] = 1
    line_number: int = Field(gt=0)
    replay_record_id: Identifier
    source_event_instance_id: Identifier
    source_host_id: Identifier
    source_event_id: Literal[4625, 4776]
    adapter_id: Literal["wazuh-windows-eventchannel-v1"] = WAZUH_ADAPTER_ID
    value_origin: Literal["derived"] = "derived"
    representation_basis: Literal["simlab_typed_windows_security_event"] = (
        "simlab_typed_windows_security_event"
    )


class WazuhReplayManifest(Definition):
    """Identity, compatibility context, and files for one Wazuh export."""

    schema_version: Literal[1] = 1
    kind: Literal["wazuh_replay"] = "wazuh_replay"
    replay_id: Identifier
    source_telemetry_id: Identifier
    source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    adapter_id: Literal["wazuh-windows-eventchannel-v1"] = WAZUH_ADAPTER_ID
    wazuh_manager_version: Literal["4.14.7"] = WAZUH_MANAGER_VERSION
    representation_status: Literal["derived_pending_observed_fixture"] = (
        "derived_pending_observed_fixture"
    )
    intended_validation_mode: Literal["wazuh_logtest"] = "wazuh_logtest"
    correlation_time_basis: Literal["manager_ingestion_time"] = "manager_ingestion_time"
    supported_event_ids: tuple[Literal[4625, 4776], ...]
    source_event_count: int = Field(ge=0)
    exported_event_count: int = Field(ge=0)
    omitted_event_count: int = Field(ge=0)
    events: ArtifactFileReference
    provenance: ArtifactFileReference
    limitations: tuple[str, ...] = Field(min_length=1)


class WazuhReplayBundle(Definition):
    """Location and manifest returned after writing or reusing an export."""

    path: Path
    manifest: WazuhReplayManifest
    created: bool


class LoadedWazuhReplayBundle(Definition):
    """An integrity-checked Wazuh replay bundle."""

    path: Path
    manifest: WazuhReplayManifest
    events: tuple[dict[str, Any], ...]
    provenance: tuple[WazuhReplayProvenance, ...]


def export_wazuh_replay(
    telemetry_path: str | Path,
    output_root: str | Path = "outputs/wazuh",
) -> WazuhReplayBundle:
    """Export supported telemetry as Wazuh EventChannel input records."""

    bundle = load_authentication_bundle(telemetry_path)
    supported_records = tuple(
        record
        for record in bundle.records
        if record.event.event_id in SUPPORTED_EVENT_IDS
    )
    replay_events = tuple(_wazuh_event(record) for record in supported_records)
    provenance = tuple(
        _provenance_record(bundle.manifest.telemetry_id, line_number, record)
        for line_number, record in enumerate(supported_records, start=1)
    )
    events_bytes = b"".join(canonical_json(event) + b"\n" for event in replay_events)
    provenance_bytes = b"".join(canonical_json(record) + b"\n" for record in provenance)
    manifest_content = {
        "schema_version": 1,
        "kind": "wazuh_replay",
        "source_telemetry_id": bundle.manifest.telemetry_id,
        "source_manifest_sha256": sha256(
            (bundle.path / "manifest.json").read_bytes()
        ).hexdigest(),
        "adapter_id": WAZUH_ADAPTER_ID,
        "wazuh_manager_version": WAZUH_MANAGER_VERSION,
        "representation_status": "derived_pending_observed_fixture",
        "intended_validation_mode": "wazuh_logtest",
        "correlation_time_basis": "manager_ingestion_time",
        "supported_event_ids": SUPPORTED_EVENT_IDS,
        "source_event_count": len(bundle.records),
        "exported_event_count": len(replay_events),
        "omitted_event_count": len(bundle.records) - len(replay_events),
        "events": {"path": "events.jsonl"},
        "provenance": {"path": "provenance.jsonl"},
        "limitations": (
            "The EventChannel envelope is derived and has not yet been compared "
            "with a sanitized Wazuh-agent capture.",
            "Rendered Windows message text and Wazuh transport metadata are omitted; "
            "rules consume structured Windows fields.",
            "Wazuh evaluates frequency windows using manager ingestion time rather "
            "than the embedded Windows event timestamp.",
        ),
    }
    content_files = {
        "events.jsonl": events_bytes,
        "provenance.jsonl": provenance_bytes,
    }
    replay_id = content_address("wazuh-replay", manifest_content, content_files)
    manifest = WazuhReplayManifest(replay_id=replay_id, **manifest_content)
    checksummed_files = {
        "manifest.json": pretty_json(manifest),
        **content_files,
    }
    expected_files = {
        **checksummed_files,
        "SHA256SUMS": sha256sums(checksummed_files),
    }
    replay_path = Path(output_root) / bundle.manifest.telemetry_id / replay_id
    created = write_verified_directory(replay_path, expected_files)
    return WazuhReplayBundle(path=replay_path, manifest=manifest, created=created)


def load_wazuh_replay_bundle(path: str | Path) -> LoadedWazuhReplayBundle:
    """Integrity-check and load a Wazuh replay export."""

    replay_path = Path(path)
    manifest_bytes = (replay_path / "manifest.json").read_bytes()
    manifest = WazuhReplayManifest.model_validate_json(manifest_bytes)
    if replay_path.name != manifest.replay_id:
        raise ValueError("Wazuh replay directory does not match its manifest ID")
    if replay_path.parent.name != manifest.source_telemetry_id:
        raise ValueError("Wazuh replay parent does not match its source telemetry ID")
    if manifest.events.path != "events.jsonl":
        raise ValueError("Wazuh replay events path must be 'events.jsonl'")
    if manifest.provenance.path != "provenance.jsonl":
        raise ValueError("Wazuh replay provenance path must be 'provenance.jsonl'")

    events_bytes = (replay_path / manifest.events.path).read_bytes()
    provenance_bytes = (replay_path / manifest.provenance.path).read_bytes()
    events = tuple(
        _decode_json_object(line) for line in events_bytes.splitlines() if line
    )
    provenance = tuple(
        WazuhReplayProvenance.model_validate_json(line)
        for line in provenance_bytes.splitlines()
        if line
    )
    if len(events) != manifest.exported_event_count:
        raise ValueError("events.jsonl count does not match its Wazuh replay manifest")
    if len(provenance) != manifest.exported_event_count:
        raise ValueError(
            "provenance.jsonl count does not match its Wazuh replay manifest"
        )
    if tuple(record.line_number for record in provenance) != tuple(
        range(1, len(events) + 1)
    ):
        raise ValueError("Wazuh replay provenance line numbers are not contiguous")

    manifest_content = manifest.model_dump(exclude={"replay_id"})
    expected_replay_id = content_address(
        "wazuh-replay",
        manifest_content,
        {"events.jsonl": events_bytes, "provenance.jsonl": provenance_bytes},
    )
    if manifest.replay_id != expected_replay_id:
        raise ValueError("Wazuh replay content does not match its replay ID")

    checksummed_files = {
        "manifest.json": manifest_bytes,
        "events.jsonl": events_bytes,
        "provenance.jsonl": provenance_bytes,
    }
    expected_files = {
        **checksummed_files,
        "SHA256SUMS": sha256sums(checksummed_files),
    }
    actual_files = {
        file.relative_to(replay_path).as_posix()
        for file in replay_path.rglob("*")
        if file.is_file()
    }
    if actual_files != set(expected_files):
        raise ValueError("Wazuh replay bundle contains unexpected or missing files")
    if (replay_path / "SHA256SUMS").read_bytes() != expected_files["SHA256SUMS"]:
        raise ValueError("Wazuh replay bundle contains invalid checksums")

    return LoadedWazuhReplayBundle(
        path=replay_path,
        manifest=manifest,
        events=events,
        provenance=provenance,
    )


def _wazuh_event(record: AuthenticationArtifactRecord) -> dict[str, Any]:
    event = record.event
    if not isinstance(event.data, (Event4625Data, Event4776Data)):
        raise ValueError(f"event {event.event_id} has no Wazuh replay mapping")

    system = {
        "providerName": event.provider_name,
        "providerGuid": event.provider_guid,
        "eventID": str(event.event_id),
        "version": str(event.version),
        "level": str(event.level),
        "task": str(event.task),
        "opcode": str(event.opcode),
        "keywords": event.keywords,
        "systemTime": event.occurred_at.astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "eventRecordID": str(event.record_id),
        "processID": str(event.process_id),
        "threadID": str(event.thread_id),
        "channel": event.channel,
        "computer": event.computer,
        "severityValue": "AUDIT_FAILURE",
    }
    if event.correlation_activity_id is not None:
        system["activityID"] = event.correlation_activity_id

    event_data = {
        _lower_initial(name): value
        for name, value in event.data.model_dump(mode="json", by_alias=True).items()
    }
    return {"win": {"system": system, "eventdata": event_data}}


def _provenance_record(
    telemetry_id: str,
    line_number: int,
    record: AuthenticationArtifactRecord,
) -> WazuhReplayProvenance:
    identity = ":".join((telemetry_id, record.event_instance_id, str(line_number)))
    return WazuhReplayProvenance(
        line_number=line_number,
        replay_record_id=f"wazuh-record-{uuid5(_REPLAY_NAMESPACE, identity)}",
        source_event_instance_id=record.event_instance_id,
        source_host_id=record.host_id,
        source_event_id=record.event.event_id,
    )


def _lower_initial(value: str) -> str:
    return value[:1].lower() + value[1:]


def _decode_json_object(value: bytes) -> dict[str, Any]:
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise ValueError("Wazuh replay line must contain a JSON object")
    return decoded

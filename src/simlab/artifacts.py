"""Deterministic artifact bundles for generated SimLab telemetry."""

from collections import Counter
from ipaddress import IPv4Address
from pathlib import Path
from typing import Literal, Self
from uuid import UUID, uuid5

from pydantic import Field, model_validator

from simlab.authentication import AuthenticationScenario
from simlab.definition import Definition, Identifier
from simlab.environment import CorporateEnvironment
from simlab.storage import (
    canonical_json,
    content_address,
    model_digest,
    pretty_json,
    sha256sums,
    write_verified_directory,
)
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


class ArtifactFileReference(Definition):
    """Location of one file within an artifact bundle."""

    path: str


class ArtifactCollectionReference(Definition):
    """Location and size of a file collection within an artifact bundle."""

    directory: str
    file_count: int = Field(ge=0)


class HostAliasSnapshot(Definition):
    """Derived hostname and address aliases used for source resolution."""

    host_id: Identifier
    hostname: str = Field(min_length=1)
    ipv4_addresses: tuple[IPv4Address, ...] = Field(min_length=1)


class AuthenticationTelemetryManifest(Definition):
    """Run-wide context for a deterministic authentication artifact bundle."""

    schema_version: Literal[2] = 2
    kind: Literal["authentication_telemetry"] = "authentication_telemetry"
    telemetry_id: Identifier
    environment_id: Identifier
    environment_definition_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_id: Identifier
    scenario_definition_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_count: int = Field(ge=0)
    event_profile_ids: tuple[Identifier, ...]
    audit_policy_ids: tuple[Identifier, ...]
    source_alias_context: Literal["derived_environment_snapshot"]
    source_host_aliases: tuple[HostAliasSnapshot, ...]
    observability_source: Literal["host_audit_policy"]
    clock_assumption: Literal["synchronized_host_clocks"]
    timing_basis: Literal["attempt_start_plus_synthetic_event_delay"]
    jsonl: ArtifactFileReference
    xml: ArtifactCollectionReference

    @model_validator(mode="after")
    def validate_source_aliases(self) -> Self:
        """Require fixed artifact paths and unambiguous source aliases."""

        if self.jsonl.path != "events.jsonl":
            raise ValueError("authentication JSONL path must be 'events.jsonl'")
        if self.xml.directory != "xml":
            raise ValueError("authentication XML directory must be 'xml'")

        host_ids = [alias.host_id for alias in self.source_host_aliases]
        hostnames = [alias.hostname.casefold() for alias in self.source_host_aliases]
        addresses = [
            address
            for alias in self.source_host_aliases
            for address in alias.ipv4_addresses
        ]
        if len(host_ids) != len(set(host_ids)):
            raise ValueError("source alias host IDs must be unique")
        if len(hostnames) != len(set(hostnames)):
            raise ValueError("source alias hostnames must be unique")
        if len(addresses) != len(set(addresses)):
            raise ValueError("source alias IP addresses must be unique")
        return self


class AuthenticationArtifactBundle(Definition):
    """Location and manifest returned after writing or reusing a bundle."""

    path: Path
    manifest: AuthenticationTelemetryManifest
    created: bool


class LoadedAuthenticationBundle(Definition):
    """An integrity-checked telemetry bundle ready for analysis."""

    path: Path
    manifest: AuthenticationTelemetryManifest
    records: tuple[AuthenticationArtifactRecord, ...]


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
    source_aliases = _source_host_aliases(scenario, environment)
    jsonl_bytes = b"".join(canonical_json(record) + b"\n" for record in records)
    xml_files = {
        record.xml_path: to_event_xml(record.event).encode("utf-8")
        for record in records
    }
    hosts = {host.id: host for host in environment.hosts}
    manifest_content = {
        "schema_version": 2,
        "kind": "authentication_telemetry",
        "environment_id": environment.id,
        "environment_definition_canonical_sha256": model_digest(environment),
        "scenario_id": scenario.id,
        "scenario_definition_canonical_sha256": model_digest(scenario),
        "event_count": len(records),
        "event_profile_ids": sorted({record.event.profile_id for record in records}),
        "audit_policy_ids": sorted(
            {hosts[record.host_id].audit_policy_id for record in records}
        ),
        "source_alias_context": "derived_environment_snapshot",
        "source_host_aliases": source_aliases,
        "observability_source": telemetry.observability_source,
        "clock_assumption": telemetry.clock_assumption,
        "timing_basis": telemetry.timing_basis,
        "jsonl": {
            "path": "events.jsonl",
        },
        "xml": {
            "directory": "xml",
            "file_count": len(xml_files),
        },
    }
    content_files = {
        "events.jsonl": jsonl_bytes,
        **xml_files,
    }
    telemetry_id = content_address("telemetry", manifest_content, content_files)
    manifest = AuthenticationTelemetryManifest(
        telemetry_id=telemetry_id,
        **manifest_content,
    )
    manifest_bytes = pretty_json(manifest)
    checksummed_files = {
        "manifest.json": manifest_bytes,
        **content_files,
    }
    expected_files = {
        **checksummed_files,
        "SHA256SUMS": sha256sums(checksummed_files),
    }

    bundle_path = Path(output_root) / scenario.id / telemetry_id
    created = write_verified_directory(bundle_path, expected_files)

    return AuthenticationArtifactBundle(
        path=bundle_path,
        manifest=manifest,
        created=created,
    )


def load_authentication_bundle(path: str | Path) -> LoadedAuthenticationBundle:
    """Load a telemetry bundle and verify its identity and stored artifacts."""

    bundle_path = Path(path)
    manifest_path = bundle_path / "manifest.json"
    events_path = bundle_path / "events.jsonl"
    manifest_bytes = manifest_path.read_bytes()
    manifest = AuthenticationTelemetryManifest.model_validate_json(manifest_bytes)

    if bundle_path.name != manifest.telemetry_id:
        raise ValueError(
            f"telemetry directory {bundle_path.name!r} does not match manifest ID "
            f"{manifest.telemetry_id!r}"
        )

    jsonl_bytes = events_path.read_bytes()
    records = tuple(
        AuthenticationArtifactRecord.model_validate_json(line)
        for line in jsonl_bytes.splitlines()
        if line
    )
    if len(records) != manifest.event_count:
        raise ValueError("events.jsonl count does not match its manifest")
    if len({record.event_instance_id for record in records}) != len(records):
        raise ValueError("events.jsonl contains duplicate event-instance IDs")
    if len({record.xml_path for record in records}) != len(records):
        raise ValueError("events.jsonl contains duplicate XML paths")

    xml_files = {
        record.xml_path: (bundle_path / record.xml_path).read_bytes()
        for record in records
    }
    if len(xml_files) != manifest.xml.file_count:
        raise ValueError("XML file count does not match its manifest")
    for record in records:
        expected_xml = to_event_xml(record.event).encode("utf-8")
        if xml_files[record.xml_path] != expected_xml:
            raise ValueError(f"XML file does not match JSONL event: {record.xml_path}")

    content_files = {
        "events.jsonl": jsonl_bytes,
        **xml_files,
    }
    manifest_content = manifest.model_dump(exclude={"telemetry_id"})
    expected_telemetry_id = content_address(
        "telemetry",
        manifest_content,
        content_files,
    )
    if manifest.telemetry_id != expected_telemetry_id:
        raise ValueError("telemetry content does not match its telemetry ID")

    checksummed_files = {
        "manifest.json": manifest_bytes,
        **content_files,
    }
    expected_files = {
        **checksummed_files,
        "SHA256SUMS": sha256sums(checksummed_files),
    }
    actual_files = {
        file.relative_to(bundle_path).as_posix()
        for file in bundle_path.rglob("*")
        if file.is_file()
    }
    if actual_files != set(expected_files):
        raise ValueError(
            "telemetry bundle contains invalid checksums or unexpected files"
        )
    if (bundle_path / "SHA256SUMS").read_bytes() != expected_files["SHA256SUMS"]:
        raise ValueError("telemetry bundle contains invalid checksums")

    return LoadedAuthenticationBundle(
        path=bundle_path,
        manifest=manifest,
        records=records,
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


def _source_host_aliases(
    scenario: AuthenticationScenario,
    environment: CorporateEnvironment,
) -> tuple[HostAliasSnapshot, ...]:
    """Capture only aliases required to resolve this scenario's event sources."""

    source_host_ids = sorted({attempt.source_host_id for attempt in scenario.attempts})
    hosts = {host.id: host for host in environment.hosts}
    aliases: list[HostAliasSnapshot] = []

    for source_host_id in source_host_ids:
        source = hosts[source_host_id]
        hostname_matches = [
            host.id
            for host in environment.hosts
            if host.hostname.casefold() == source.hostname.casefold()
        ]
        if len(hostname_matches) != 1:
            raise ValueError(
                f"source hostname {source.hostname!r} is ambiguous in the environment"
            )

        address_matches = [
            host.id
            for host in environment.hosts
            if host.ipv4_address == source.ipv4_address
        ]
        if len(address_matches) != 1:
            raise ValueError(
                f"source address {source.ipv4_address} is ambiguous in the environment"
            )

        aliases.append(
            HostAliasSnapshot(
                host_id=source.id,
                hostname=source.hostname,
                ipv4_addresses=(source.ipv4_address,),
            )
        )

    return tuple(aliases)


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

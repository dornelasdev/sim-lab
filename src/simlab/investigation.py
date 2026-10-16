"""Prepare the first investigation's evidence independently of its interface."""

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid5

from pydantic import AwareDatetime, Field

from simlab.authentication import AuthenticationScenario
from simlab.definition import Definition, Identifier, read_yaml
from simlab.environment import CorporateEnvironment, load_environment
from simlab.storage import (
    canonical_json,
    content_address,
    pretty_json,
    sha256sums,
    verify_directory,
    write_verified_directory,
)
from simlab.telemetry.authentication import (
    EventFieldProvenance,
    generate_authentication_telemetry,
)
from simlab.telemetry.windows_security import WindowsSecurityEvent

_CASE_NAMESPACE = UUID("5a40ba31-b510-5594-9e0f-5a16c267a88f")


class InvestigationEvidence(Definition):
    """Windows evidence and provenance without scenario-author answers."""

    event_instance_id: Identifier
    host_id: Identifier
    event: WindowsSecurityEvent
    field_provenance: EventFieldProvenance


class InvestigationCaseManifest(Definition):
    """Evidence identity and the boundary of the supplied investigation data."""

    schema_version: Literal[1] = 1
    case_id: Identifier
    exercise_id: Literal["password-spray"] = "password-spray"
    title: str = "Suspected multi-account authentication attack"
    environment_id: Identifier
    event_count: int = Field(gt=0)
    evidence_started_at: AwareDatetime
    evidence_ended_at: AwareDatetime
    coverage_basis: Literal["modeled_activity_only_not_complete_host_audit_capture"] = (
        "modeled_activity_only_not_complete_host_audit_capture"
    )
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class InvestigationCase:
    """One reproducible case, ready for actual Wazuh evaluation."""

    path: Path
    manifest: InvestigationCaseManifest
    environment: CorporateEnvironment
    evidence: tuple[InvestigationEvidence, ...]


def prepare_password_spray_evidence(
    project_root: str | Path,
    output_root: str | Path,
) -> InvestigationCase:
    """Assemble the agreed fifteen-event case with host-wide record ordering."""

    root = Path(project_root).resolve()
    environment = load_environment(root / "environments" / "corp-lab.yaml")
    route_root = root / "routes" / "ad-authentication"
    sections = (
        ("repeated-password-failure.yaml", "case-earlier-failures", 10, None),
        ("normal.yaml", "case-interactive-context", 12, "bob"),
        ("password-spray.yaml", "case-spray-window", 15, None),
    )
    generated = []
    for route_name, scenario_id, minute, identity in sections:
        definition = read_yaml(route_root / route_name)
        definition["id"] = scenario_id
        definition["start_at"] = datetime(2026, 9, 14, 9, minute, tzinfo=UTC)
        if identity is not None:
            definition["attempts"][0]["identity_id"] = identity
        scenario = AuthenticationScenario.model_validate(definition)
        generated.extend(
            (scenario.id, event)
            for event in generate_authentication_telemetry(scenario, environment).events
        )

    generated.sort(key=lambda item: (item[1].event.occurred_at, item[1].host_id))
    if len(generated) != 15:
        raise ValueError(
            "the first investigation requires its agreed 15-event evidence"
        )
    record_ids: Counter[str] = Counter()
    evidence: list[InvestigationEvidence] = []
    author_context = []
    for scenario_id, item in generated:
        record_ids[item.host_id] += 1
        event = item.event.model_copy(
            update={"record_id": 1000 + record_ids[item.host_id]}
        )
        identity = uuid5(_CASE_NAMESPACE, canonical_json(event).decode())
        instance_id = f"evidence-{identity}"
        evidence.append(
            InvestigationEvidence(
                event_instance_id=instance_id,
                host_id=item.host_id,
                event=event,
                field_provenance=item.field_provenance,
            )
        )
        author_context.append(
            {
                "event_instance_id": instance_id,
                "scenario_id": scenario_id,
                "source_attempt_id": item.source_attempt_id,
                "synthetic_correlation_id": item.synthetic_correlation_id,
            }
        )

    metadata = {
        "schema_version": 1,
        "exercise_id": "password-spray",
        "title": "Suspected multi-account authentication attack",
        "environment_id": environment.id,
        "event_count": len(evidence),
        "evidence_started_at": evidence[0].event.occurred_at,
        "evidence_ended_at": evidence[-1].event.occurred_at,
        "coverage_basis": "modeled_activity_only_not_complete_host_audit_capture",
        "limitations": (
            "Evidence represents selected modeled activity, not complete host logs.",
            "Later authentication and source process activity are unavailable.",
            "Account names do not establish the human operator or password reuse.",
        ),
    }
    content = {
        "events.jsonl": b"".join(canonical_json(item) + b"\n" for item in evidence),
        "environment.json": pretty_json(environment),
        "author-context.json": pretty_json(author_context),
    }
    case_id = content_address("case", metadata, content)
    manifest = InvestigationCaseManifest(case_id=case_id, **metadata)
    files = {"manifest.json": pretty_json(manifest), **content}
    path = Path(output_root).resolve() / "cases" / "password-spray" / case_id
    write_verified_directory(path, {**files, "SHA256SUMS": sha256sums(files)})
    return InvestigationCase(path, manifest, environment, tuple(evidence))


def failure_evaluation_windows(
    case: InvestigationCase,
) -> tuple[tuple[InvestigationEvidence, ...], ...]:
    """Separate historical failure sequences whose gaps exceed the rule window."""

    windows: list[list[InvestigationEvidence]] = []
    for item in case.evidence:
        if item.event.event_id not in {4625, 4776}:
            continue
        if not windows or (
            item.event.occurred_at - windows[-1][-1].event.occurred_at
            > timedelta(seconds=60)
        ):
            windows.append([])
        windows[-1].append(item)
    for window in windows:
        if window[-1].event.occurred_at - window[0].event.occurred_at > timedelta(
            seconds=60
        ):
            raise ValueError("compressed evaluation cannot represent a window over 60s")
    return tuple(tuple(window) for window in windows)


def load_investigation_case(path: str | Path) -> InvestigationCase:
    """Verify saved evidence before presenting it in an analyst workspace."""

    root = Path(path)
    files = {
        name: (root / name).read_bytes()
        for name in (
            "manifest.json",
            "events.jsonl",
            "environment.json",
            "author-context.json",
        )
    }
    manifest = InvestigationCaseManifest.model_validate_json(files["manifest.json"])
    metadata = manifest.model_dump(exclude={"case_id"})
    content = {name: data for name, data in files.items() if name != "manifest.json"}
    if (
        root.name != manifest.case_id
        or content_address("case", metadata, content) != manifest.case_id
    ):
        raise ValueError("case identity does not match its saved evidence")
    verify_directory(root, {**files, "SHA256SUMS": sha256sums(files)})
    environment = CorporateEnvironment.model_validate_json(files["environment.json"])
    evidence = tuple(
        InvestigationEvidence.model_validate_json(line)
        for line in files["events.jsonl"].splitlines()
        if line
    )
    if (
        environment.id != manifest.environment_id
        or len(evidence) != manifest.event_count
    ):
        raise ValueError(
            "case environment or evidence count does not match its manifest"
        )
    if len({item.event_instance_id for item in evidence}) != len(evidence):
        raise ValueError("case contains duplicate event references")
    times = tuple(item.event.occurred_at for item in evidence)
    if (
        not times
        or times != tuple(sorted(times))
        or (
            times[0] != manifest.evidence_started_at
            or times[-1] != manifest.evidence_ended_at
        )
    ):
        raise ValueError("case event times do not match its recorded range")
    known_hosts = {host.id for host in environment.hosts}
    if any(item.host_id not in known_hosts for item in evidence):
        raise ValueError("case evidence refers to an unknown inventory host")
    return InvestigationCase(root, manifest, environment, evidence)


def evidence_account(item: InvestigationEvidence) -> str:
    """Normalize the account for filtering while preserving the raw event elsewhere."""

    return item.event.data.target_user_name.split("@", 1)[0]


def evidence_source_ip(
    case: InvestigationCase, item: InvestigationEvidence
) -> tuple[str, bool]:
    """Return an event address or an explicitly derived inventory lookup."""

    data = item.event.data
    address = getattr(data, "ip_address", "-")
    if address not in {"", "-"}:
        parsed = ip_address(address)
        return str(getattr(parsed, "ipv4_mapped", None) or parsed), False
    workstation = getattr(data, "workstation", None) or getattr(
        data, "workstation_name", ""
    )
    for host in case.environment.hosts:
        if host.hostname.casefold() == workstation.casefold():
            return str(host.ipv4_address), True
    return "", False


def parse_investigation_time(value: str, case: InvestigationCase) -> datetime | None:
    """Accept UTC clock times on the case date, or an explicit ISO datetime."""

    if not value.strip():
        return None
    value = value.strip()
    try:
        if "T" in value or " " in value:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            day = case.manifest.evidence_started_at.astimezone(UTC).date()
            parsed = datetime.fromisoformat(f"{day.isoformat()}T{value}")
    except ValueError as error:
        raise ValueError(
            "Use UTC HH:MM[:SS] or an ISO datetime for time filters."
        ) from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def filter_investigation_evidence(
    case: InvestigationCase,
    *,
    account: str = "",
    host: str = "",
    source_ip: str = "",
    event_id: int | None = None,
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
    references: set[str] | None = None,
) -> tuple[InvestigationEvidence, ...]:
    """Filter event evidence without modifying it or consulting author context."""

    if started_at is not None and ended_at is not None and started_at > ended_at:
        raise ValueError("From must be earlier than or equal to To.")
    source = ""
    if source_ip.strip():
        parsed = ip_address(source_ip.strip())
        source = str(getattr(parsed, "ipv4_mapped", None) or parsed)
    return tuple(
        item
        for item in case.evidence
        if (
            not account.strip()
            or account.strip().casefold() in evidence_account(item).casefold()
        )
        and (
            not host.strip()
            or host.strip().casefold() in item.event.computer.casefold()
            or host.strip().casefold() == item.host_id.casefold()
        )
        and (not source or evidence_source_ip(case, item)[0] == source)
        and (event_id is None or item.event.event_id == event_id)
        and (started_at is None or item.event.occurred_at >= started_at)
        and (ended_at is None or item.event.occurred_at <= ended_at)
        and (references is None or item.event_instance_id in references)
    )

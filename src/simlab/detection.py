"""Reference authentication detection over verified telemetry bundles."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID, uuid5

from pydantic import AwareDatetime, Field, StringConstraints

from simlab.artifacts import (
    AuthenticationArtifactRecord,
    HostAliasSnapshot,
    LoadedAuthenticationBundle,
)
from simlab.definition import Definition, Identifier, read_yaml
from simlab.storage import canonical_json
from simlab.telemetry.windows_security import Event4625Data, Event4776Data

_DETECTION_NAMESPACE = UUID("19acddd3-dfc4-5596-a9c2-5cdbe203a0e8")
AttackTechniqueId = Annotated[
    str,
    StringConstraints(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$"),
]


class FindingSeverity(StrEnum):
    """Analyst-facing impact level supported by the baseline detector."""

    MEDIUM = "medium"


class FindingConfidence(StrEnum):
    """Strength of the observable evidence supporting a finding."""

    MEDIUM = "medium"
    HIGH = "high"


class SignalType(StrEnum):
    """Independent Windows observations used by password-spray detection."""

    DOMAIN_CREDENTIAL_VALIDATION = "domain_credential_validation"
    DESTINATION_LOGON = "destination_logon"


class DomainCredentialValidationDefinition(Definition):
    """Qualifying bad-password NTLM validation on the domain controller."""

    event_id: Literal[4776]
    status: Literal["0xC000006A"]


class DestinationLogonDefinition(Definition):
    """Qualifying failed NTLM network logon on the destination system."""

    event_id: Literal[4625]
    status: Literal["0xC000006D"]
    sub_status: Literal["0xC000006A"]
    logon_type: Literal["3"]
    authentication_package: Literal["NTLM"]


class PasswordSpraySignalDefinitions(Definition):
    """The two independent Windows event patterns in this profile."""

    domain_credential_validation: DomainCredentialValidationDefinition
    destination_logon: DestinationLogonDefinition


class PasswordSprayDetectionProfile(Definition):
    """Versioned, intentionally narrow password-spray detection policy."""

    schema_version: Literal[1]
    kind: Literal["password_spray"]
    id: Identifier
    name: str = Field(min_length=1)
    finding_type: Literal["suspected_password_spray"]
    minimum_distinct_users: int = Field(ge=2)
    window_seconds: int = Field(gt=0)
    window_mode: Literal["sliding"]
    severity: Literal["medium"]
    single_signal_confidence: Literal["medium"]
    multiple_signal_confidence: Literal["high"]
    mitre_attack_ids: tuple[AttackTechniqueId, ...] = Field(min_length=1)
    merge_strategy: Literal["resolved_source_time_and_users"]
    evidence_basis: Literal["behavioral_pattern"]
    limitations: tuple[str, ...] = Field(min_length=1)
    signals: PasswordSpraySignalDefinitions


class DetectionSignalMatch(Definition):
    """One independently qualifying event pattern over a time window."""

    signal_id: Identifier
    signal_type: SignalType
    source_host_id: Identifier | None
    observed_sources: tuple[str, ...] = Field(min_length=1)
    destination_host_id: Identifier | None
    started_at: AwareDatetime
    ended_at: AwareDatetime
    target_usernames: tuple[str, ...] = Field(min_length=1)
    event_instance_ids: tuple[Identifier, ...] = Field(min_length=1)


class AuthenticationFinding(Definition):
    """Analyst-facing hypothesis produced from one or both event signals."""

    schema_version: Literal[1] = 1
    finding_id: Identifier
    finding_type: Literal["suspected_password_spray"]
    title: str = Field(min_length=1)
    severity: FindingSeverity
    confidence: FindingConfidence
    mitre_attack_ids: tuple[AttackTechniqueId, ...] = Field(min_length=1)
    evidence_basis: Literal["behavioral_pattern"]
    source_host_id: Identifier | None
    started_at: AwareDatetime
    ended_at: AwareDatetime
    target_usernames: tuple[str, ...] = Field(min_length=1)
    signals: tuple[DetectionSignalMatch, ...] = Field(min_length=1)
    event_instance_ids: tuple[Identifier, ...] = Field(min_length=1)
    limitations: tuple[str, ...] = Field(min_length=1)


class AuthenticationDetectionResult(Definition):
    """Deterministic findings for one bundle and one detection profile."""

    source_telemetry_id: Identifier
    profile_id: Identifier
    findings: tuple[AuthenticationFinding, ...]


@dataclass(frozen=True)
class _Observation:
    occurred_at: datetime
    username: str
    username_key: str
    observed_source: str
    event_instance_id: str


@dataclass(frozen=True)
class _SignalGroup:
    signal_type: SignalType
    source_host_id: str | None
    destination_host_id: str | None
    observations: tuple[_Observation, ...]


def load_password_spray_profile(
    path: str | Path,
) -> PasswordSprayDetectionProfile:
    """Load a versioned password-spray profile from YAML."""

    return PasswordSprayDetectionProfile.model_validate(read_yaml(path))


def detect_authentication_password_spray(
    bundle: LoadedAuthenticationBundle,
    profile: PasswordSprayDetectionProfile,
) -> AuthenticationDetectionResult:
    """Detect spray-like failures without using simulation ground truth."""

    hostname_aliases, address_aliases = _alias_maps(bundle.manifest.source_host_aliases)
    groups = [
        *_credential_validation_groups(bundle.records, profile, hostname_aliases),
        *_destination_logon_groups(bundle.records, profile, address_aliases),
    ]
    matches = [
        match
        for group in groups
        for match in _qualifying_matches(
            group,
            bundle.manifest.telemetry_id,
            profile,
        )
    ]
    findings = _merge_matches(matches, bundle.manifest.telemetry_id, profile)
    return AuthenticationDetectionResult(
        source_telemetry_id=bundle.manifest.telemetry_id,
        profile_id=profile.id,
        findings=tuple(findings),
    )


def _alias_maps(
    aliases: tuple[HostAliasSnapshot, ...],
) -> tuple[dict[str, str], dict[str, str]]:
    hostname_aliases = {alias.hostname.casefold(): alias.host_id for alias in aliases}
    address_aliases = {
        str(address): alias.host_id
        for alias in aliases
        for address in alias.ipv4_addresses
    }
    return hostname_aliases, address_aliases


def _credential_validation_groups(
    records: tuple[AuthenticationArtifactRecord, ...],
    profile: PasswordSprayDetectionProfile,
    hostname_aliases: dict[str, str],
) -> list[_SignalGroup]:
    grouped: dict[tuple[str, str | None], list[_Observation]] = defaultdict(list)
    definition = profile.signals.domain_credential_validation

    for record in records:
        event = record.event
        if event.event_id != definition.event_id or not isinstance(
            event.data, Event4776Data
        ):
            continue
        if event.data.status.casefold() != definition.status.casefold():
            continue

        observed_source = event.data.workstation
        source_host_id = hostname_aliases.get(observed_source.casefold())
        source_key = source_host_id or f"unresolved:{observed_source.casefold()}"
        grouped[(source_key, source_host_id)].append(
            _Observation(
                occurred_at=event.occurred_at,
                username=event.data.target_user_name,
                username_key=event.data.target_user_name.casefold(),
                observed_source=observed_source,
                event_instance_id=record.event_instance_id,
            )
        )

    return [
        _SignalGroup(
            signal_type=SignalType.DOMAIN_CREDENTIAL_VALIDATION,
            source_host_id=source_host_id,
            destination_host_id=None,
            observations=tuple(observations),
        )
        for (_, source_host_id), observations in sorted(grouped.items())
    ]


def _destination_logon_groups(
    records: tuple[AuthenticationArtifactRecord, ...],
    profile: PasswordSprayDetectionProfile,
    address_aliases: dict[str, str],
) -> list[_SignalGroup]:
    grouped: dict[tuple[str, str | None, str], list[_Observation]] = defaultdict(list)
    definition = profile.signals.destination_logon

    for record in records:
        event = record.event
        if event.event_id != definition.event_id or not isinstance(
            event.data, Event4625Data
        ):
            continue
        if not (
            event.data.status.casefold() == definition.status.casefold()
            and event.data.sub_status.casefold() == definition.sub_status.casefold()
            and event.data.logon_type == definition.logon_type
            and event.data.authentication_package_name.casefold()
            == definition.authentication_package.casefold()
        ):
            continue

        observed_source = event.data.ip_address
        source_host_id = address_aliases.get(observed_source)
        source_key = source_host_id or f"unresolved:{observed_source}"
        grouped[(source_key, source_host_id, record.host_id)].append(
            _Observation(
                occurred_at=event.occurred_at,
                username=event.data.target_user_name,
                username_key=event.data.target_user_name.casefold(),
                observed_source=observed_source,
                event_instance_id=record.event_instance_id,
            )
        )

    return [
        _SignalGroup(
            signal_type=SignalType.DESTINATION_LOGON,
            source_host_id=source_host_id,
            destination_host_id=destination_host_id,
            observations=tuple(observations),
        )
        for (_, source_host_id, destination_host_id), observations in sorted(
            grouped.items()
        )
    ]


def _qualifying_matches(
    group: _SignalGroup,
    telemetry_id: str,
    profile: PasswordSprayDetectionProfile,
) -> list[DetectionSignalMatch]:
    observations = sorted(
        group.observations,
        key=lambda item: (item.occurred_at, item.event_instance_id),
    )
    duration = timedelta(seconds=profile.window_seconds)
    left = 0
    candidates: list[list[_Observation]] = []

    for right, observation in enumerate(observations):
        while observation.occurred_at - observations[left].occurred_at > duration:
            left += 1
        window = observations[left : right + 1]
        if len({item.username_key for item in window}) >= (
            profile.minimum_distinct_users
        ):
            candidates.append(window)

    merged = _merge_overlapping_observations(candidates)
    return [
        _build_signal_match(group, items, telemetry_id, profile.id) for items in merged
    ]


def _merge_overlapping_observations(
    candidates: list[list[_Observation]],
) -> list[list[_Observation]]:
    merged: list[list[_Observation]] = []
    for candidate in candidates:
        if not merged or candidate[0].occurred_at > merged[-1][-1].occurred_at:
            merged.append(list(candidate))
            continue
        known_ids = {item.event_instance_id for item in merged[-1]}
        merged[-1].extend(
            item for item in candidate if item.event_instance_id not in known_ids
        )
        merged[-1].sort(key=lambda item: (item.occurred_at, item.event_instance_id))
    return merged


def _build_signal_match(
    group: _SignalGroup,
    observations: list[_Observation],
    telemetry_id: str,
    profile_id: str,
) -> DetectionSignalMatch:
    usernames = _display_usernames(observations)
    event_ids = tuple(item.event_instance_id for item in observations)
    identity = canonical_json(
        {
            "telemetry_id": telemetry_id,
            "profile_id": profile_id,
            "signal_type": group.signal_type,
            "source_host_id": group.source_host_id,
            "destination_host_id": group.destination_host_id,
            "event_instance_ids": event_ids,
        }
    ).decode()
    return DetectionSignalMatch(
        signal_id=f"signal-{uuid5(_DETECTION_NAMESPACE, identity)}",
        signal_type=group.signal_type,
        source_host_id=group.source_host_id,
        observed_sources=tuple(
            sorted({item.observed_source for item in observations}, key=str.casefold)
        ),
        destination_host_id=group.destination_host_id,
        started_at=observations[0].occurred_at,
        ended_at=observations[-1].occurred_at,
        target_usernames=usernames,
        event_instance_ids=event_ids,
    )


def _display_usernames(observations: list[_Observation]) -> tuple[str, ...]:
    by_key: dict[str, str] = {}
    for observation in observations:
        by_key.setdefault(observation.username_key, observation.username)
    return tuple(by_key[key] for key in sorted(by_key))


def _merge_matches(
    matches: list[DetectionSignalMatch],
    telemetry_id: str,
    profile: PasswordSprayDetectionProfile,
) -> list[AuthenticationFinding]:
    matches = sorted(matches, key=_match_sort_key)
    edges: dict[int, set[int]] = defaultdict(set)
    for left_index, left in enumerate(matches):
        for right_index in range(left_index + 1, len(matches)):
            right = matches[right_index]
            if _can_merge(left, right, profile.minimum_distinct_users):
                edges[left_index].add(right_index)
                edges[right_index].add(left_index)

    components: list[list[DetectionSignalMatch]] = []
    unseen = set(range(len(matches)))
    while unseen:
        start = min(unseen)
        queue = deque([start])
        unseen.remove(start)
        component_indexes: list[int] = []
        while queue:
            current = queue.popleft()
            component_indexes.append(current)
            for neighbor in sorted(edges[current]):
                if neighbor in unseen:
                    unseen.remove(neighbor)
                    queue.append(neighbor)
        components.append([matches[index] for index in sorted(component_indexes)])

    findings = [
        _build_finding(component, telemetry_id, profile) for component in components
    ]
    return sorted(findings, key=lambda item: (item.started_at, item.finding_id))


def _can_merge(
    left: DetectionSignalMatch,
    right: DetectionSignalMatch,
    minimum_distinct_users: int,
) -> bool:
    if left.signal_type is right.signal_type:
        return False
    if left.source_host_id is None or left.source_host_id != right.source_host_id:
        return False
    if left.ended_at < right.started_at or right.ended_at < left.started_at:
        return False
    left_users = {username.casefold() for username in left.target_usernames}
    right_users = {username.casefold() for username in right.target_usernames}
    return len(left_users & right_users) >= minimum_distinct_users


def _build_finding(
    signals: list[DetectionSignalMatch],
    telemetry_id: str,
    profile: PasswordSprayDetectionProfile,
) -> AuthenticationFinding:
    signals = sorted(signals, key=_match_sort_key)
    signal_types = {signal.signal_type for signal in signals}
    confidence = (
        profile.multiple_signal_confidence
        if len(signal_types) > 1
        else profile.single_signal_confidence
    )
    usernames_by_key: dict[str, str] = {}
    for signal in signals:
        for username in signal.target_usernames:
            usernames_by_key.setdefault(username.casefold(), username)
    usernames = tuple(usernames_by_key[key] for key in sorted(usernames_by_key))
    event_ids = tuple(
        sorted(
            {event_id for signal in signals for event_id in signal.event_instance_ids}
        )
    )
    source_host_ids = {
        signal.source_host_id for signal in signals if signal.source_host_id is not None
    }
    source_host_id = next(iter(source_host_ids)) if len(source_host_ids) == 1 else None
    signal_ids = tuple(signal.signal_id for signal in signals)
    identity = canonical_json(
        {
            "telemetry_id": telemetry_id,
            "profile_id": profile.id,
            "signal_ids": signal_ids,
        }
    ).decode()
    return AuthenticationFinding(
        finding_id=f"finding-{uuid5(_DETECTION_NAMESPACE, identity)}",
        finding_type=profile.finding_type,
        title="Suspected password spray",
        severity=profile.severity,
        confidence=confidence,
        mitre_attack_ids=profile.mitre_attack_ids,
        evidence_basis=profile.evidence_basis,
        source_host_id=source_host_id,
        started_at=min(signal.started_at for signal in signals),
        ended_at=max(signal.ended_at for signal in signals),
        target_usernames=usernames,
        signals=tuple(signals),
        event_instance_ids=event_ids,
        limitations=profile.limitations,
    )


def _match_sort_key(
    match: DetectionSignalMatch,
) -> tuple[datetime, str, str]:
    return match.started_at, match.signal_type.value, match.signal_id

"""Generate deterministic Windows Security telemetry from authentication routes."""

from collections import Counter
from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Literal, Self
from uuid import UUID, uuid5

from pydantic import Field, model_validator

from simlab.authentication import (
    AuthenticationFailureReason,
    AuthenticationFlow,
    AuthenticationOutcome,
    AuthenticationProtocol,
    AuthenticationScenario,
)
from simlab.definition import Definition, Identifier
from simlab.environment import (
    AuditCategory,
    AuditOutcome,
    CorporateEnvironment,
    Domain,
    Host,
    Identity,
    ServiceKind,
)
from simlab.telemetry.windows_security import (
    Event4624Data,
    Event4625Data,
    Event4768Data,
    Event4769Data,
    Event4776Data,
    WindowsEventData,
    WindowsSecurityEvent,
    create_windows_security_event,
)

_GENERATOR_NAMESPACE = UUID("4c2e594e-6383-5e30-8ad2-778df07e1cea")
_EVENT_DELAY = {
    4768: timedelta(milliseconds=10),
    4769: timedelta(milliseconds=20),
    4624: timedelta(milliseconds=30),
    4776: timedelta(milliseconds=10),
    4625: timedelta(milliseconds=20),
}
_AUDIT_EVENT_DOCUMENTATION = (
    "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-"
)
_EVENT_DOCUMENTATION = {
    event_id: f"{_AUDIT_EVENT_DOCUMENTATION}{event_id}"
    for event_id in (4624, 4625, 4768, 4769, 4776)
}


class ValueOrigin(StrEnum):
    """How SimLab knows or produced a generated event field."""

    DOCUMENTED = "documented"
    DERIVED = "derived"
    SYNTHETIC = "synthetic"
    UNAVAILABLE = "unavailable"


class EventFieldProvenance(Definition):
    """Mutually exclusive origins covering every Windows event field."""

    documented: frozenset[str] = Field(default_factory=frozenset)
    derived: frozenset[str] = Field(default_factory=frozenset)
    synthetic: frozenset[str] = Field(default_factory=frozenset)
    unavailable: frozenset[str] = Field(default_factory=frozenset)
    documentation: tuple[str, ...]
    notes: tuple[str, ...] = ()


class GeneratedWindowsEvent(Definition):
    """A Windows event plus transparent simulation and provenance metadata."""

    source_attempt_id: Identifier
    host_id: Identifier
    synthetic_correlation_id: str
    event: WindowsSecurityEvent
    field_provenance: EventFieldProvenance

    @model_validator(mode="after")
    def validate_field_provenance(self) -> Self:
        """Require exactly one origin for every serialized Windows event field."""

        origin_sets = (
            self.field_provenance.documented,
            self.field_provenance.derived,
            self.field_provenance.synthetic,
            self.field_provenance.unavailable,
        )
        combined: set[str] = set()
        for fields in origin_sets:
            overlap = combined.intersection(fields)
            if overlap:
                raise ValueError(
                    f"event fields have multiple origins: {sorted(overlap)}"
                )
            combined.update(fields)

        expected = _event_field_paths(self.event)
        if combined != expected:
            missing = sorted(expected - combined)
            unknown = sorted(combined - expected)
            raise ValueError(
                f"event field provenance mismatch; missing={missing}, unknown={unknown}"
            )
        return self


class GeneratedAuthenticationTelemetry(Definition):
    """Generated authentication telemetry and its timing assumptions."""

    scenario_id: Identifier
    observability_source: Literal["host_audit_policy"] = "host_audit_policy"
    clock_assumption: Literal["synchronized_host_clocks"] = "synchronized_host_clocks"
    timing_basis: Literal["attempt_start_plus_synthetic_event_delay"] = (
        "attempt_start_plus_synthetic_event_delay"
    )
    events: list[GeneratedWindowsEvent]


def generate_authentication_telemetry(
    scenario: AuthenticationScenario,
    environment: CorporateEnvironment,
) -> GeneratedAuthenticationTelemetry:
    """Generate the Windows events observable under each host's audit policy."""

    scenario.validate_against(environment)
    hosts = {host.id: host for host in environment.hosts}
    identities = {identity.id: identity for identity in environment.identities}
    domains = {domain.id: domain for domain in environment.domains}
    record_ids: Counter[str] = Counter()
    generated: list[GeneratedWindowsEvent] = []

    for attempt_at, attempt in scenario.timeline():
        identity = identities[attempt.identity_id]
        source = hosts[attempt.source_host_id]
        destination = hosts[attempt.destination_host_id]
        authority = hosts[attempt.authority_host_id]
        domain = domains[identity.domain_id]
        correlation_id = _guid(scenario.id, attempt.id, "ground-truth")

        if scenario.flow is AuthenticationFlow.FRESH_INTERACTIVE_DOMAIN_LOGON:
            if attempt.outcome is not AuthenticationOutcome.SUCCESS:
                raise ValueError(
                    "fresh interactive logon generation currently supports success only"
                )
            generated.extend(
                _generate_interactive_logon(
                    scenario=scenario,
                    attempt_id=attempt.id,
                    attempt_at=attempt_at,
                    identity=identity,
                    source=source,
                    destination=destination,
                    authority=authority,
                    domain=domain,
                    environment=environment,
                    record_ids=record_ids,
                    correlation_id=correlation_id,
                )
            )
        elif scenario.flow is AuthenticationFlow.NETWORK_SERVICE_AUTHENTICATION:
            if scenario.protocol is not AuthenticationProtocol.NTLM:
                raise ValueError(
                    "network service generation currently supports NTLM only"
                )
            service = next(
                service
                for service in environment.services
                if service.id == scenario.service_id
            )
            if service.kind is not ServiceKind.SMB:
                raise ValueError(
                    "network service generation currently supports SMB only"
                )
            if attempt.outcome is not AuthenticationOutcome.FAILURE or (
                attempt.failure_reason is not AuthenticationFailureReason.BAD_PASSWORD
            ):
                raise ValueError(
                    "network authentication generation currently supports bad-password "
                    "failures only"
                )
            generated.extend(
                _generate_ntlm_failure(
                    scenario=scenario,
                    attempt_id=attempt.id,
                    attempt_at=attempt_at,
                    identity=identity,
                    source=source,
                    destination=destination,
                    authority=authority,
                    domain=domain,
                    environment=environment,
                    record_ids=record_ids,
                    correlation_id=correlation_id,
                )
            )

    generated.sort(
        key=lambda item: (
            item.event.occurred_at,
            item.host_id,
            item.event.event_id,
            item.source_attempt_id,
        )
    )
    _validate_expectations(scenario, generated)
    return GeneratedAuthenticationTelemetry(scenario_id=scenario.id, events=generated)


def _generate_interactive_logon(
    *,
    scenario: AuthenticationScenario,
    attempt_id: str,
    attempt_at: datetime,
    identity: Identity,
    source: Host,
    destination: Host,
    authority: Host,
    domain: Domain,
    environment: CorporateEnvironment,
    record_ids: Counter[str],
    correlation_id: str,
) -> list[GeneratedWindowsEvent]:
    events: list[GeneratedWindowsEvent] = []
    logon_guid = _guid(scenario.id, attempt_id, "windows-logon-guid")

    if _is_audited(
        environment,
        authority,
        AuditCategory.KERBEROS_AUTHENTICATION_SERVICE,
        AuditOutcome.SUCCESS,
    ):
        events.append(
            _build_generated_event(
                attempt_id=attempt_id,
                host=authority,
                domain=domain,
                event_id=4768,
                occurred_at=attempt_at + _EVENT_DELAY[4768],
                record_ids=record_ids,
                correlation_id=correlation_id,
                data=Event4768Data(
                    target_user_name=identity.username,
                    target_domain_name=domain.dns_name.upper(),
                    target_sid=_identity_sid(domain, identity),
                    service_name="krbtgt",
                    service_sid=f"{domain.sid}-502",
                    ticket_options="0x40810010",
                    status="0x0",
                    ticket_encryption_type="0x12",
                    pre_auth_type="2",
                    ip_address=f"::ffff:{source.ipv4_address}",
                    ip_port=str(_client_port(scenario.id, attempt_id, "as-req")),
                    cert_issuer_name="",
                    cert_serial_number="",
                    cert_thumbprint="",
                    response_ticket="",
                    account_supported_encryption_types="N/A",
                    account_available_keys="N/A",
                    service_supported_encryption_types="N/A",
                    service_available_keys="N/A",
                    dc_supported_encryption_types="N/A",
                    dc_available_keys="N/A",
                    client_advertized_encryption_types="N/A",
                    session_key_encryption_type="0x12",
                    pre_auth_encryption_type="0x12",
                ),
                derived_data={
                    "TargetUserName",
                    "TargetDomainName",
                    "TargetSid",
                    "ServiceSid",
                    "IpAddress",
                },
                synthetic_data={"IpPort"},
                unavailable_data={
                    "CertIssuerName",
                    "CertSerialNumber",
                    "CertThumbprint",
                    "ResponseTicket",
                    "AccountSupportedEncryptionTypes",
                    "AccountAvailableKeys",
                    "ServiceSupportedEncryptionTypes",
                    "ServiceAvailableKeys",
                    "DCSupportedEncryptionTypes",
                    "DCAvailableKeys",
                    "ClientAdvertizedEncryptionTypes",
                },
                notes=(
                    "AES-256 (0x12), password pre-authentication (2), and ticket "
                    "options are documented baseline assumptions, not observed values.",
                    "Ticket bytes and environment-specific encryption capability "
                    "fields are intentionally unavailable.",
                ),
            )
        )

    if _is_audited(
        environment,
        authority,
        AuditCategory.KERBEROS_SERVICE_TICKET_OPERATIONS,
        AuditOutcome.SUCCESS,
    ):
        events.append(
            _build_generated_event(
                attempt_id=attempt_id,
                host=authority,
                domain=domain,
                event_id=4769,
                occurred_at=attempt_at + _EVENT_DELAY[4769],
                record_ids=record_ids,
                correlation_id=correlation_id,
                data=Event4769Data(
                    target_user_name=(f"{identity.username}@{domain.dns_name.upper()}"),
                    target_domain_name=domain.dns_name.upper(),
                    service_name=f"{destination.hostname}$",
                    service_sid=_host_sid(domain, destination),
                    ticket_options="0x40810000",
                    ticket_encryption_type="0x12",
                    ip_address=f"::ffff:{source.ipv4_address}",
                    ip_port=str(_client_port(scenario.id, attempt_id, "tgs-req")),
                    status="0x0",
                    logon_guid=logon_guid,
                    transmitted_services="-",
                    request_ticket_hash="",
                    response_ticket_hash="",
                    account_supported_encryption_types="N/A",
                    account_available_keys="N/A",
                    service_supported_encryption_types="N/A",
                    service_available_keys="N/A",
                    dc_supported_encryption_types="N/A",
                    dc_available_keys="N/A",
                    client_advertized_encryption_types="N/A",
                    session_key_encryption_type="0x12",
                ),
                derived_data={
                    "TargetUserName",
                    "TargetDomainName",
                    "ServiceName",
                    "ServiceSid",
                    "IpAddress",
                },
                synthetic_data={"IpPort", "LogonGuid"},
                unavailable_data={
                    "TransmittedServices",
                    "RequestTicketHash",
                    "ResponseTicketHash",
                    "AccountSupportedEncryptionTypes",
                    "AccountAvailableKeys",
                    "ServiceSupportedEncryptionTypes",
                    "ServiceAvailableKeys",
                    "DCSupportedEncryptionTypes",
                    "DCAvailableKeys",
                    "ClientAdvertizedEncryptionTypes",
                },
                notes=(
                    "The synthetic LogonGuid correlates this TGS request with the "
                    "workstation logon event.",
                    "Ticket hashes and environment-specific encryption capability "
                    "fields are intentionally unavailable.",
                ),
            )
        )

    if _is_audited(
        environment,
        destination,
        AuditCategory.LOGON,
        AuditOutcome.SUCCESS,
    ):
        events.append(
            _build_generated_event(
                attempt_id=attempt_id,
                host=destination,
                domain=domain,
                event_id=4624,
                occurred_at=attempt_at + _EVENT_DELAY[4624],
                record_ids=record_ids,
                correlation_id=correlation_id,
                data=Event4624Data(
                    subject_user_sid="S-1-5-18",
                    subject_user_name=f"{destination.hostname}$",
                    subject_domain_name=domain.netbios_name,
                    subject_logon_id="0x3e7",
                    target_user_sid=_identity_sid(domain, identity),
                    target_user_name=identity.username,
                    target_domain_name=domain.netbios_name,
                    target_logon_id=_logon_id(scenario.id, attempt_id),
                    logon_type="2",
                    logon_process_name="User32",
                    authentication_package_name="Kerberos",
                    workstation_name=destination.hostname,
                    logon_guid=logon_guid,
                    transmitted_services="-",
                    lm_package_name="-",
                    key_length="0",
                    process_id="0x0",
                    process_name=r"C:\Windows\System32\winlogon.exe",
                    ip_address="-",
                    ip_port="0",
                    impersonation_level="%%1833",
                    restricted_admin_mode="-",
                    target_outbound_user_name="-",
                    target_outbound_domain_name="-",
                    virtual_account="%%1843",
                    target_linked_logon_id="0x0",
                    elevated_token="%%1842",
                ),
                derived_data={
                    "SubjectUserName",
                    "SubjectDomainName",
                    "TargetUserSid",
                    "TargetUserName",
                    "TargetDomainName",
                    "WorkstationName",
                },
                synthetic_data={"TargetLogonId", "LogonGuid"},
                unavailable_data={
                    "TransmittedServices",
                    "LmPackageName",
                    "ProcessId",
                    "IpAddress",
                    "IpPort",
                    "RestrictedAdminMode",
                    "TargetOutboundUserName",
                    "TargetOutboundDomainName",
                    "TargetLinkedLogonId",
                },
                notes=(
                    "Logon type 2 represents an interactive logon; User32 and "
                    "Kerberos describe the documented baseline flow.",
                    "Token-state values are documented baseline assumptions, not "
                    "observations from a Windows host.",
                ),
            )
        )

    return events


def _generate_ntlm_failure(
    *,
    scenario: AuthenticationScenario,
    attempt_id: str,
    attempt_at: datetime,
    identity: Identity,
    source: Host,
    destination: Host,
    authority: Host,
    domain: Domain,
    environment: CorporateEnvironment,
    record_ids: Counter[str],
    correlation_id: str,
) -> list[GeneratedWindowsEvent]:
    events: list[GeneratedWindowsEvent] = []

    if _is_audited(
        environment,
        authority,
        AuditCategory.CREDENTIAL_VALIDATION,
        AuditOutcome.FAILURE,
    ):
        events.append(
            _build_generated_event(
                attempt_id=attempt_id,
                host=authority,
                domain=domain,
                event_id=4776,
                occurred_at=attempt_at + _EVENT_DELAY[4776],
                record_ids=record_ids,
                correlation_id=correlation_id,
                data=Event4776Data(
                    package_name="MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
                    target_user_name=identity.username,
                    workstation=source.hostname,
                    status="0xC000006A",
                ),
                derived_data={"TargetUserName", "Workstation"},
                notes=(
                    "4776 is emitted on the domain controller that validates the "
                    "domain credential; 0xC000006A means bad password.",
                ),
            )
        )

    if _is_audited(
        environment,
        destination,
        AuditCategory.LOGON,
        AuditOutcome.FAILURE,
    ):
        events.append(
            _build_generated_event(
                attempt_id=attempt_id,
                host=destination,
                domain=domain,
                event_id=4625,
                occurred_at=attempt_at + _EVENT_DELAY[4625],
                record_ids=record_ids,
                correlation_id=correlation_id,
                data=Event4625Data(
                    subject_user_sid="S-1-0-0",
                    subject_user_name="-",
                    subject_domain_name="-",
                    subject_logon_id="0x0",
                    target_user_sid="S-1-0-0",
                    target_user_name=identity.username,
                    target_domain_name=domain.netbios_name,
                    status="0xC000006D",
                    failure_reason="%%2313",
                    sub_status="0xC000006A",
                    logon_type="3",
                    logon_process_name="NtLmSsp",
                    authentication_package_name="NTLM",
                    workstation_name=source.hostname,
                    transmitted_services="-",
                    lm_package_name="NTLM V2",
                    key_length="0",
                    process_id="0x0",
                    process_name="-",
                    ip_address=str(source.ipv4_address),
                    ip_port=str(_client_port(scenario.id, attempt_id, "smb")),
                ),
                derived_data={
                    "TargetUserName",
                    "TargetDomainName",
                    "WorkstationName",
                    "IpAddress",
                },
                synthetic_data={"IpPort"},
                unavailable_data={
                    "SubjectUserSid",
                    "SubjectUserName",
                    "SubjectDomainName",
                    "SubjectLogonId",
                    "TargetUserSid",
                    "TransmittedServices",
                    "ProcessId",
                    "ProcessName",
                },
                notes=(
                    "Logon type 3 represents network access on FS01; status "
                    "0xC000006D with substatus 0xC000006A represents a bad password.",
                    "The source port is deterministic synthetic data; failed-logon "
                    "security and process fields that cannot be derived are "
                    "unavailable.",
                ),
            )
        )

    return events


def _build_generated_event(
    *,
    attempt_id: str,
    host: Host,
    domain: Domain,
    event_id: int,
    occurred_at: datetime,
    record_ids: Counter[str],
    correlation_id: str,
    data: WindowsEventData,
    derived_data: set[str],
    synthetic_data: set[str] | None = None,
    unavailable_data: set[str] | None = None,
    notes: tuple[str, ...] = (),
) -> GeneratedWindowsEvent:
    record_ids[host.id] += 1
    event = create_windows_security_event(
        profile_id=host.event_profile_id,
        event_id=event_id,
        occurred_at=occurred_at,
        record_id=1000 + record_ids[host.id],
        computer=_fqdn(host, domain),
        process_id=0,
        thread_id=0,
        correlation_activity_id=None,
        data=data,
    )
    synthetic_data = synthetic_data or set()
    unavailable_data = unavailable_data or set()
    all_data = {
        f"event_data.{field.serialization_alias or name}"
        for name, field in type(data).model_fields.items()
    }
    derived_paths = {f"event_data.{name}" for name in derived_data}
    synthetic_paths = {f"event_data.{name}" for name in synthetic_data}
    unavailable_paths = {f"event_data.{name}" for name in unavailable_data}
    documented_paths = all_data - derived_paths - synthetic_paths - unavailable_paths

    provenance = EventFieldProvenance(
        documented=frozenset(
            {
                "system.provider_name",
                "system.provider_guid",
                "system.channel",
                "system.event_id",
                "system.version",
                "system.level",
                "system.task",
                "system.opcode",
                "system.keywords",
                *documented_paths,
            }
        ),
        derived=frozenset(
            {
                "system.profile_id",
                "system.computer",
                *derived_paths,
            }
        ),
        synthetic=frozenset(
            {
                "system.occurred_at",
                "system.record_id",
                *synthetic_paths,
            }
        ),
        unavailable=frozenset(
            {
                "system.process_id",
                "system.thread_id",
                "system.correlation_activity_id",
                *unavailable_paths,
            }
        ),
        documentation=(_EVENT_DOCUMENTATION[event_id],),
        notes=notes,
    )
    return GeneratedWindowsEvent(
        source_attempt_id=attempt_id,
        host_id=host.id,
        synthetic_correlation_id=correlation_id,
        event=event,
        field_provenance=provenance,
    )


def _event_field_paths(event: WindowsSecurityEvent) -> set[str]:
    system_fields = {
        f"system.{name}" for name in type(event).model_fields if name != "data"
    }
    data_fields = {
        f"event_data.{field.serialization_alias or name}"
        for name, field in type(event.data).model_fields.items()
    }
    return system_fields | data_fields


def _is_audited(
    environment: CorporateEnvironment,
    host: Host,
    category: AuditCategory,
    outcome: AuditOutcome,
) -> bool:
    policies = {policy.id: policy for policy in environment.audit_policies}
    return policies[host.audit_policy_id].records(category, outcome)


def _validate_expectations(
    scenario: AuthenticationScenario,
    generated: list[GeneratedWindowsEvent],
) -> None:
    expected = Counter(
        {
            (expectation.host_id, expectation.event_id): expectation.count
            for expectation in scenario.expected_events
        }
    )
    actual = Counter((item.host_id, item.event.event_id) for item in generated)
    if actual != expected:
        raise ValueError(
            f"generated telemetry does not match scenario expectations; "
            f"expected={dict(expected)}, actual={dict(actual)}"
        )


def _identity_sid(domain: Domain, identity: Identity) -> str:
    return f"{domain.sid}-{identity.rid}"


def _host_sid(domain: Domain, host: Host) -> str:
    return f"{domain.sid}-{host.account_rid}"


def _fqdn(host: Host, domain: Domain) -> str:
    return f"{host.hostname}.{domain.dns_name}"


def _guid(*parts: str) -> str:
    value = uuid5(_GENERATOR_NAMESPACE, ":".join(parts))
    return "{" + str(value).upper() + "}"


def _logon_id(*parts: str) -> str:
    digest = sha256(":".join(parts).encode()).digest()
    return f"0x{int.from_bytes(digest[:6], byteorder='big'):x}"


def _client_port(*parts: str) -> int:
    digest = sha256(":".join(parts).encode()).digest()
    return 49152 + int.from_bytes(digest[:2], byteorder="big") % 16384

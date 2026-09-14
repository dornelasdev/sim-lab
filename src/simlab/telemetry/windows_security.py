"""Typed Windows Security events and Event XML serialization."""

from datetime import UTC, datetime
from typing import Literal, Self
from xml.etree import ElementTree

from pydantic import AwareDatetime, Field, model_validator
from pydantic.fields import FieldInfo

from simlab.definition import Definition, Identifier

EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
PROVIDER_NAME = "Microsoft-Windows-Security-Auditing"
PROVIDER_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
SECURITY_CHANNEL = "Security"


def _event_field(name: str) -> FieldInfo:
    return Field(serialization_alias=name)


class Event4624Data(Definition):
    """Full version 2 payload for a successful Windows logon."""

    subject_user_sid: str = _event_field("SubjectUserSid")
    subject_user_name: str = _event_field("SubjectUserName")
    subject_domain_name: str = _event_field("SubjectDomainName")
    subject_logon_id: str = _event_field("SubjectLogonId")
    target_user_sid: str = _event_field("TargetUserSid")
    target_user_name: str = _event_field("TargetUserName")
    target_domain_name: str = _event_field("TargetDomainName")
    target_logon_id: str = _event_field("TargetLogonId")
    logon_type: str = _event_field("LogonType")
    logon_process_name: str = _event_field("LogonProcessName")
    authentication_package_name: str = _event_field("AuthenticationPackageName")
    workstation_name: str = _event_field("WorkstationName")
    logon_guid: str = _event_field("LogonGuid")
    transmitted_services: str = _event_field("TransmittedServices")
    lm_package_name: str = _event_field("LmPackageName")
    key_length: str = _event_field("KeyLength")
    process_id: str = _event_field("ProcessId")
    process_name: str = _event_field("ProcessName")
    ip_address: str = _event_field("IpAddress")
    ip_port: str = _event_field("IpPort")
    impersonation_level: str = _event_field("ImpersonationLevel")
    restricted_admin_mode: str = _event_field("RestrictedAdminMode")
    target_outbound_user_name: str = _event_field("TargetOutboundUserName")
    target_outbound_domain_name: str = _event_field("TargetOutboundDomainName")
    virtual_account: str = _event_field("VirtualAccount")
    target_linked_logon_id: str = _event_field("TargetLinkedLogonId")
    elevated_token: str = _event_field("ElevatedToken")


class Event4625Data(Definition):
    """Full version 0 payload for a failed Windows logon."""

    subject_user_sid: str = _event_field("SubjectUserSid")
    subject_user_name: str = _event_field("SubjectUserName")
    subject_domain_name: str = _event_field("SubjectDomainName")
    subject_logon_id: str = _event_field("SubjectLogonId")
    target_user_sid: str = _event_field("TargetUserSid")
    target_user_name: str = _event_field("TargetUserName")
    target_domain_name: str = _event_field("TargetDomainName")
    status: str = _event_field("Status")
    failure_reason: str = _event_field("FailureReason")
    sub_status: str = _event_field("SubStatus")
    logon_type: str = _event_field("LogonType")
    logon_process_name: str = _event_field("LogonProcessName")
    authentication_package_name: str = _event_field("AuthenticationPackageName")
    workstation_name: str = _event_field("WorkstationName")
    transmitted_services: str = _event_field("TransmittedServices")
    lm_package_name: str = _event_field("LmPackageName")
    key_length: str = _event_field("KeyLength")
    process_id: str = _event_field("ProcessId")
    process_name: str = _event_field("ProcessName")
    ip_address: str = _event_field("IpAddress")
    ip_port: str = _event_field("IpPort")


class Event4768Data(Definition):
    """Full modern payload for a Kerberos TGT request."""

    target_user_name: str = _event_field("TargetUserName")
    target_domain_name: str = _event_field("TargetDomainName")
    target_sid: str = _event_field("TargetSid")
    service_name: str = _event_field("ServiceName")
    service_sid: str = _event_field("ServiceSid")
    ticket_options: str = _event_field("TicketOptions")
    status: str = _event_field("Status")
    ticket_encryption_type: str = _event_field("TicketEncryptionType")
    pre_auth_type: str = _event_field("PreAuthType")
    ip_address: str = _event_field("IpAddress")
    ip_port: str = _event_field("IpPort")
    cert_issuer_name: str = _event_field("CertIssuerName")
    cert_serial_number: str = _event_field("CertSerialNumber")
    cert_thumbprint: str = _event_field("CertThumbprint")
    response_ticket: str = _event_field("ResponseTicket")
    account_supported_encryption_types: str = _event_field(
        "AccountSupportedEncryptionTypes"
    )
    account_available_keys: str = _event_field("AccountAvailableKeys")
    service_supported_encryption_types: str = _event_field(
        "ServiceSupportedEncryptionTypes"
    )
    service_available_keys: str = _event_field("ServiceAvailableKeys")
    dc_supported_encryption_types: str = _event_field("DCSupportedEncryptionTypes")
    dc_available_keys: str = _event_field("DCAvailableKeys")
    client_advertized_encryption_types: str = _event_field(
        "ClientAdvertizedEncryptionTypes"
    )
    session_key_encryption_type: str = _event_field("SessionKeyEncryptionType")
    pre_auth_encryption_type: str = _event_field("PreAuthEncryptionType")


class Event4769Data(Definition):
    """Full modern payload for a Kerberos service-ticket request."""

    target_user_name: str = _event_field("TargetUserName")
    target_domain_name: str = _event_field("TargetDomainName")
    service_name: str = _event_field("ServiceName")
    service_sid: str = _event_field("ServiceSid")
    ticket_options: str = _event_field("TicketOptions")
    ticket_encryption_type: str = _event_field("TicketEncryptionType")
    ip_address: str = _event_field("IpAddress")
    ip_port: str = _event_field("IpPort")
    status: str = _event_field("Status")
    logon_guid: str = _event_field("LogonGuid")
    transmitted_services: str = _event_field("TransmittedServices")
    request_ticket_hash: str = _event_field("RequestTicketHash")
    response_ticket_hash: str = _event_field("ResponseTicketHash")
    account_supported_encryption_types: str = _event_field(
        "AccountSupportedEncryptionTypes"
    )
    account_available_keys: str = _event_field("AccountAvailableKeys")
    service_supported_encryption_types: str = _event_field(
        "ServiceSupportedEncryptionTypes"
    )
    service_available_keys: str = _event_field("ServiceAvailableKeys")
    dc_supported_encryption_types: str = _event_field("DCSupportedEncryptionTypes")
    dc_available_keys: str = _event_field("DCAvailableKeys")
    client_advertized_encryption_types: str = _event_field(
        "ClientAdvertizedEncryptionTypes"
    )
    session_key_encryption_type: str = _event_field("SessionKeyEncryptionType")


class Event4776Data(Definition):
    """Full version 0 payload for NTLM credential validation."""

    package_name: str = _event_field("PackageName")
    target_user_name: str = _event_field("TargetUserName")
    workstation: str = _event_field("Workstation")
    status: str = _event_field("Status")


WindowsEventData = (
    Event4624Data | Event4625Data | Event4768Data | Event4769Data | Event4776Data
)


class WindowsEventMetadata(Definition):
    """System-envelope values fixed by a Windows event schema."""

    event_id: int
    version: int = Field(ge=0)
    level: int = Field(ge=0)
    task: int = Field(ge=0)
    opcode: int = Field(ge=0)
    keywords: str
    payload_type: type[Definition]


class WindowsSecurityEventProfile(Definition):
    """A versioned collection of Windows Security event schemas."""

    id: Identifier
    schemas: dict[int, WindowsEventMetadata]


WINDOWS_SECURITY_2025_01 = WindowsSecurityEventProfile(
    id="windows-security-2025-01",
    schemas={
        4624: WindowsEventMetadata(
            event_id=4624,
            version=2,
            level=0,
            task=12544,
            opcode=0,
            keywords="0x8020000000000000",
            payload_type=Event4624Data,
        ),
        4625: WindowsEventMetadata(
            event_id=4625,
            version=0,
            level=0,
            task=12546,
            opcode=0,
            keywords="0x8010000000000000",
            payload_type=Event4625Data,
        ),
        4768: WindowsEventMetadata(
            event_id=4768,
            version=2,
            level=0,
            task=14339,
            opcode=0,
            keywords="0x8020000000000000",
            payload_type=Event4768Data,
        ),
        4769: WindowsEventMetadata(
            event_id=4769,
            version=2,
            level=0,
            task=14337,
            opcode=0,
            keywords="0x8020000000000000",
            payload_type=Event4769Data,
        ),
        4776: WindowsEventMetadata(
            event_id=4776,
            version=0,
            level=0,
            task=14336,
            opcode=0,
            keywords="0x8010000000000000",
            payload_type=Event4776Data,
        ),
    },
)

WINDOWS_SECURITY_PROFILES = {
    WINDOWS_SECURITY_2025_01.id: WINDOWS_SECURITY_2025_01,
}


class WindowsSecurityEvent(Definition):
    """A typed Windows Security event ready for output serialization."""

    profile_id: Identifier
    provider_name: Literal["Microsoft-Windows-Security-Auditing"] = PROVIDER_NAME
    provider_guid: Literal["{54849625-5478-4994-A5BA-3E3B0328C30D}"] = PROVIDER_GUID
    channel: Literal["Security"] = SECURITY_CHANNEL
    event_id: int
    version: int = Field(ge=0)
    level: int = Field(ge=0)
    task: int = Field(ge=0)
    opcode: int = Field(ge=0)
    keywords: str
    occurred_at: AwareDatetime
    record_id: int = Field(gt=0)
    computer: str = Field(min_length=1)
    process_id: int = Field(ge=0)
    thread_id: int = Field(ge=0)
    correlation_activity_id: str | None = None
    data: WindowsEventData

    @model_validator(mode="after")
    def validate_profile_schema(self) -> Self:
        """Ensure the envelope and payload match the selected profile."""

        profile = WINDOWS_SECURITY_PROFILES.get(self.profile_id)
        if profile is None:
            raise ValueError(f"unknown Windows Security profile {self.profile_id!r}")

        metadata = profile.schemas.get(self.event_id)
        if metadata is None:
            raise ValueError(
                f"event {self.event_id} is not defined by profile {profile.id!r}"
            )

        envelope_values = {
            "version": self.version,
            "level": self.level,
            "task": self.task,
            "opcode": self.opcode,
            "keywords": self.keywords,
        }
        for field_name, value in envelope_values.items():
            if value != getattr(metadata, field_name):
                raise ValueError(
                    f"event {self.event_id} has invalid {field_name} for "
                    f"profile {profile.id!r}"
                )

        if not isinstance(self.data, metadata.payload_type):
            raise ValueError(
                f"event {self.event_id} requires {metadata.payload_type.__name__}"
            )
        return self


def create_windows_security_event(
    *,
    profile_id: str,
    event_id: int,
    occurred_at: datetime,
    record_id: int,
    computer: str,
    process_id: int,
    thread_id: int,
    data: WindowsEventData,
    correlation_activity_id: str | None = None,
) -> WindowsSecurityEvent:
    """Create an event using envelope metadata from a versioned profile."""

    profile = WINDOWS_SECURITY_PROFILES.get(profile_id)
    if profile is None:
        raise ValueError(f"unknown Windows Security profile {profile_id!r}")
    metadata = profile.schemas.get(event_id)
    if metadata is None:
        raise ValueError(f"event {event_id} is not defined by profile {profile_id!r}")

    return WindowsSecurityEvent(
        profile_id=profile_id,
        event_id=event_id,
        version=metadata.version,
        level=metadata.level,
        task=metadata.task,
        opcode=metadata.opcode,
        keywords=metadata.keywords,
        occurred_at=occurred_at,
        record_id=record_id,
        computer=computer,
        process_id=process_id,
        thread_id=thread_id,
        correlation_activity_id=correlation_activity_id,
        data=data,
    )


def to_event_xml(event: WindowsSecurityEvent) -> str:
    """Serialize a typed event to the native Windows Event XML shape."""

    ElementTree.register_namespace("", EVENT_NAMESPACE)
    root = ElementTree.Element(_tag("Event"))
    system = ElementTree.SubElement(root, _tag("System"))
    ElementTree.SubElement(
        system,
        _tag("Provider"),
        {"Name": event.provider_name, "Guid": event.provider_guid},
    )
    _text_element(system, "EventID", str(event.event_id))
    _text_element(system, "Version", str(event.version))
    _text_element(system, "Level", str(event.level))
    _text_element(system, "Task", str(event.task))
    _text_element(system, "Opcode", str(event.opcode))
    _text_element(system, "Keywords", event.keywords)
    ElementTree.SubElement(
        system,
        _tag("TimeCreated"),
        {"SystemTime": _system_time(event.occurred_at)},
    )
    _text_element(system, "EventRecordID", str(event.record_id))

    correlation_attributes = {}
    if event.correlation_activity_id is not None:
        correlation_attributes["ActivityID"] = event.correlation_activity_id
    ElementTree.SubElement(system, _tag("Correlation"), correlation_attributes)
    ElementTree.SubElement(
        system,
        _tag("Execution"),
        {"ProcessID": str(event.process_id), "ThreadID": str(event.thread_id)},
    )
    _text_element(system, "Channel", event.channel)
    _text_element(system, "Computer", event.computer)
    ElementTree.SubElement(system, _tag("Security"))

    event_data = ElementTree.SubElement(root, _tag("EventData"))
    for name, value in event.data.model_dump(mode="json", by_alias=True).items():
        data_element = ElementTree.SubElement(event_data, _tag("Data"), {"Name": name})
        data_element.text = value

    ElementTree.indent(root, space="  ")
    return ElementTree.tostring(root, encoding="unicode", xml_declaration=True)


def _tag(name: str) -> str:
    return f"{{{EVENT_NAMESPACE}}}{name}"


def _text_element(parent: ElementTree.Element, name: str, value: str) -> None:
    element = ElementTree.SubElement(parent, _tag(name))
    element.text = value


def _system_time(value: datetime) -> str:
    utc_value = value.astimezone(UTC)
    return utc_value.isoformat(timespec="microseconds").replace("+00:00", "Z")

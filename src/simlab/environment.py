"""Models and loading for SimLab environment definitions."""

from enum import StrEnum
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from simlab.definition import Definition, Identifier, read_yaml

DomainSid = Annotated[
    str,
    StringConstraints(pattern=r"^S-1-5-21-(?:[0-9]+-){2}[0-9]+$"),
]


class Environment(Definition):
    """Fields shared by any future environment type."""

    schema_version: Literal[1]
    id: Identifier
    name: str = Field(min_length=1)


class Domain(Definition):
    """An Active Directory domain known to the corporate environment."""

    id: Identifier
    dns_name: str = Field(min_length=1)
    netbios_name: str = Field(min_length=1, max_length=15)
    sid: DomainSid


class HostRole(StrEnum):
    """Host purposes currently required by the authentication route."""

    DOMAIN_CONTROLLER = "domain_controller"
    MEMBER_SERVER = "member_server"
    WORKSTATION = "workstation"


class ServiceKind(StrEnum):
    """Network services that routes can target explicitly."""

    SMB = "smb"


class AuditOutcome(StrEnum):
    """Windows audit outcomes that a policy can record."""

    SUCCESS = "success"
    FAILURE = "failure"


class AuditCategory(StrEnum):
    """Authentication-related Windows advanced audit categories."""

    LOGON = "logon"
    CREDENTIAL_VALIDATION = "credential_validation"
    KERBEROS_AUTHENTICATION_SERVICE = "kerberos_authentication_service"
    KERBEROS_SERVICE_TICKET_OPERATIONS = "kerberos_service_ticket_operations"


class AuditSetting(Definition):
    """Enabled outcomes for one advanced audit-policy category."""

    category: AuditCategory
    outcomes: set[AuditOutcome] = Field(min_length=1)


class AuditPolicy(Definition):
    """Reusable audit-policy settings assigned to Windows hosts."""

    id: Identifier
    name: str = Field(min_length=1)
    settings: list[AuditSetting] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_categories(self) -> Self:
        """Reject ambiguous duplicate settings for the same category."""

        categories = [setting.category for setting in self.settings]
        if len(categories) != len(set(categories)):
            raise ValueError("audit policy categories must be unique")
        return self

    def records(self, category: AuditCategory, outcome: AuditOutcome) -> bool:
        """Return whether this policy records an event category and outcome."""

        return any(
            setting.category is category and outcome in setting.outcomes
            for setting in self.settings
        )


class Host(Definition):
    """A computer participating in the corporate environment."""

    id: Identifier
    hostname: str = Field(min_length=1)
    platform: Literal["windows"]
    role: HostRole
    domain_id: Identifier
    account_rid: int = Field(gt=0)
    ipv4_address: IPv4Address
    event_profile_id: Identifier
    audit_policy_id: Identifier


class Service(Definition):
    """A typed network service exposed by one environment host."""

    id: Identifier
    kind: ServiceKind
    host_id: Identifier
    port: int = Field(ge=1, le=65535)


class Identity(Definition):
    """A domain identity available to scenarios."""

    id: Identifier
    username: str = Field(min_length=1)
    domain_id: Identifier
    rid: int = Field(gt=0)


class CorporateEnvironment(Environment):
    """A corporate environment used by AD-focused routes."""

    kind: Literal["corporate"]
    domains: list[Domain] = Field(min_length=1)
    audit_policies: list[AuditPolicy] = Field(min_length=1)
    hosts: list[Host] = Field(min_length=1)
    services: list[Service] = Field(default_factory=list)
    identities: list[Identity] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_entity_references(self) -> Self:
        """Ensure IDs are unambiguous and domain references can be resolved."""

        _require_unique_ids("domains", self.domains)
        _require_unique_ids("audit_policies", self.audit_policies)
        _require_unique_ids("hosts", self.hosts)
        _require_unique_ids("services", self.services)
        _require_unique_ids("identities", self.identities)

        domain_ids = {domain.id for domain in self.domains}
        for collection_name, entities in (
            ("hosts", self.hosts),
            ("identities", self.identities),
        ):
            for entity in entities:
                if entity.domain_id not in domain_ids:
                    raise ValueError(
                        f"{collection_name} entity {entity.id!r} references unknown "
                        f"domain {entity.domain_id!r}"
                    )

        audit_policy_ids = {policy.id for policy in self.audit_policies}
        for host in self.hosts:
            if host.audit_policy_id not in audit_policy_ids:
                raise ValueError(
                    f"host {host.id!r} references unknown audit policy "
                    f"{host.audit_policy_id!r}"
                )

        host_ids = {host.id for host in self.hosts}
        for service in self.services:
            if service.host_id not in host_ids:
                raise ValueError(
                    f"service {service.id!r} references unknown host "
                    f"{service.host_id!r}"
                )

        principal_rids: set[tuple[str, int]] = set()
        for principal in [*self.hosts, *self.identities]:
            rid = (
                principal.account_rid if isinstance(principal, Host) else principal.rid
            )
            principal_key = (principal.domain_id, rid)
            if principal_key in principal_rids:
                raise ValueError(
                    f"duplicate RID {rid!r} in domain {principal.domain_id!r}"
                )
            principal_rids.add(principal_key)

        return self


def _require_unique_ids(collection_name: str, entities: list[Any]) -> None:
    """Reject duplicate IDs inside one typed entity collection."""

    seen: set[str] = set()
    for entity in entities:
        if entity.id in seen:
            raise ValueError(
                f"duplicate id {entity.id!r} in {collection_name} collection"
            )
        seen.add(entity.id)


def load_environment(path: str | Path) -> CorporateEnvironment:
    """Load and validate a corporate environment from YAML."""

    return CorporateEnvironment.model_validate(read_yaml(path))

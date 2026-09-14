"""Shared authentication actions and route validation."""

from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from simlab.definition import Definition, Identifier, read_yaml
from simlab.environment import CorporateEnvironment, HostRole


class CredentialType(StrEnum):
    """Credential categories currently used by authentication routes."""

    PASSWORD = "password"


class AccessType(StrEnum):
    """How a user is attempting to access a destination host."""

    INTERACTIVE = "interactive"
    NETWORK = "network"


class AuthenticationProtocol(StrEnum):
    """Authentication protocols represented by the current routes."""

    KERBEROS = "kerberos"
    NTLM = "ntlm"


class AuthenticationFlow(StrEnum):
    """Security context that determines the expected authentication exchange."""

    FRESH_INTERACTIVE_DOMAIN_LOGON = "fresh_interactive_domain_logon"
    NETWORK_SERVICE_AUTHENTICATION = "network_service_authentication"


class AuthenticationOutcome(StrEnum):
    """The result observed by the authentication action."""

    SUCCESS = "success"
    FAILURE = "failure"


class AuthenticationFailureReason(StrEnum):
    """Failure reasons currently required by authentication routes."""

    BAD_PASSWORD = "bad_password"


class AuthenticationAttempt(Definition):
    """One protocol-independent attempt to authenticate an identity."""

    id: Identifier
    offset_seconds: int = Field(ge=0)
    identity_id: Identifier
    source_host_id: Identifier
    destination_host_id: Identifier
    authority_host_id: Identifier
    credential_type: CredentialType
    access_type: AccessType
    outcome: AuthenticationOutcome
    failure_reason: AuthenticationFailureReason | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        """Keep success and failure details internally consistent."""

        if (
            self.outcome is AuthenticationOutcome.FAILURE
            and self.failure_reason is None
        ):
            raise ValueError("a failed authentication requires a failure_reason")
        if (
            self.outcome is AuthenticationOutcome.SUCCESS
            and self.failure_reason is not None
        ):
            raise ValueError("a successful authentication cannot have a failure_reason")
        return self


class EventExpectation(Definition):
    """An assertion about observable telemetry, not an event-generation rule."""

    event_id: int = Field(gt=0)
    host_id: Identifier
    count: int = Field(gt=0)


class AuthenticationScenario(Definition):
    """An ordered, deterministic sequence of authentication attempts."""

    schema_version: Literal[1]
    kind: Literal["authentication"]
    id: Identifier
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    environment_id: Identifier
    start_at: AwareDatetime
    protocol: AuthenticationProtocol
    flow: AuthenticationFlow
    service_id: Identifier | None = None
    attempts: list[AuthenticationAttempt] = Field(min_length=1)
    expected_events: list[EventExpectation] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_attempt_sequence(self) -> Self:
        """Require ordered actions and a coherent authentication flow."""

        seen: set[str] = set()
        previous_offset = -1
        for attempt in self.attempts:
            if attempt.id in seen:
                raise ValueError(f"duplicate authentication attempt id {attempt.id!r}")
            if attempt.offset_seconds < previous_offset:
                raise ValueError(
                    "authentication attempts must be ordered by offset_seconds"
                )
            seen.add(attempt.id)
            previous_offset = attempt.offset_seconds

        if self.flow is AuthenticationFlow.FRESH_INTERACTIVE_DOMAIN_LOGON:
            if self.protocol is not AuthenticationProtocol.KERBEROS:
                raise ValueError("a fresh interactive domain logon requires Kerberos")
            if self.service_id is not None:
                raise ValueError("an interactive logon cannot target a network service")
            for attempt in self.attempts:
                if attempt.access_type is not AccessType.INTERACTIVE:
                    raise ValueError("an interactive logon requires interactive access")
                if attempt.source_host_id != attempt.destination_host_id:
                    raise ValueError(
                        "an interactive logon must originate on its destination host"
                    )

        if self.flow is AuthenticationFlow.NETWORK_SERVICE_AUTHENTICATION:
            if self.service_id is None:
                raise ValueError("network authentication requires a service_id")
            for attempt in self.attempts:
                if attempt.access_type is not AccessType.NETWORK:
                    raise ValueError("network authentication requires network access")

        expectation_keys = [
            (expectation.host_id, expectation.event_id)
            for expectation in self.expected_events
        ]
        if len(expectation_keys) != len(set(expectation_keys)):
            raise ValueError("event expectations must be unique by host and event id")
        return self

    def timeline(self) -> list[tuple[datetime, AuthenticationAttempt]]:
        """Resolve relative offsets into reproducible action timestamps."""

        return [
            (self.start_at + timedelta(seconds=attempt.offset_seconds), attempt)
            for attempt in self.attempts
        ]

    def validate_against(self, environment: CorporateEnvironment) -> Self:
        """Verify that every action references compatible environment entities."""

        if self.environment_id != environment.id:
            raise ValueError(
                f"scenario expects environment {self.environment_id!r}, "
                f"received {environment.id!r}"
            )

        identities = {identity.id: identity for identity in environment.identities}
        hosts = {host.id: host for host in environment.hosts}
        services = {service.id: service for service in environment.services}

        service = None
        if self.service_id is not None:
            service = services.get(self.service_id)
            if service is None:
                raise ValueError(
                    f"scenario references unknown service {self.service_id!r}"
                )

        for expectation in self.expected_events:
            if expectation.host_id not in hosts:
                raise ValueError(
                    f"event {expectation.event_id} expectation references unknown "
                    f"host {expectation.host_id!r}"
                )

        for attempt in self.attempts:
            identity = identities.get(attempt.identity_id)
            if identity is None:
                raise ValueError(
                    f"attempt {attempt.id!r} references unknown identity "
                    f"{attempt.identity_id!r}"
                )

            referenced_hosts = {
                "source": attempt.source_host_id,
                "destination": attempt.destination_host_id,
                "authority": attempt.authority_host_id,
            }
            for reference_name, host_id in referenced_hosts.items():
                if host_id not in hosts:
                    raise ValueError(
                        f"attempt {attempt.id!r} references unknown {reference_name} "
                        f"host {host_id!r}"
                    )

            authority = hosts[attempt.authority_host_id]
            if authority.role is not HostRole.DOMAIN_CONTROLLER:
                raise ValueError(
                    f"attempt {attempt.id!r} authority {authority.id!r} is not a "
                    "domain controller"
                )
            if identity.domain_id != authority.domain_id:
                raise ValueError(
                    f"attempt {attempt.id!r} identity and authority belong to "
                    "different domains"
                )
            if service is not None and attempt.destination_host_id != service.host_id:
                raise ValueError(
                    f"attempt {attempt.id!r} destination does not host service "
                    f"{service.id!r}"
                )

        return self


def load_authentication_scenario(
    path: str | Path,
    environment: CorporateEnvironment,
) -> AuthenticationScenario:
    """Load an authentication scenario and validate its environment references."""

    scenario = AuthenticationScenario.model_validate(read_yaml(path))
    return scenario.validate_against(environment)

"""SimLab's public Python interface."""

from simlab.artifacts import (
    AuthenticationArtifactBundle,
    generate_authentication_bundle,
)
from simlab.authentication import AuthenticationScenario, load_authentication_scenario
from simlab.environment import CorporateEnvironment, load_environment
from simlab.telemetry.authentication import (
    GeneratedAuthenticationTelemetry,
    generate_authentication_telemetry,
)

__all__ = [
    "AuthenticationArtifactBundle",
    "AuthenticationScenario",
    "CorporateEnvironment",
    "GeneratedAuthenticationTelemetry",
    "generate_authentication_bundle",
    "generate_authentication_telemetry",
    "load_authentication_scenario",
    "load_environment",
]

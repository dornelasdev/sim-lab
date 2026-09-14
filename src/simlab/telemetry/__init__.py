"""Telemetry models and serializers provided by SimLab."""

from simlab.telemetry.authentication import (
    GeneratedAuthenticationTelemetry,
    GeneratedWindowsEvent,
    ValueOrigin,
    generate_authentication_telemetry,
)
from simlab.telemetry.windows_security import (
    WINDOWS_SECURITY_2025_01,
    WindowsSecurityEvent,
    create_windows_security_event,
    to_event_xml,
)

__all__ = [
    "GeneratedAuthenticationTelemetry",
    "GeneratedWindowsEvent",
    "WINDOWS_SECURITY_2025_01",
    "ValueOrigin",
    "WindowsSecurityEvent",
    "create_windows_security_event",
    "generate_authentication_telemetry",
    "to_event_xml",
]

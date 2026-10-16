"""Pinned Wazuh compatibility and the shared Windows failure-event adapter."""

from datetime import UTC
from typing import Any

from simlab.telemetry.windows_security import (
    Event4625Data,
    Event4776Data,
    WindowsSecurityEvent,
)

WAZUH_MANAGER_VERSION = "4.14.7"
SUPPORTED_EVENT_IDS = (4625, 4776)


def to_wazuh_event(event: WindowsSecurityEvent) -> dict[str, Any]:
    """Keep the tested EventChannel-shaped input used by real rule evaluation."""

    if not isinstance(event.data, (Event4625Data, Event4776Data)):
        raise ValueError(f"event {event.event_id} has no Wazuh rule-test mapping")

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


def _lower_initial(value: str) -> str:
    return value[:1].lower() + value[1:]

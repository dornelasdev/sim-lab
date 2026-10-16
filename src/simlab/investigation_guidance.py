"""Read-only analyst orientation, distinct from evidence and author answers."""

from simlab.environment import HostRole
from simlab.wazuh_evaluation import SavedInvestigation

WINDOWS_EVENT_NOTES = (
    "Windows Security event IDs\n"
    "Read the event's host, time, account, logon type, and outcome together. "
    "An event ID alone does not establish an attack.\n\n"
    "Present in this first case\n"
    "4624 — A logon session was created successfully on the recording host. "
    "Success alone does not establish unauthorized access.\n"
    "4625 — A logon attempt failed on the recording host. Read Status and "
    "SubStatus for the reason, plus LogonType for the access method.\n"
    "4768 — A Kerberos ticket-granting ticket (TGT) was requested; recorded "
    "on a domain controller. Check the result, not just the request.\n"
    "4769 — A Kerberos service ticket was requested; recorded on a domain "
    "controller. A ticket request is not proof that the service was accessed.\n"
    "4776 — NTLM credential validation by the authoritative system: a DC "
    "for domain accounts, the local computer for local accounts. It gives "
    "source workstation context, not the destination server.\n\n"
    "Other useful IDs — reference only, not added to this case\n"
    "4771 — Kerberos pre-authentication failed on a DC. Read FailureCode.\n"
    "4648 — Explicit credentials were used for a logon attempt. Can occur "
    "with RunAs or scheduled tasks; not automatically suspicious.\n"
    "4672 — Sensitive privileges assigned to a new logon session. Correlate "
    "the logon ID; not proof of privilege escalation.\n"
    "4688 — Process creation. Useful for identifying a source process; "
    "command-line visibility depends on audit configuration.\n"
    "4740 — Account lockout. Caller computer can help locate the source.\n\n"
    "Quick field reminders\n"
    "LogonType 2 = interactive; 3 = network; 10 = Remote Desktop. "
    "For 4625 these describe the failed attempt.\n"
    "4776 Status 0xC000006A = bad password; 0xC0000064 = unknown username; "
    "0xC0000234 = locked account; 0x0 = success.\n"
    "4625 can use generic Status 0xC000006D with a more specific SubStatus "
    "such as 0xC000006A. Read both.\n"
    "4771 uses Kerberos codes: 0x18 = invalid pre-authentication information, "
    "commonly an incorrect password. Do not reuse NTLM status mappings.\n\n"
    "These are Windows event IDs, not Wazuh rule IDs. Absence from this "
    "selected dataset is not proof that an event never occurred.\n"
    "Source: Microsoft Learn Windows Security auditing event documentation. "
    "Links and a compact table: docs/windows-event-reference.md."
)


def investigation_context(investigation: SavedInvestigation) -> str:
    """Explain supplied inventory and investigation boundaries without a verdict."""

    environment = investigation.case.environment
    roles = {
        HostRole.DOMAIN_CONTROLLER: "domain controller / domain authentication",
        HostRole.WORKSTATION: "Windows workstation",
        HostRole.MEMBER_SERVER: "domain member server",
    }
    lines = [
        "Analyst brief — inventory context, not event evidence",
        "",
        "Your task is to triage unexplained authentication activity. Establish "
        "what the records show, compare related activity, and decide what "
        "explanation or additional evidence you would need before closing.",
        "",
        "Saved environment",
    ]
    for domain in environment.domains:
        lines.append(f"Domain: {domain.netbios_name} ({domain.dns_name})")
    for host in environment.hosts:
        services = [
            f"{service.kind.value.upper()} on port {service.port}"
            for service in environment.services
            if service.host_id == host.id
        ]
        suffix = f"; {', '.join(services)}" if services else ""
        lines.append(
            f"{host.hostname} — {host.ipv4_address}; {roles[host.role]}{suffix}"
        )
    lines.extend(
        (
            "Known domain identities: "
            + ", ".join(identity.username for identity in environment.identities),
            "Inventory does not establish who was at a keyboard, account "
            "privileges, workstation ownership, or authorization to access a share.",
            "",
            "Useful pivots — buttons below open filtered Evidence",
            "Source timeline: review all supplied records tied to the active "
            "match's source IP. Compare accounts, host observers, and spacing. "
            "An inventory-derived IP remains inventory context.",
            "Earlier activity: inspect the case before the active match's "
            "evaluation window begins, using original event time. "
            "Compare single-account and multi-account activity; "
            "earlier failures are not automatically benign.",
            "Successful logons: review all supplied 4624 records. Compare event "
            "time, account, observer, and LogonType before relating a success "
            "to failed attempts. This is a case-wide search, not post-alert proof.",
            "",
            "Context you would request — unavailable in this exercise",
            "Asset/user ownership and expected access; authorized jobs or change "
            "tickets; source endpoint processes; and later authentication logs. "
            "No ticket search, endpoint query, or collection is performed here. "
            "Write these as evidence gaps and proposed next steps, not findings.",
            "",
            "L1 decision support — no automatic verdict",
            "Escalate when suspicious activity remains unexplained and needs "
            "deeper validation or action beyond your available evidence/access. "
            "State the pattern and uncertainty; compromise need not be proven.",
            "Pending: more evidence needed records the unanswered question and "
            "what you would request. It does not claim that a request was sent.",
            "Close as benign only with a corroborated authorized explanation. "
            "Close as false positive only with evidence that the detection "
            "does not substantiate the suspected behavior. Missing logs alone "
            "do not justify either conclusion.",
            "",
            "Coverage reminder",
            *investigation.case.manifest.limitations,
            "The brief is not a normal-activity baseline or a scenario answer. "
            "There is no hidden user/IT response behind the pivot buttons.",
        )
    )
    return "\n".join(lines)

# Wazuh replay

SimLab uses a temporary Wazuh manager to evaluate exported Windows telemetry.
The indexer, dashboard, and agents are intentionally outside this workflow.

## Security model

The two Wazuh alerts are independent observations:

- event 4776 represents NTLM credential validation on the authority;
- event 4625 represents the failed network logon on the destination.

Each rule requires three different target usernames from the same observed
source within 60 seconds. The level-1 rules qualify bad-password NTLM failures
but use `no_log`, so only the level-10 spray signal is analyst-facing. SimLab's
reference detector remains responsible for merging the two observations into a
single high-confidence finding.

The rule chain is tested against Wazuh 4.14.7. Event 4625 inherits stock rule
60122 (`Logon Failure - Unknown user or bad password`). Wazuh 4.14.7 has no
dedicated stock rule for event 4776, so that chain inherits stock rule 60104
(`Windows audit failure event`) before applying its event-specific filters.

### Logtest compatibility boundary

Real agent events arrive with the `windows_eventchannel` decoder identity.
`wazuh-logtest` instead labels pasted EventChannel-shaped JSON as `json`, even
when its location is set to `EventChannel`. Stock entry rule 60000 therefore
cannot match the replay without a test adapter.

This isolated manager mounts a test-only copy of Wazuh 4.14.7's
`0575-win-base_rules.xml`. Only entry rule 60000 is adapted: its `ossec`
category condition is removed and its decoder identity becomes `json`. The
remaining base rules and all downstream Security rules stay on the pinned stock
lineage. Do not use this patched file in a manager receiving real Windows-agent
events; remove its Compose mount before that later validation.

## Export

Generate telemetry, then export its supported events:

```bash
uv run simlab export wazuh \
  --telemetry outputs/<scenario-id>/<telemetry-id>
```

The resulting directory is
`outputs/wazuh/<telemetry-id>/<wazuh-replay-id>/` and contains:

```text
manifest.json     Source identity and compatibility context
events.jsonl      Input lines targeting Wazuh's EventChannel decoder
provenance.jsonl  One-to-one links back to SimLab event-instance IDs
SHA256SUMS        Exact checksums for the files above
```

The EventChannel representation is derived from SimLab's typed Windows events.
It is structurally targeted at Wazuh but remains explicitly unverified against
an observed Wazuh-agent capture until that sanitized fixture is added.

## Rule-engine validation

Start only the temporary manager:

```bash
docker compose -f integrations/wazuh/compose.yaml up -d
```

Wait until the manager is ready, then open `wazuh-logtest`:

```bash
docker compose -f integrations/wazuh/compose.yaml exec manager \
  /var/ossec/bin/wazuh-logtest
```

Paste the lines from one replay bundle's `events.jsonl` into the same logtest
session, one at a time. Use a new logtest session for each case so frequency
state does not carry between them.

The 60-second correlation window is measured using manager ingestion time, not
the embedded Windows `systemTime`. Submit each control's lines continuously.
This validates native rule-engine correlation, not delayed historical playback.

Expected positive control, generated from `password-spray.yaml`:

- rule 100101 fires once for the third distinct 4625 username;
- rule 100111 fires once for the third distinct 4776 username;
- individual failures are qualified by hidden rules 100100 and 100110.

Expected negative control, generated from `repeated-password-failure.yaml`:

- neither rule 100101 nor 100111 fires;
- all attempts target the same username and therefore do not represent a spray.

Stop and remove the temporary manager when validation is complete:

```bash
docker compose -f integrations/wazuh/compose.yaml down
```

If either distinct-user correlation fails, do not weaken the rules to a simple
failure counter. That result is a compatibility failure requiring reassessment.

## Authoritative references

- [Wazuh 4.14.7 Windows base rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0575-win-base_rules.xml)
- [Wazuh 4.14.7 Windows Security rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0580-win-security_rules.xml)
- [Wazuh rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Wazuh logtest documentation](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Wazuh guidance for EventChannel JSON in logtest](https://github.com/wazuh/wazuh/discussions/25405)

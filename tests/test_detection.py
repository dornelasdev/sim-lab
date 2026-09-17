from datetime import timedelta
from hashlib import sha256
from pathlib import Path

from simlab.analysis import analyze_authentication_bundle, load_analysis_findings
from simlab.artifacts import generate_authentication_bundle, load_authentication_bundle
from simlab.authentication import load_authentication_scenario
from simlab.detection import (
    FindingConfidence,
    FindingSeverity,
    SignalType,
    detect_authentication_password_spray,
    load_password_spray_profile,
)
from simlab.environment import load_environment

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication"
PROFILE_PATH = PROJECT_ROOT / "detections" / "authentication" / "password-spray.yaml"


def _loaded_bundle(tmp_path, route_name):
    environment = load_environment(ENVIRONMENT_PATH)
    scenario = load_authentication_scenario(
        ROUTE_PATH / route_name,
        environment,
    )
    generated = generate_authentication_bundle(scenario, environment, tmp_path)
    return load_authentication_bundle(generated.path)


def test_merges_two_independent_password_spray_signals(tmp_path) -> None:
    bundle = _loaded_bundle(tmp_path, "password-spray.yaml")
    profile = load_password_spray_profile(PROFILE_PATH)

    result = detect_authentication_password_spray(bundle, profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.finding_type == "suspected_password_spray"
    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.confidence is FindingConfidence.HIGH
    assert finding.source_host_id == "ws01"
    assert finding.target_usernames == ("alice", "bob", "carol")
    assert finding.mitre_attack_ids == ("T1110.003",)
    assert len(finding.event_instance_ids) == 6
    assert {signal.signal_type for signal in finding.signals} == {
        SignalType.DOMAIN_CREDENTIAL_VALIDATION,
        SignalType.DESTINATION_LOGON,
    }
    assert "password value is not observable" in finding.limitations[0]


def test_normal_authentication_does_not_create_a_finding(tmp_path) -> None:
    bundle = _loaded_bundle(tmp_path, "normal.yaml")
    profile = load_password_spray_profile(PROFILE_PATH)

    result = detect_authentication_password_spray(bundle, profile)

    assert result.findings == ()


def test_repeated_failures_for_one_user_do_not_meet_distinct_user_threshold(
    tmp_path,
) -> None:
    bundle = _loaded_bundle(tmp_path, "password-spray.yaml")
    profile = load_password_spray_profile(PROFILE_PATH)
    repeated_user_records = tuple(
        record.model_copy(
            update={
                "event": record.event.model_copy(
                    update={
                        "data": record.event.data.model_copy(
                            update={"target_user_name": "alice"}
                        )
                    }
                )
            }
        )
        for record in bundle.records
    )
    repeated_user_bundle = bundle.model_copy(update={"records": repeated_user_records})

    result = detect_authentication_password_spray(repeated_user_bundle, profile)

    assert result.findings == ()


def test_one_independent_signal_has_medium_confidence(tmp_path) -> None:
    bundle = _loaded_bundle(tmp_path, "password-spray.yaml")
    profile = load_password_spray_profile(PROFILE_PATH)
    dc_records = tuple(
        record for record in bundle.records if record.event.event_id == 4776
    )
    single_signal_bundle = bundle.model_copy(update={"records": dc_records})

    result = detect_authentication_password_spray(single_signal_bundle, profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.confidence is FindingConfidence.MEDIUM
    assert [signal.signal_type for signal in finding.signals] == [
        SignalType.DOMAIN_CREDENTIAL_VALIDATION
    ]


def test_unresolved_sources_remain_separate_medium_confidence_findings(
    tmp_path,
) -> None:
    bundle = _loaded_bundle(tmp_path, "password-spray.yaml")
    profile = load_password_spray_profile(PROFILE_PATH)
    manifest = bundle.manifest.model_copy(update={"source_host_aliases": ()})
    unresolved_bundle = bundle.model_copy(update={"manifest": manifest})

    result = detect_authentication_password_spray(unresolved_bundle, profile)

    assert len(result.findings) == 2
    assert all(
        finding.confidence is FindingConfidence.MEDIUM for finding in result.findings
    )
    assert all(finding.source_host_id is None for finding in result.findings)


def test_detector_does_not_use_synthetic_ground_truth_correlation(tmp_path) -> None:
    bundle = _loaded_bundle(tmp_path, "password-spray.yaml")
    profile = load_password_spray_profile(PROFILE_PATH)
    changed_records = tuple(
        record.model_copy(update={"synthetic_correlation_id": f"unrelated-{index}"})
        for index, record in enumerate(bundle.records)
    )
    changed_bundle = bundle.model_copy(update={"records": changed_records})

    original = detect_authentication_password_spray(bundle, profile)
    changed = detect_authentication_password_spray(changed_bundle, profile)

    assert changed == original


def test_sliding_window_detects_activity_across_clock_minute_boundaries(
    tmp_path,
) -> None:
    bundle = _loaded_bundle(tmp_path, "password-spray.yaml")
    profile = load_password_spray_profile(PROFILE_PATH)
    dc_records = [record for record in bundle.records if record.event.event_id == 4776]
    offsets = (59, 90, 118)
    shifted_records = tuple(
        record.model_copy(
            update={
                "event": record.event.model_copy(
                    update={
                        "occurred_at": bundle.records[0].event.occurred_at
                        + timedelta(seconds=offset)
                    }
                )
            }
        )
        for record, offset in zip(dc_records, offsets, strict=True)
    )
    shifted_bundle = bundle.model_copy(update={"records": shifted_records})

    result = detect_authentication_password_spray(shifted_bundle, profile)

    assert len(result.findings) == 1
    assert result.findings[0].confidence is FindingConfidence.MEDIUM


def test_writes_and_reuses_separate_content_addressed_analysis(tmp_path) -> None:
    telemetry_root = tmp_path / "telemetry"
    analysis_root = tmp_path / "analyses"
    bundle = _loaded_bundle(telemetry_root, "password-spray.yaml")

    first = analyze_authentication_bundle(bundle.path, PROFILE_PATH, analysis_root)
    second = analyze_authentication_bundle(bundle.path, PROFILE_PATH, analysis_root)
    findings = load_analysis_findings(first.path)

    assert first.created is True
    assert second.created is False
    assert first.path == second.path
    assert first.path.parent.name == bundle.manifest.telemetry_id
    assert first.manifest.source_telemetry_id == bundle.manifest.telemetry_id
    assert (
        first.manifest.source_manifest_sha256
        == sha256((bundle.path / "manifest.json").read_bytes()).hexdigest()
    )
    assert len(first.manifest.detection_profile_canonical_sha256) == 64
    assert first.manifest.finding_count == 1
    assert len(findings) == 1
    assert set(path.name for path in first.path.iterdir()) == {
        "SHA256SUMS",
        "findings.jsonl",
        "manifest.json",
    }

    checksum_entries = {}
    for line in (first.path / "SHA256SUMS").read_text().splitlines():
        digest, relative_path = line.split("  ", maxsplit=1)
        checksum_entries[relative_path] = digest
    assert checksum_entries == {
        relative_path: sha256((first.path / relative_path).read_bytes()).hexdigest()
        for relative_path in ("findings.jsonl", "manifest.json")
    }

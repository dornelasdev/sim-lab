"""Content-addressed analysis artifacts derived from telemetry bundles."""

from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import Field

from simlab.artifacts import (
    ArtifactFileReference,
    load_authentication_bundle,
)
from simlab.definition import Definition, Identifier
from simlab.detection import (
    AuthenticationFinding,
    detect_authentication_password_spray,
    load_password_spray_profile,
)
from simlab.storage import (
    canonical_json,
    content_address,
    model_digest,
    pretty_json,
    sha256sums,
    write_verified_directory,
)


class AuthenticationAnalysisManifest(Definition):
    """Identity, inputs, and output references for one detection analysis."""

    schema_version: Literal[1] = 1
    kind: Literal["authentication_detection_analysis"] = (
        "authentication_detection_analysis"
    )
    analysis_id: Identifier
    source_telemetry_id: Identifier
    source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    detection_profile_id: Identifier
    detection_profile_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    finding_count: int = Field(ge=0)
    findings: ArtifactFileReference


class AuthenticationAnalysisBundle(Definition):
    """Location and manifest returned after writing or reusing an analysis."""

    path: Path
    manifest: AuthenticationAnalysisManifest
    created: bool


def analyze_authentication_bundle(
    bundle_path: str | Path,
    profile_path: str | Path,
    output_root: str | Path = "outputs/analyses",
) -> AuthenticationAnalysisBundle:
    """Run password-spray detection and store separate analysis artifacts."""

    bundle = load_authentication_bundle(bundle_path)
    profile = load_password_spray_profile(profile_path)
    result = detect_authentication_password_spray(bundle, profile)

    findings_bytes = b"".join(
        canonical_json(finding) + b"\n" for finding in result.findings
    )
    manifest_content = {
        "schema_version": 1,
        "kind": "authentication_detection_analysis",
        "source_telemetry_id": bundle.manifest.telemetry_id,
        "source_manifest_sha256": sha256(
            (bundle.path / "manifest.json").read_bytes()
        ).hexdigest(),
        "detection_profile_id": profile.id,
        "detection_profile_canonical_sha256": model_digest(profile),
        "finding_count": len(result.findings),
        "findings": {
            "path": "findings.jsonl",
        },
    }
    content_files = {"findings.jsonl": findings_bytes}
    analysis_id = content_address("analysis", manifest_content, content_files)
    manifest = AuthenticationAnalysisManifest(
        analysis_id=analysis_id,
        **manifest_content,
    )
    checksummed_files = {
        "manifest.json": pretty_json(manifest),
        **content_files,
    }
    expected_files = {
        **checksummed_files,
        "SHA256SUMS": sha256sums(checksummed_files),
    }
    analysis_path = Path(output_root) / bundle.manifest.telemetry_id / analysis_id
    created = write_verified_directory(analysis_path, expected_files)
    return AuthenticationAnalysisBundle(
        path=analysis_path,
        manifest=manifest,
        created=created,
    )


def load_analysis_findings(
    path: str | Path,
) -> tuple[AuthenticationFinding, ...]:
    """Integrity-check an analysis artifact and load its finding records."""

    analysis_path = Path(path)
    manifest_bytes = (analysis_path / "manifest.json").read_bytes()
    manifest = AuthenticationAnalysisManifest.model_validate_json(manifest_bytes)
    if analysis_path.name != manifest.analysis_id:
        raise ValueError("analysis directory does not match its manifest ID")
    if analysis_path.parent.name != manifest.source_telemetry_id:
        raise ValueError("analysis parent does not match its source telemetry ID")
    if manifest.findings.path != "findings.jsonl":
        raise ValueError("analysis findings path must be 'findings.jsonl'")

    findings_bytes = (analysis_path / manifest.findings.path).read_bytes()
    manifest_content = manifest.model_dump(exclude={"analysis_id"})
    expected_analysis_id = content_address(
        "analysis",
        manifest_content,
        {"findings.jsonl": findings_bytes},
    )
    if manifest.analysis_id != expected_analysis_id:
        raise ValueError("analysis manifest content does not match its analysis ID")

    findings = tuple(
        AuthenticationFinding.model_validate_json(line)
        for line in findings_bytes.splitlines()
        if line
    )
    if len(findings) != manifest.finding_count:
        raise ValueError("findings.jsonl count does not match its manifest")

    checksummed_files = {
        "manifest.json": manifest_bytes,
        "findings.jsonl": findings_bytes,
    }
    expected_files = {
        **checksummed_files,
        "SHA256SUMS": sha256sums(checksummed_files),
    }
    actual_files = {
        file.relative_to(analysis_path).as_posix()
        for file in analysis_path.rglob("*")
        if file.is_file()
    }
    if actual_files != set(expected_files):
        raise ValueError("analysis bundle contains unexpected or missing files")
    if (analysis_path / "SHA256SUMS").read_bytes() != expected_files["SHA256SUMS"]:
        raise ValueError("analysis bundle contains invalid checksums")
    return findings

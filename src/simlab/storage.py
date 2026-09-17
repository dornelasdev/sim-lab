"""Internal deterministic serialization and content-addressed storage helpers."""

import json
import shutil
from datetime import datetime
from enum import Enum
from hashlib import sha256
from ipaddress import IPv4Address
from pathlib import Path
from tempfile import mkdtemp
from typing import Any

from pydantic import BaseModel


def canonical_json(value: Any) -> bytes:
    """Serialize supported project values into deterministic compact JSON."""

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def pretty_json(value: Any) -> bytes:
    """Serialize supported project values into deterministic readable JSON."""

    return (
        json.dumps(normalize(value), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def model_digest(model: BaseModel) -> str:
    """Return the SHA-256 digest of a normalized model."""

    return sha256(canonical_json(model)).hexdigest()


def content_address(
    prefix: str,
    metadata: Any,
    files: dict[str, bytes],
) -> str:
    """Identify semantic metadata together with exact generated file content."""

    identity = {
        "metadata": metadata,
        "files": _checksum_entries(files),
    }
    return f"{prefix}-{sha256(canonical_json(identity)).hexdigest()}"


def sha256sums(files: dict[str, bytes]) -> bytes:
    """Render conventional SHA256SUMS content for the supplied files."""

    return "".join(
        f"{entry['sha256']}  {entry['path']}\n" for entry in _checksum_entries(files)
    ).encode("utf-8")


def write_verified_directory(destination: Path, files: dict[str, bytes]) -> bool:
    """Atomically create a directory or verify that identical content exists."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        verify_directory(destination, files)
        return False

    temporary_path = Path(
        mkdtemp(prefix=f".{destination.name}-", dir=destination.parent)
    )
    try:
        _write_files(temporary_path, files)
        temporary_path.rename(destination)
    except Exception:
        if temporary_path.exists():
            shutil.rmtree(temporary_path)
        if destination.exists():
            verify_directory(destination, files)
            return False
        raise
    return True


def verify_directory(root: Path, expected: dict[str, bytes]) -> None:
    """Reject a content-addressed directory whose files do not match."""

    if not root.is_dir():
        raise FileExistsError(f"bundle path exists but is not a directory: {root}")

    actual = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    if actual != expected:
        raise FileExistsError(
            f"bundle path exists with content that does not match its ID: {root}"
        )


def normalize(value: Any) -> Any:
    """Convert project model values into deterministic JSON-compatible values."""

    if isinstance(value, BaseModel):
        return {
            field.serialization_alias or name: normalize(getattr(value, name))
            for name, field in type(value).model_fields.items()
        }
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        normalized = [normalize(item) for item in value]
        return sorted(normalized, key=canonical_json)
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (IPv4Address, Path)):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    return value


def _write_files(root: Path, files: dict[str, bytes]) -> None:
    for relative_path, content in files.items():
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)


def _checksum_entries(files: dict[str, bytes]) -> list[dict[str, str]]:
    return [
        {"path": path, "sha256": sha256(content).hexdigest()}
        for path, content in sorted(files.items())
    ]

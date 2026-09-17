"""Shared primitives for declarative SimLab definitions."""

from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, StringConstraints

Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9-]*$"),
]


class Definition(BaseModel):
    """Apply consistent validation rules to SimLab definition files."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_by_alias=True,
        validate_by_name=True,
    )


def read_yaml(path: str | Path) -> Any:
    """Read a UTF-8 YAML definition from disk."""

    definition_path = Path(path)
    with definition_path.open(encoding="utf-8") as file:
        return yaml.safe_load(file)

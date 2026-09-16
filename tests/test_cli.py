from pathlib import Path

from simlab.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication" / "normal.yaml"


def test_generates_and_reuses_authentication_bundle_from_cli(
    tmp_path,
    capsys,
) -> None:
    arguments = [
        "generate",
        "authentication",
        "--environment",
        str(ENVIRONMENT_PATH),
        "--route",
        str(ROUTE_PATH),
        "--output-root",
        str(tmp_path),
    ]

    assert main(arguments) == 0
    created_output = capsys.readouterr()
    assert created_output.err == ""
    assert created_output.out.startswith("created: ")

    assert main(arguments) == 0
    reused_output = capsys.readouterr()
    assert reused_output.err == ""
    assert reused_output.out.startswith("reused: ")


def test_returns_error_for_missing_definition(tmp_path, capsys) -> None:
    exit_code = main(
        [
            "generate",
            "authentication",
            "--environment",
            str(tmp_path / "missing.yaml"),
            "--route",
            str(ROUTE_PATH),
        ]
    )

    output = capsys.readouterr()
    assert exit_code == 1
    assert output.out == ""
    assert output.err.startswith("error: ")

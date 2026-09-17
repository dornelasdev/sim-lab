from pathlib import Path

from simlab.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication" / "normal.yaml"
SPRAY_ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication" / "password-spray.yaml"
PROFILE_PATH = PROJECT_ROOT / "detections" / "authentication" / "password-spray.yaml"


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


def test_detects_authentication_bundle_from_cli(tmp_path, capsys) -> None:
    telemetry_root = tmp_path / "telemetry"
    analysis_root = tmp_path / "analyses"
    assert (
        main(
            [
                "generate",
                "authentication",
                "--environment",
                str(ENVIRONMENT_PATH),
                "--route",
                str(SPRAY_ROUTE_PATH),
                "--output-root",
                str(telemetry_root),
            ]
        )
        == 0
    )
    generated_output = capsys.readouterr()
    bundle_path = generated_output.out.removeprefix("created: ").strip()

    arguments = [
        "detect",
        "authentication",
        "--telemetry",
        bundle_path,
        "--profile",
        str(PROFILE_PATH),
        "--output-root",
        str(analysis_root),
    ]
    assert main(arguments) == 0
    detection_output = capsys.readouterr()
    assert detection_output.err == ""
    assert detection_output.out.startswith("created: ")

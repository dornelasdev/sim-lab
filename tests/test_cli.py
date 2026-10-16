from pathlib import Path

import pytest

from simlab.cli import build_parser, main


def test_launches_investigation_tui_from_explicit_subcommand(tmp_path, monkeypatch):
    launched = []
    monkeypatch.setattr(
        "simlab.tui.run_tui", lambda project_root: launched.append(project_root)
    )

    assert main(["tui", "--project-root", str(tmp_path)]) == 0
    assert launched == [tmp_path]


def test_prepare_parser_preserves_explicit_locations(tmp_path):
    arguments = build_parser().parse_args(
        [
            "prepare",
            "password-spray",
            "--project-root",
            str(tmp_path / "project"),
            "--output-root",
            str(tmp_path / "evidence"),
        ]
    )

    assert arguments.exercise == "password-spray"
    assert arguments.project_root == tmp_path / "project"
    assert arguments.output_root == tmp_path / "evidence"


def test_tui_parser_defaults_to_current_project():
    arguments = build_parser().parse_args(["tui"])
    assert arguments.project_root == Path.cwd()


@pytest.mark.parametrize("command", ["generate", "detect", "export"])
def test_retired_commands_are_not_available(command, capsys):
    with pytest.raises(SystemExit) as error:
        main([command])

    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_prepare_returns_readable_error_for_missing_project(tmp_path, capsys):
    output_root = tmp_path / "outputs"
    assert (
        main(
            [
                "prepare",
                "password-spray",
                "--project-root",
                str(tmp_path / "missing-project"),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("error: ")
    assert not output_root.exists()

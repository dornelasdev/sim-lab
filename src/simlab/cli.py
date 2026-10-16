"""Command-line entry points for preparing and opening SOC investigations."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    """Expose only the active investigation commands."""

    parser = argparse.ArgumentParser(prog="simlab")
    commands = parser.add_subparsers(dest="command", required=True)

    tui = commands.add_parser("tui", help="Open the SOC investigation workspace.")
    tui.add_argument(
        "--project-root",
        default=Path.cwd(),
        type=Path,
        help="Project directory (default: current directory).",
    )
    tui.set_defaults(handler=_run_tui)

    prepare = commands.add_parser(
        "prepare",
        help="Prepare one investigation and collect actual Wazuh rule-test results.",
    )
    prepare.add_argument("exercise", choices=("password-spray",))
    prepare.add_argument("--project-root", default=Path.cwd(), type=Path)
    prepare.add_argument("--output-root", type=Path)
    prepare.set_defaults(handler=_prepare_investigation)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a SimLab command and return a process exit code."""

    arguments = build_parser().parse_args(argv)
    try:
        return arguments.handler(arguments)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _run_tui(arguments: argparse.Namespace) -> int:
    from simlab.tui import run_tui

    run_tui(arguments.project_root)
    return 0


def _prepare_investigation(arguments: argparse.Namespace) -> int:
    from simlab.wazuh_evaluation import prepare_password_spray_investigation

    output_root = arguments.output_root or arguments.project_root / "outputs"
    prepared = prepare_password_spray_investigation(arguments.project_root, output_root)
    print(f"Case evidence: {prepared.case.path}")
    print(f"Wazuh evaluation: {prepared.evaluation_path}")
    print(
        f"Evidence: {prepared.case.manifest.event_count} events; "
        f"Wazuh spray rule-test matches: {len(prepared.alerts)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line entry point for SimLab workflows."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from simlab.analysis import analyze_authentication_bundle
from simlab.artifacts import generate_authentication_bundle
from simlab.authentication import load_authentication_scenario
from simlab.environment import load_environment
from simlab.wazuh import export_wazuh_replay


def build_parser() -> argparse.ArgumentParser:
    """Build the public SimLab command hierarchy."""

    parser = argparse.ArgumentParser(prog="simlab")
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser(
        "generate",
        help="Generate deterministic lab artifacts.",
    )
    generators = generate.add_subparsers(dest="generator", required=True)

    authentication = generators.add_parser(
        "authentication",
        help="Generate Windows telemetry from an authentication route.",
    )
    authentication.add_argument(
        "--environment",
        required=True,
        type=Path,
        help="Path to the corporate environment YAML definition.",
    )
    authentication.add_argument(
        "--route",
        required=True,
        type=Path,
        help="Path to the authentication route YAML definition.",
    )
    authentication.add_argument(
        "--output-root",
        default=Path("outputs"),
        type=Path,
        help="Generated artifact root (default: outputs).",
    )
    authentication.set_defaults(handler=_generate_authentication)

    detect = commands.add_parser(
        "detect",
        help="Analyze generated lab artifacts.",
    )
    detectors = detect.add_subparsers(dest="detector", required=True)

    authentication_detection = detectors.add_parser(
        "authentication",
        help="Detect password-spray behavior in an authentication bundle.",
    )
    authentication_detection.add_argument(
        "--telemetry",
        required=True,
        type=Path,
        help="Path to an authentication telemetry bundle.",
    )
    authentication_detection.add_argument(
        "--profile",
        required=True,
        type=Path,
        help="Path to a password-spray detection profile.",
    )
    authentication_detection.add_argument(
        "--output-root",
        default=Path("outputs/analyses"),
        type=Path,
        help="Analysis artifact root (default: outputs/analyses).",
    )
    authentication_detection.set_defaults(handler=_detect_authentication)

    export = commands.add_parser(
        "export",
        help="Export telemetry for an external security platform.",
    )
    exporters = export.add_subparsers(dest="exporter", required=True)

    wazuh = exporters.add_parser(
        "wazuh",
        help="Export Windows telemetry for Wazuh EventChannel replay.",
    )
    wazuh.add_argument(
        "--telemetry",
        required=True,
        type=Path,
        help="Path to an authentication telemetry bundle.",
    )
    wazuh.add_argument(
        "--output-root",
        default=Path("outputs/wazuh"),
        type=Path,
        help="Wazuh replay artifact root (default: outputs/wazuh).",
    )
    wazuh.set_defaults(handler=_export_wazuh)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a SimLab command and return a process exit code."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        return arguments.handler(arguments)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _generate_authentication(arguments: argparse.Namespace) -> int:
    environment = load_environment(arguments.environment)
    scenario = load_authentication_scenario(arguments.route, environment)
    bundle = generate_authentication_bundle(
        scenario,
        environment,
        arguments.output_root,
    )
    action = "created" if bundle.created else "reused"
    print(f"{action}: {bundle.path}")
    return 0


def _detect_authentication(arguments: argparse.Namespace) -> int:
    analysis = analyze_authentication_bundle(
        arguments.telemetry,
        arguments.profile,
        arguments.output_root,
    )
    action = "created" if analysis.created else "reused"
    print(f"{action}: {analysis.path}")
    return 0


def _export_wazuh(arguments: argparse.Namespace) -> int:
    replay = export_wazuh_replay(
        arguments.telemetry,
        arguments.output_root,
    )
    action = "created" if replay.created else "reused"
    print(f"{action}: {replay.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

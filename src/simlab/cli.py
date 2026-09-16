"""Command-line entry point for SimLab workflows."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from simlab.artifacts import generate_authentication_bundle
from simlab.authentication import load_authentication_scenario
from simlab.environment import load_environment


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


if __name__ == "__main__":
    raise SystemExit(main())

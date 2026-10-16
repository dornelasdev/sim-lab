"""Start the first investigation using the existing real Wazuh preparation path."""

import asyncio
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static
from textual.worker import Worker

from simlab.investigation_tui import InvestigationScreen
from simlab.wazuh_evaluation import (
    PreparedInvestigation,
    prepare_password_spray_investigation,
)


class PreparationScreen(Screen):
    """Prepare on explicit request; reviewing the result remains Docker-free."""

    CSS_PATH = "preparation.tcss"
    BINDINGS = [("escape", "back", "Back"), ("g", "guide", "Guide")]

    def __init__(self, project_root: Path, output_root: Path) -> None:
        super().__init__()
        self.project_root = project_root
        self.output_root = output_root
        self.busy = False
        self.prepared: PreparedInvestigation | None = None
        self.worker: Worker[None] | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with (
            VerticalScroll(id="preparation-page"),
            Vertical(id="preparation-card", classes="panel") as card,
        ):
            card.border_title = "Start an investigation"
            yield Static(
                "Current exercise: unexplained domain authentication activity.\n"
                "Environment: CORP, with DC01, WS01, and the FS01 SMB server.",
                id="preparation-brief",
                markup=False,
            )
            yield Static(
                "Prepare case creates reproducible evidence and collects actual "
                "Wazuh rule-test results. Then open the investigation to review "
                "Alert → Evidence → Context → Assessment.\n\n"
                "Docker Desktop and the existing Wazuh manager must be running. "
                "Start the manager yourself if needed:\n"
                "docker compose -f integrations/wazuh/compose.yaml up -d\n\n"
                "SimLab does not start/stop Docker, change manager configuration, "
                "or substitute a local detector. Existing cases and reports "
                "remain intact. New preparation produces a separate evaluation.",
                id="preparation-runtime",
                markup=False,
            )
            yield Static(
                "Ready. No Wazuh evaluation runs until you choose Prepare case.",
                id="preparation-status",
                markup=False,
            )
            with Horizontal(id="preparation-actions"):
                yield Button("Prepare case", id="prepare-case", variant="primary")
                yield Button("Open investigation", id="prepare-open", disabled=True)
                yield Button("Main menu", id="prepare-back")
                yield Button("Guide", id="prepare-guide")
        yield Footer()

    @on(Button.Pressed, "#prepare-case")
    def start_preparation(self) -> None:
        if self.busy or self.prepared is not None:
            return
        self.busy = True
        self.update_controls()
        self.query_one("#preparation-status", Static).update(
            Text(
                "Preparing evidence and collecting real Wazuh results…\n"
                "The interface stays responsive. Keep it open and wait for "
                "completion; this run cannot be cancelled from this page."
            )
        )
        self.worker = self.prepare_in_background()

    @work(group="case-preparation", exit_on_error=False)
    async def prepare_in_background(self) -> None:
        try:
            prepared = await asyncio.to_thread(
                prepare_password_spray_investigation,
                self.project_root,
                self.output_root,
            )
        except Exception as error:
            # This is a UI boundary: retain runtime errors without losing the app.
            self.log.error("Investigation preparation failed", error)
            self.query_one("#preparation-status", Static).update(
                Text(
                    f"Preparation failed: {error}\n"
                    "No fallback detector was used. Check the manager and retry. "
                    "Evidence may already have been saved; existing artifacts "
                    "are not deleted. You can also return to open a saved case."
                )
            )
            self.query_one("#prepare-case", Button).label = "Retry preparation"
        else:
            self.prepared = prepared
            self.query_one("#preparation-status", Static).update(
                Text(
                    f"Ready: {prepared.case.manifest.event_count} evidence events; "
                    f"{len(prepared.alerts)} Wazuh rule-test matches.\n"
                    f"Saved evaluation: {prepared.evaluation_path.name}\n"
                    "Open investigation verifies these saved artifacts. "
                    "Wazuh can be stopped manually after preparation."
                )
            )
        finally:
            self.busy = False
            if self.is_mounted:
                self.update_controls()

    def update_controls(self) -> None:
        self.query_one("#prepare-case", Button).disabled = (
            self.busy or self.prepared is not None
        )
        self.query_one("#prepare-open", Button).disabled = (
            self.busy or self.prepared is None
        )
        self.query_one("#prepare-back", Button).disabled = self.busy

    @on(Button.Pressed, "#prepare-open")
    def open_investigation(self) -> None:
        if self.busy or self.prepared is None:
            return
        self.app.switch_screen(
            InvestigationScreen(
                self.output_root, evaluation_path=self.prepared.evaluation_path
            )
        )

    @on(Button.Pressed, "#prepare-back")
    def action_back(self) -> None:
        if self.busy:
            self.app.notify("Preparation is still running. Wait before leaving.")
            return
        self.app.pop_screen()

    @on(Button.Pressed, "#prepare-guide")
    def action_guide(self) -> None:
        from simlab.tui import GuideScreen

        self.app.push_screen(
            GuideScreen(
                "Starting an investigation",
                "Start Docker and the existing manager manually, then choose "
                "Prepare case. The same real-engine workflow is available as "
                "uv run simlab prepare password-spray.\n\n"
                "Preparation runs off the UI thread, so the terminal remains "
                "responsive. Duplicate runs and Back are disabled until it "
                "finishes. Normal quit actions are blocked while preparation "
                "runs, including with the Guide open. Forced terminal closure "
                "is not a supported cancellation mechanism.\n\n"
                "Failures remain visible and can be retried; there is no local "
                "detector fallback. Evidence saved before a failure is retained. "
                "No manager settings, ports, credentials, or volumes are changed.\n\n"
                "Open investigation goes directly to this run's verified saved "
                "case. Reviewing it needs no running manager. Open prepared "
                "investigation on the main menu lists previous evaluations and "
                "restores their saved assessments. Preparing again is not needed "
                "to resume an existing investigation.\n\n"
                "These are simulated Windows records evaluated by real Wazuh "
                "rule testing, not live endpoint captures or persisted SIEM alerts.",
            )
        )

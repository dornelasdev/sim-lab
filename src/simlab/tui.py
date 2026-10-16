"""Main menu, shared theme, and read-only overlays for SOC investigations."""

from pathlib import Path

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.theme import Theme
from textual.widgets import Button, Footer, Header, Static

SIMLAB_THEME = Theme(
    name="simlab-soc",
    primary="#73ADB8",
    secondary="ansi_default",
    accent="#8AC3CC",
    success="#519873",
    warning="#B88B43",
    error="#B6535D",
    ansi=True,
    variables={
        "ansi-background": "ansi_default",
        "ansi-foreground": "ansi_default",
        "title-color": "#A8BED2",
        "action-color": "#719FB8",
        "action-focus-color": "#A5D7DF",
        "dropdown-hover-background": "#243640",
        "dropdown-active-background": "#315D66",
        "dropdown-highlight-foreground": "#F0F5F6",
        "block-cursor-background": "ansi_default",
        "block-cursor-blurred-background": "ansi_default",
        "block-cursor-foreground": "#8AC3CC",
        "block-cursor-blurred-foreground": "ansi_default",
        "block-cursor-text-style": "bold underline",
        "border": "#8AC3CC",
        "border-blurred": "ansi_default",
        "button-color-foreground": "ansi_default",
        "button-focus-text-style": "bold",
        "footer-key-foreground": "#719FB8",
        "input-selection-background": "ansi_default",
        "input-selection-foreground": "ansi_default",
        "scrollbar": "ansi_default",
        "scrollbar-active": "#8AC3CC",
        "scrollbar-hover": "#8AC3CC",
        "scrollbar-background": "ansi_default",
        "scrollbar-background-hover": "ansi_default",
        "scrollbar-background-active": "ansi_default",
    },
)

WELCOME_GUIDE = (
    "Start investigation\n"
    "Prepare the first exercise with the existing running Wazuh manager, then "
    "open that exact saved result. Docker startup/shutdown stays manual. The "
    "preparation page explains the prerequisite and displays retryable errors.\n\n"
    "Open prepared investigation\n"
    "Resume a saved case and its Wazuh rule-test evaluation without running "
    "Docker. Reopening an evaluation restores its saved assessment. You do not "
    "need to prepare again to resume it.\n\n"
    "Investigation flow\n"
    "Alert → Evidence → Context → Assessment. Inspect the independent Wazuh "
    "matches, search event evidence, use contextual pivots, and save your "
    "reasoning separately from the source artifacts. The investigation Guide "
    "includes Windows event-ID notes and explains coverage limitations.\n\n"
    "Fidelity\n"
    "Windows records are simulated. Wazuh evaluation uses the real manager's "
    "rule-test engine; results are not persisted dashboard alerts. No local "
    "detector substitutes for an unavailable manager. No real escalation or "
    "endpoint response is performed by a saved recommendation."
)


class GuideScreen(ModalScreen[None]):
    """Show scrollable read-only guidance or a saved report."""

    BINDINGS = [
        ("escape", "close", "Close"),
        ("g", "close", "Close guide"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, title: str, content: str) -> None:
        super().__init__()
        self.guide_title = title
        self.guide_content = content

    def compose(self) -> ComposeResult:
        with Vertical(id="guide-dialog", classes="panel") as dialog:
            dialog.border_title = Text(self.guide_title)
            with VerticalScroll(id="guide-content-scroll"):
                yield Static(self.guide_content, id="guide-content", markup=False)
            with Horizontal(id="guide-actions"):
                yield Button("Close guide", id="close-guide", variant="primary")

    @on(Button.Pressed, "#close-guide")
    def close_button(self) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


class SimLabApp(App[None]):
    """Start or resume the SOC investigation flow without legacy dependencies."""

    TITLE = "SimLab"
    SUB_TITLE = "SOC practice · Investigations"
    BINDINGS = [("q", "quit", "Quit"), ("g", "toggle_guide", "Guide")]
    CSS_PATH = "simlab.tcss"

    def get_theme_variable_defaults(self) -> dict[str, str]:
        """Keep application styles usable when a built-in theme is selected."""

        return {
            **super().get_theme_variable_defaults(),
            **{
                name: SIMLAB_THEME.variables[name]
                for name in (
                    "ansi-background",
                    "ansi-foreground",
                    "title-color",
                    "action-color",
                    "action-focus-color",
                    "dropdown-hover-background",
                    "dropdown-active-background",
                    "dropdown-highlight-foreground",
                )
            },
        }

    def __init__(
        self,
        project_root: str | Path,
        output_root: str | Path | None = None,
    ) -> None:
        super().__init__()
        self.register_theme(SIMLAB_THEME)
        self.theme = SIMLAB_THEME.name
        self.project_root = Path(project_root).resolve()
        self.output_root = (
            Path(output_root).resolve()
            if output_root is not None
            else self.project_root / "outputs"
        )

    def compose(self) -> ComposeResult:
        yield Header()
        with (
            VerticalScroll(id="welcome-page"),
            Vertical(id="welcome-card", classes="panel") as card,
        ):
            card.border_title = "SOC investigation workspace"
            yield Static(
                "Start the first exercise or resume a saved investigation.",
                markup=False,
            )
            yield Button(
                "Start investigation", id="start-preparation", variant="primary"
            )
            yield Button("Open prepared investigation", id="start-investigation")
            yield Button("Guide", id="welcome-guide")
        yield Footer()

    @on(Button.Pressed, "#start-preparation")
    def start_preparation(self) -> None:
        from simlab.preparation_tui import PreparationScreen

        self.push_screen(PreparationScreen(self.project_root, self.output_root))

    @on(Button.Pressed, "#start-investigation")
    def start_investigation(self) -> None:
        from simlab.investigation_tui import InvestigationScreen

        self.push_screen(InvestigationScreen(self.output_root))

    @on(Button.Pressed, "#welcome-guide")
    def action_toggle_guide(self) -> None:
        self.push_screen(GuideScreen("Starting an investigation", WELCOME_GUIDE))

    async def action_quit(self) -> None:
        """Guard keyboard and palette exits, including screens under overlays."""

        from simlab.investigation_tui import AssessmentExitScreen, InvestigationScreen
        from simlab.preparation_tui import PreparationScreen

        if any(
            isinstance(screen, PreparationScreen) and screen.busy
            for screen in self.screen_stack
        ):
            self.notify(
                "Preparation is still running. Wait for completion before quitting.",
                severity="warning",
            )
            return
        if any(
            isinstance(screen, AssessmentExitScreen) for screen in self.screen_stack
        ):
            return
        if any(
            isinstance(screen, InvestigationScreen) and screen.has_unsaved_assessment
            for screen in self.screen_stack
        ):
            self.push_screen(AssessmentExitScreen(quitting=True), self.confirm_quit)
            return
        await super().action_quit()

    def confirm_quit(self, discard: bool | None) -> None:
        if discard:
            self.exit()


def run_tui(project_root: str | Path = ".") -> None:
    """Launch the SOC investigation terminal interface."""

    SimLabApp(project_root).run()

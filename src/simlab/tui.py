"""Guided full-screen terminal interface for SimLab workflows."""

from contextlib import suppress
from enum import StrEnum
from functools import partial
from pathlib import Path
from shlex import join as shell_join

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.theme import Theme
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Footer,
    Header,
    Label,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from simlab.analysis import load_analysis_findings
from simlab.artifacts import AuthenticationTelemetryManifest
from simlab.authentication import AuthenticationScenario, load_authentication_scenario
from simlab.definition import read_yaml
from simlab.detection import (
    AuthenticationFinding,
    PasswordSprayDetectionProfile,
    load_password_spray_profile,
)
from simlab.environment import CorporateEnvironment, load_environment
from simlab.wazuh import SUPPORTED_EVENT_IDS, WAZUH_MANAGER_VERSION
from simlab.workflow import (
    DefinitionStatus,
    TelemetryDefinitionContext,
    TelemetryEventView,
    TelemetryInspection,
    discover_workflow_catalog,
    inspect_telemetry_bundle,
    resolve_telemetry_definition_context,
    run_detection_stage,
    run_generation_stage,
    run_wazuh_export_stage,
)

SIMLAB_THEME = Theme(
    name="simlab-soc",
    primary="#367983",
    secondary="#394D54",
    accent="#4A8690",
    success="#519873",
    warning="#B88B43",
    error="#B6535D",
    foreground="#CDD5DA",
    background="#06090D",
    surface="#0D1218",
    panel="#10161D",
    boost="#1C252D",
    variables={
        "block-cursor-background": "#253B42",
        "block-cursor-blurred-background": "#18262C",
        "block-cursor-foreground": "#E0E6E9",
        "border": "#48656C",
        "border-blurred": "#222A31",
        "button-color-foreground": "#05090C",
        "button-focus-text-style": "bold",
        "footer-key-foreground": "#5B858C",
        "input-selection-background": "#1F3136",
        "scrollbar": "#1E2A31",
        "scrollbar-active": "#365F67",
        "scrollbar-hover": "#293B43",
    },
)


class WorkflowMode(StrEnum):
    """Ways to enter the guided workflow."""

    NEW = "new"
    EXISTING = "existing"


class WorkflowStage(StrEnum):
    """Ordered pages in the guided authentication workflow."""

    ENVIRONMENT = "environment"
    ROUTE = "route"
    ACQUIRE = "acquire"
    INSPECT = "inspect"
    DETECT = "detect"
    EXPORT = "export"


GUIDE_CONTENT: dict[WorkflowStage | None, tuple[str, str]] = {
    None: (
        "Starting a workflow",
        (
            "Purpose\n"
            "Choose whether SimLab should generate deterministic telemetry from "
            "local definitions or inspect an existing telemetry artifact.\n\n"
            "New simulation\n"
            "Builds context from an environment and authentication route before "
            "acquiring telemetry.\n\n"
            "Existing telemetry\n"
            "Starts from a stored bundle and its manifest. Recorded provenance "
            "remains authoritative even if the current local definitions have "
            "changed or are unavailable.\n\n"
            "Navigation states\n"
            "▶ marks the current stage, ✓ a completed stage, ○ an available "
            "stage, and × a locked stage."
        ),
    ),
    WorkflowStage.ENVIRONMENT: (
        "Environment guide",
        (
            "Purpose\n"
            "Select the simulated infrastructure in which authentication occurs. "
            "The definition identifies relevant domains, hosts, services, "
            "identities, and audit coverage.\n\n"
            "What to examine\n"
            "Check whether the available systems and services can support the "
            "authentication behavior you intend to study. The environment is a "
            "declared model, not proof that equivalent infrastructure was run."
        ),
    ),
    WorkflowStage.ROUTE: (
        "Authentication route guide",
        (
            "Purpose\n"
            "Choose the authentication activity SimLab will represent inside the "
            "selected environment.\n\n"
            "What to examine\n"
            "Review the protocol path, participating systems, attempted identities, "
            "and expected Windows events. These expectations state what the "
            "scenario intends to produce; they are not observed evidence."
        ),
    ),
    WorkflowStage.ACQUIRE: (
        "Telemetry acquisition guide",
        (
            "Purpose\n"
            "Create, reuse, or open an exact telemetry bundle for inspection.\n\n"
            "Provenance boundary\n"
            "A bundle manifest records the environment and scenario identities "
            "used for that artifact. After acquisition, those inputs become "
            "read-only for the current workflow. Starting a new simulation clears "
            "only TUI state; it does not delete stored artifacts."
        ),
    ),
    WorkflowStage.INSPECT: (
        "Telemetry inspection guide",
        (
            "Purpose\n"
            "Examine the stored evidence before applying a detection conclusion. "
            "When opening existing telemetry, the manifest supplies the recorded "
            "context even if earlier stages were skipped.\n\n"
            "Overview\n"
            "Summarizes bundle identity, provenance, event totals, host coverage, "
            "and whether recorded definitions still match local definitions.\n\n"
            "Events\n"
            "Lists the Windows events in occurrence order. Use the host, event ID, "
            "target identity, and status together to understand where each part of "
            "the authentication activity became visible.\n\n"
            "Selected event details\n"
            "Shows evidence used to relate an event to its authentication attempt. "
            "Field origin labels distinguish documented, derived, and synthetic "
            "values. SimLab correlation identifiers are ground truth for the "
            "simulation, not fields a defender would receive from Windows.\n\n"
            "XML\n"
            "Shows the stored Windows-event representation for the selected event. "
            "Use it to connect the normalized table view to the artifact that can "
            "be exported for downstream tooling.\n\n"
            "Interpretation boundary\n"
            "Expected-versus-observed comparisons verify whether the bundle matches "
            "its declared scenario. They do not by themselves prove that a "
            "detection would identify the behavior."
        ),
    ),
    WorkflowStage.DETECT: (
        "Detection guide",
        (
            "Purpose\n"
            "Evaluate inspected telemetry using observable conditions from a "
            "detection profile.\n\n"
            "What to examine\n"
            "Review the profile signals, grouping fields, threshold, and time "
            "window before running it. Detection intentionally does not use "
            "SimLab's synthetic ground-truth correlation.\n\n"
            "Result boundary\n"
            "A finding explains what matched the profile; it is an analytical "
            "inference rather than another Windows event. A completed analysis is "
            "locked to its profile. New analysis reuses the same telemetry without "
            "altering it."
        ),
    ),
    WorkflowStage.EXPORT: (
        "Wazuh export guide",
        (
            "Purpose\n"
            "Adapt supported stored Windows events into replay artifacts for the "
            "separate Wazuh runtime workflow.\n\n"
            "What to examine\n"
            "Confirm the supported and omitted event counts, target manager "
            "version, and representation status. Export does not start Docker, "
            "submit events, or run wazuh-logtest. Wazuh ingestion time controls "
            "frequency windows during replay."
        ),
    ),
}


STAGE_ORDER = (
    WorkflowStage.ENVIRONMENT,
    WorkflowStage.ROUTE,
    WorkflowStage.ACQUIRE,
    WorkflowStage.INSPECT,
    WorkflowStage.DETECT,
    WorkflowStage.EXPORT,
)


class GuideScreen(ModalScreen[None]):
    """Show read-only guidance for the current workflow stage."""

    BINDINGS = [
        ("escape", "close", "Close"),
        ("g", "close", "Close guide"),
    ]

    def __init__(self, title: str, content: str) -> None:
        super().__init__()
        self.guide_title = title
        self.guide_content = content

    def compose(self) -> ComposeResult:
        with Vertical(id="guide-dialog"):
            yield Static(self.guide_title, classes="dialog-title", markup=False)
            with VerticalScroll(id="guide-content-scroll"):
                yield Static(self.guide_content, id="guide-content", markup=False)
            with Horizontal(id="guide-actions"):
                yield Button("Close guide", id="close-guide", variant="primary")

    @on(Button.Pressed, "#close-guide")
    def close_button(self) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


class ConfirmResetScreen(ModalScreen[bool]):
    """Confirm that an upstream change may clear downstream workflow state."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static("Change workflow input?", classes="dialog-title")
            yield Static(self.message, id="confirm-message", markup=False)
            with Horizontal(classes="page-actions"):
                yield Button("Keep current workflow", id="cancel-reset")
                yield Button(
                    "Clear downstream state",
                    id="confirm-reset",
                    variant="warning",
                )

    @on(Button.Pressed, "#confirm-reset")
    def confirm(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#cancel-reset")
    def cancel(self) -> None:
        self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


class SimLabApp(App[None]):
    """Guide one authentication workflow through explicit observable stages."""

    TITLE = "SimLab"
    SUB_TITLE = "Guided authentication workflow"
    BINDINGS = [("q", "quit", "Quit"), ("g", "toggle_guide", "Guide")]
    CSS_PATH = "simlab.tcss"

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
        self.analysis_root = self.output_root / "analyses"
        self.wazuh_root = self.output_root / "wazuh"
        self.catalog = discover_workflow_catalog(self.project_root, self.output_root)
        self.mode: WorkflowMode | None = None
        self.active_stage: WorkflowStage | None = None
        self.environment_path: Path | None = None
        self.route_path: Path | None = None
        self.definition_context: TelemetryDefinitionContext | None = None
        self.inspection: TelemetryInspection | None = None
        self.selected_event: TelemetryEventView | None = None
        self.analysis_complete = False
        self.analysis_profile_path: Path | None = None
        self.wazuh_export_complete = False

    def compose(self) -> ComposeResult:
        yield Header()
        with ContentSwitcher(id="root-content", initial="welcome-page"):
            with VerticalScroll(id="welcome-page"), Vertical(id="welcome-card"):
                yield Static("Start a SimLab workflow", classes="welcome-title")
                yield Static(
                    "Generate a new deterministic simulation or inspect an "
                    "existing telemetry bundle with its recorded provenance.",
                    markup=False,
                )
                yield Button(
                    "New simulation",
                    id="start-new",
                    variant="primary",
                )
                yield Button(
                    "Inspect existing telemetry",
                    id="start-existing",
                )
                yield Button("Guide", id="welcome-guide", classes="guide-button")

            with Horizontal(id="workflow-shell"):
                with Vertical(id="sidebar"):
                    yield Static("Workflow", id="sidebar-title")
                    for stage in STAGE_ORDER:
                        yield Button(
                            stage.value.title(),
                            id=f"nav-{stage.value}",
                            classes="stage-button",
                            disabled=True,
                        )
                    yield Button("Guide", id="workflow-guide", classes="guide-button")

                with Vertical(id="main-panel"):
                    with ContentSwitcher(
                        id="stage-content",
                        initial="environment-page",
                    ):
                        with VerticalScroll(
                            id="environment-page",
                            classes="workflow-page",
                        ):
                            yield Static("Choose environment", classes="page-title")
                            yield Static(
                                "The environment defines the AD domain, systems, "
                                "services, identities, and audit coverage available "
                                "to a scenario.",
                                classes="guidance",
                                markup=False,
                            )
                            with Vertical(classes="field", id="environment-picker"):
                                yield Label("Available environments")
                                yield Select(
                                    self._path_options(self.catalog.environments),
                                    prompt="Select an environment",
                                    allow_blank=True,
                                    id="environment-select",
                                )
                            yield Static(
                                "Select an environment to review its security context.",
                                id="environment-context",
                                classes="context-panel",
                                markup=False,
                            )
                            with Horizontal(classes="page-actions"):
                                yield Button("Welcome", id="environment-back")
                                yield Button(
                                    "Next: Route",
                                    id="environment-next",
                                    variant="primary",
                                )

                        with VerticalScroll(
                            id="route-page",
                            classes="workflow-page",
                        ):
                            yield Static(
                                "Choose authentication route",
                                classes="page-title",
                            )
                            yield Static(
                                "A route declares the authentication activity and "
                                "the Windows events expected from it. Expectations "
                                "are not observed evidence.",
                                classes="guidance",
                                markup=False,
                            )
                            with Vertical(classes="field", id="route-picker"):
                                yield Label("Compatible authentication routes")
                                yield Select(
                                    [],
                                    prompt="Select a route",
                                    allow_blank=True,
                                    id="route-select",
                                )
                            yield Static(
                                "Choose a compatible route to review its protocol "
                                "and expected telemetry.",
                                id="route-context",
                                classes="context-panel",
                                markup=False,
                            )
                            with Horizontal(classes="page-actions"):
                                yield Button("Back", id="route-back")
                                yield Button(
                                    "Next: Acquire",
                                    id="route-next",
                                    variant="primary",
                                )

                        with VerticalScroll(
                            id="acquire-page",
                            classes="workflow-page",
                        ):
                            yield Static("Acquire telemetry", classes="page-title")
                            yield Static(
                                "Generation creates or reuses deterministic telemetry. "
                                "Opening existing telemetry treats its manifest as the "
                                "recorded source context.",
                                classes="guidance",
                                markup=False,
                            )
                            yield Static(
                                "Choose a workflow entry path first.",
                                id="acquire-context",
                                classes="context-panel",
                                markup=False,
                            )
                            with Vertical(classes="field", id="telemetry-picker"):
                                yield Label("Current telemetry bundles")
                                yield Select(
                                    self._path_options(self.catalog.telemetry_bundles),
                                    prompt="Select an exact telemetry bundle",
                                    allow_blank=True,
                                    id="telemetry-select",
                                )
                            yield Static(
                                "Select a bundle to preview its recorded identity.",
                                id="telemetry-choice-context",
                                classes="context-panel",
                                markup=False,
                            )
                            with Horizontal(classes="page-actions"):
                                yield Button("Back", id="acquire-back")
                                yield Button(
                                    "Generate telemetry",
                                    id="generate",
                                    variant="primary",
                                )
                                yield Button(
                                    "Inspect selected telemetry",
                                    id="inspect",
                                    variant="primary",
                                )
                                yield Button(
                                    "Start new simulation",
                                    id="restart-simulation",
                                    variant="warning",
                                )

                        with Vertical(id="inspect-page", classes="workflow-page"):
                            yield Static("Inspect telemetry", classes="page-title")
                            yield Static(
                                "Compare declared expectations with verified stored "
                                "events before drawing a detection conclusion.",
                                id="inspection-context",
                                classes="context-panel",
                                markup=False,
                            )
                            with TabbedContent(id="telemetry-results"):
                                with TabPane("Overview", id="overview-pane"):
                                    yield Static(
                                        "Acquire telemetry to view its overview.",
                                        id="overview",
                                        markup=False,
                                    )
                                with (
                                    TabPane("Events", id="events-pane"),
                                    Horizontal(id="event-layout"),
                                ):
                                    yield DataTable(
                                        id="event-table",
                                        cursor_type="row",
                                        zebra_stripes=True,
                                    )
                                    with VerticalScroll(id="event-detail-scroll"):
                                        yield Static(
                                            "Inspect telemetry to view events.",
                                            id="event-detail",
                                            markup=False,
                                        )
                                with TabPane("XML", id="xml-pane"), VerticalScroll():
                                    yield Static(
                                        "Select an event to preview its verified "
                                        "XML artifact.",
                                        id="xml-preview",
                                        markup=False,
                                    )
                            with Horizontal(classes="page-actions"):
                                yield Button("Back", id="inspect-back")
                                yield Button(
                                    "Next: Detect",
                                    id="inspect-next",
                                    variant="primary",
                                )

                        with Vertical(id="detect-page", classes="workflow-page"):
                            with VerticalScroll(id="detect-scroll"):
                                yield Static("Detect behavior", classes="page-title")
                                yield Static(
                                    "A detection profile describes observable "
                                    "conditions. It does not use SimLab ground-truth "
                                    "correlation.",
                                    classes="guidance",
                                    markup=False,
                                )
                                with Vertical(classes="field", id="profile-picker"):
                                    yield Label("Detection profile")
                                    yield Select(
                                        self._path_options(
                                            self.catalog.detection_profiles
                                        ),
                                        prompt="Select a detection profile",
                                        allow_blank=True,
                                        id="profile-select",
                                    )
                                yield Static(
                                    "Select a profile to review its signals and "
                                    "thresholds.",
                                    id="detection-context",
                                    classes="context-panel",
                                    markup=False,
                                )
                                yield Static(
                                    "Run detection after reviewing the profile.",
                                    id="findings",
                                    markup=False,
                                )
                            with Horizontal(classes="page-actions"):
                                yield Button("Back", id="detect-back")
                                yield Button(
                                    "Run detection",
                                    id="detect",
                                    variant="primary",
                                )
                                yield Button(
                                    "New analysis",
                                    id="new-analysis",
                                )
                                yield Button("Next: Export", id="detect-next")

                        with Vertical(id="export-page", classes="workflow-page"):
                            yield Static("Export for Wazuh", classes="page-title")
                            yield Static(
                                "Export adapts supported Windows events for replay. "
                                "It does not start Docker or run wazuh-logtest.",
                                id="export-context",
                                classes="context-panel",
                                markup=False,
                            )
                            with VerticalScroll(id="export-scroll"):
                                yield Static(
                                    "Inspect telemetry before exporting it.",
                                    id="wazuh-result",
                                    markup=False,
                                )
                            with Horizontal(classes="page-actions"):
                                yield Button("Back", id="export-back")
                                yield Button(
                                    "Export Wazuh replay",
                                    id="export-wazuh",
                                    variant="primary",
                                )

                    yield Static("", id="commands", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#event-table", DataTable)
        table.add_columns("Time", "Host", "Event", "User", "Status")

        if len(self.catalog.environments) == 1:
            self.query_one("#environment-select", Select).value = str(
                self.catalog.environments[0]
            )
        if len(self.catalog.detection_profiles) == 1:
            self.query_one("#profile-select", Select).value = str(
                self.catalog.detection_profiles[0]
            )
        self._show_welcome()
        self._update_ui()

    @on(Button.Pressed, "#start-new")
    def start_new(self) -> None:
        self._reset_workflow(WorkflowMode.NEW)
        self._show_stage(WorkflowStage.ENVIRONMENT)

    @on(Button.Pressed, "#start-existing")
    def start_existing(self) -> None:
        self._reset_workflow(WorkflowMode.EXISTING)
        self._show_stage(WorkflowStage.ACQUIRE)

    @on(Button.Pressed, ".guide-button")
    def open_guide(self) -> None:
        self.action_toggle_guide()

    def action_toggle_guide(self) -> None:
        title, content = GUIDE_CONTENT[self.active_stage]
        self.push_screen(GuideScreen(title, content))

    @on(Button.Pressed, ".stage-button")
    def navigate_sidebar(self, event: Button.Pressed) -> None:
        if event.button.id is None:
            return
        stage = WorkflowStage(event.button.id.removeprefix("nav-"))
        if self._stage_available(stage):
            self._show_stage(stage)

    @on(Select.Changed)
    def selection_changed(self, event: Select.Changed) -> None:
        path = self._selection_path(event.select)
        if event.select.id == "environment-select":
            self._preview_environment(path)
        elif event.select.id == "route-select":
            self._preview_route(path)
        elif event.select.id == "telemetry-select":
            self._preview_telemetry(path)
        elif event.select.id == "profile-select":
            if path != self.analysis_profile_path:
                self.analysis_complete = False
                self.analysis_profile_path = None
                self.query_one("#findings", Static).update(
                    "Run detection after reviewing the profile."
                )
            self._preview_detection_profile(path)
        self._update_ui()

    @on(Button.Pressed, "#environment-back")
    def environment_back(self) -> None:
        if self.mode is WorkflowMode.EXISTING and self.inspection is not None:
            self._show_stage(WorkflowStage.INSPECT)
        else:
            self._show_welcome()

    @on(Button.Pressed, "#environment-next")
    def environment_next(self) -> None:
        if self.inspection is not None:
            self._show_stage(WorkflowStage.INSPECT)
            return
        selected = self._selected_path("#environment-select")
        if selected is None:
            self.notify("Select an environment first.", severity="warning")
            return
        if selected != self.environment_path and self._has_environment_dependents():
            self.push_screen(
                ConfirmResetScreen(
                    "Changing the environment clears the selected route, telemetry, "
                    "detection result, and Wazuh export state."
                ),
                partial(self._confirm_environment_change, selected),
            )
            return
        self._commit_environment(selected)

    @on(Button.Pressed, "#route-back")
    def route_back(self) -> None:
        if self.mode is WorkflowMode.EXISTING:
            self._show_stage(WorkflowStage.INSPECT)
        else:
            self._show_stage(WorkflowStage.ENVIRONMENT)

    @on(Button.Pressed, "#route-next")
    def route_next(self) -> None:
        if self.inspection is not None:
            self._show_stage(WorkflowStage.INSPECT)
            return
        selected = self._selected_path("#route-select")
        if selected is None:
            self.notify("Select an authentication route first.", severity="warning")
            return
        if selected != self.route_path and self.inspection is not None:
            self.push_screen(
                ConfirmResetScreen(
                    "Changing the route clears telemetry, detection results, and "
                    "Wazuh export state."
                ),
                partial(self._confirm_route_change, selected),
            )
            return
        self._commit_route(selected)

    @on(Button.Pressed, "#acquire-back")
    def acquire_back(self) -> None:
        if self.inspection is not None:
            self._show_stage(WorkflowStage.INSPECT)
        elif self.mode is WorkflowMode.EXISTING:
            self._show_welcome()
        else:
            self._show_stage(WorkflowStage.ROUTE)

    @on(Button.Pressed, "#restart-simulation")
    def restart_simulation(self) -> None:
        self._reset_workflow(WorkflowMode.NEW)
        self._show_stage(WorkflowStage.ENVIRONMENT)

    @on(Button.Pressed, "#generate")
    def generate(self) -> None:
        if self.environment_path is None or self.route_path is None:
            self.notify(
                "Choose an environment and route first.",
                severity="warning",
            )
            return
        try:
            bundle = run_generation_stage(
                self.environment_path,
                self.route_path,
                self.output_root,
            )
            self._refresh_catalog(selected_telemetry=bundle.path)
            self._load_inspection(bundle.path)
        except (OSError, ValueError) as error:
            self._show_error(error)
            return

        self._show_stage(WorkflowStage.INSPECT)
        action = "Created" if bundle.created else "Reused"
        self.notify(f"{action} telemetry {bundle.manifest.telemetry_id}")

    @on(Button.Pressed, "#inspect")
    def inspect_selected(self) -> None:
        telemetry_path = self._selected_path("#telemetry-select")
        if telemetry_path is None:
            self.notify("Select an exact telemetry bundle.", severity="warning")
            return
        try:
            self._load_inspection(telemetry_path)
        except (OSError, ValueError) as error:
            self._show_error(error)
            return
        self._show_stage(WorkflowStage.INSPECT)

    @on(Button.Pressed, "#inspect-back")
    def inspect_back(self) -> None:
        self._show_stage(WorkflowStage.ACQUIRE)

    @on(Button.Pressed, "#inspect-next")
    def inspect_next(self) -> None:
        self._show_stage(WorkflowStage.DETECT)

    @on(Button.Pressed, "#detect-back")
    def detect_back(self) -> None:
        self._show_stage(WorkflowStage.INSPECT)

    @on(Button.Pressed, "#detect")
    def detect(self) -> None:
        telemetry_path = self._inspected_path()
        profile_path = self._selected_path("#profile-select")
        if telemetry_path is None or profile_path is None:
            self.notify(
                "Inspect telemetry and select a detection profile.",
                severity="warning",
            )
            return

        try:
            analysis = run_detection_stage(
                telemetry_path,
                profile_path,
                self.analysis_root,
            )
            findings = load_analysis_findings(analysis.path)
        except (OSError, ValueError) as error:
            self._show_error(error)
            return

        self.analysis_complete = True
        self.analysis_profile_path = profile_path
        self.query_one("#findings", Static).update(
            Text(self._render_findings(analysis.path, analysis.created, findings))
        )
        self._update_ui()
        action = "Created" if analysis.created else "Reused"
        self.notify(f"{action} analysis {analysis.manifest.analysis_id}")

    @on(Button.Pressed, "#detect-next")
    def detect_next(self) -> None:
        self._show_stage(WorkflowStage.EXPORT)

    @on(Button.Pressed, "#new-analysis")
    def new_analysis(self) -> None:
        self.analysis_complete = False
        self.analysis_profile_path = None
        self.query_one("#findings", Static).update(
            "Select a profile and run a new analysis over the same telemetry."
        )
        self._preview_detection_profile(self._selected_path("#profile-select"))
        self._update_ui()

    @on(Button.Pressed, "#export-back")
    def export_back(self) -> None:
        self._show_stage(WorkflowStage.DETECT)

    @on(Button.Pressed, "#export-wazuh")
    def export_wazuh(self) -> None:
        telemetry_path = self._inspected_path()
        if telemetry_path is None:
            self.notify("Inspect an exact telemetry bundle first.", severity="warning")
            return

        try:
            replay = run_wazuh_export_stage(telemetry_path, self.wazuh_root)
        except (OSError, ValueError) as error:
            self._show_error(error)
            return

        self.wazuh_export_complete = True
        manifest = replay.manifest
        result = "\n".join(
            (
                f"Replay ID: {manifest.replay_id}",
                f"Result: {'created' if replay.created else 'reused'}",
                f"Path: {replay.path}",
                f"Source events: {manifest.source_event_count}",
                f"Exported events: {manifest.exported_event_count}",
                f"Omitted events: {manifest.omitted_event_count}",
                f"Wazuh manager target: {manifest.wazuh_manager_version}",
                f"Representation: {manifest.representation_status}",
                "",
                "Docker and wazuh-logtest remain a separate runtime workflow.",
                "See docs/wazuh-replay.md for the validated commands.",
            )
        )
        self.query_one("#wazuh-result", Static).update(Text(result))
        self._update_ui()
        action = "Created" if replay.created else "Reused"
        self.notify(f"{action} Wazuh replay {manifest.replay_id}")

    @on(DataTable.RowHighlighted, "#event-table")
    def event_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self.inspection is None or event.row_key.value is None:
            return
        instance_id = str(event.row_key.value)
        selected = next(
            (
                item
                for item in self.inspection.events
                if item.event_instance_id == instance_id
            ),
            None,
        )
        if selected is not None:
            self._show_event(selected)

    def _show_welcome(self) -> None:
        self.query_one("#root-content", ContentSwitcher).current = "welcome-page"
        self.active_stage = None

    def _show_stage(self, stage: WorkflowStage) -> None:
        if not self._stage_available(stage):
            return
        self.query_one("#root-content", ContentSwitcher).current = "workflow-shell"
        self.query_one(
            "#stage-content", ContentSwitcher
        ).current = f"{stage.value}-page"
        self.active_stage = stage
        if stage is WorkflowStage.ENVIRONMENT:
            self._refresh_environment_page()
        elif stage is WorkflowStage.ROUTE:
            self._refresh_route_page()
        elif stage is WorkflowStage.ACQUIRE:
            self._refresh_acquire_page()
        elif stage is WorkflowStage.INSPECT:
            self._refresh_inspection_page()
        elif stage is WorkflowStage.DETECT:
            self._preview_detection_profile(self._selected_path("#profile-select"))
        elif stage is WorkflowStage.EXPORT:
            self._refresh_export_page()
        self._update_ui()

    def _reset_workflow(self, mode: WorkflowMode) -> None:
        self.mode = mode
        self.environment_path = None
        self.route_path = None
        self._clear_telemetry_state(clear_selection=True)
        self.query_one("#route-select", Select).set_options([])
        self.query_one("#environment-select", Select).disabled = (
            mode is WorkflowMode.EXISTING
        )
        self.query_one("#route-select", Select).disabled = mode is WorkflowMode.EXISTING
        self._update_ui()

    def _commit_environment(self, path: Path) -> None:
        changed = path != self.environment_path
        if changed:
            self.environment_path = path
            self.route_path = None
            self._clear_telemetry_state(clear_selection=True)
            self._update_route_options(path)
        self._show_stage(WorkflowStage.ROUTE)

    def _confirm_environment_change(self, path: Path, confirmed: bool) -> None:
        if confirmed:
            self._commit_environment(path)

    def _commit_route(self, path: Path) -> None:
        if self.environment_path is None:
            self.notify("Choose an environment first.", severity="warning")
            return
        try:
            environment = load_environment(self.environment_path)
            load_authentication_scenario(path, environment)
        except (OSError, ValueError) as error:
            self._show_error(error)
            return
        if path != self.route_path:
            self.route_path = path
            self._clear_telemetry_state(clear_selection=True)
        self._show_stage(WorkflowStage.ACQUIRE)

    def _confirm_route_change(self, path: Path, confirmed: bool) -> None:
        if confirmed:
            self._commit_route(path)

    def _update_route_options(self, environment_path: Path) -> None:
        try:
            environment = load_environment(environment_path)
        except (OSError, ValueError) as error:
            self._show_error(error)
            return
        compatible: list[Path] = []
        for path in self.catalog.routes:
            try:
                load_authentication_scenario(path, environment)
            except (OSError, ValueError):
                continue
            compatible.append(path)
        selector = self.query_one("#route-select", Select)
        selector.set_options(self._path_options(tuple(compatible)))
        if len(compatible) == 1:
            selector.value = str(compatible[0])

    def _load_inspection(self, path: Path) -> None:
        inspection = inspect_telemetry_bundle(path)
        self.inspection = inspection
        self.definition_context = resolve_telemetry_definition_context(
            inspection,
            self.catalog,
        )
        self.analysis_complete = False
        self.analysis_profile_path = None
        self.wazuh_export_complete = False

        table = self.query_one("#event-table", DataTable)
        table.clear(columns=False)
        for event in inspection.events:
            table.add_row(
                event.occurred_at.isoformat(timespec="milliseconds"),
                event.host_id,
                str(event.event_id),
                event.target_username,
                event.status,
                key=event.event_instance_id,
            )

        self.query_one("#overview", Static).update(
            Text(self._render_overview(inspection))
        )
        if inspection.events:
            self._show_event(inspection.events[0])
        else:
            self.selected_event = None
            self.query_one("#event-detail", Static).update("No events in bundle.")
            self.query_one("#xml-preview", Static).update("No XML events in bundle.")

        self.query_one("#findings", Static).update(
            "Run detection after reviewing the telemetry evidence."
        )
        self.query_one("#wazuh-result", Static).update(
            "Export this exact bundle when it is ready for Wazuh replay."
        )
        self.query_one("#telemetry-results", TabbedContent).active = "overview-pane"
        self._refresh_inspection_page()
        self._refresh_export_page()
        self._update_ui()

    def _show_event(self, event: TelemetryEventView) -> None:
        self.selected_event = event
        lines = [
            f"Event {event.event_id} on {event.host_id}",
            f"Instance: {event.event_instance_id}",
            f"Occurred: {event.occurred_at.isoformat()}",
            f"Computer: {event.computer}",
            f"Attempt: {event.source_attempt_id}",
            f"Authentication: {event.authentication_package}",
            f"Logon type: {event.logon_type}",
            f"XML: {event.xml_path}",
            "",
            "Focused evidence",
        ]
        lines.extend(
            f"{field.name}: {field.value}  [{field.origin}]" for field in event.fields
        )
        lines.extend(("", "Related events from the same attempt"))
        lines.extend(event.related_event_instance_ids or ("None",))
        lines.extend(
            (
                "",
                "Simulation correlation",
                event.synthetic_correlation_id,
                "This identifier is SimLab ground truth, not Windows evidence.",
            )
        )
        self.query_one("#event-detail", Static).update(Text("\n".join(lines)))
        self.query_one("#xml-preview", Static).update(Text(event.xml))

    def _clear_telemetry_state(self, *, clear_selection: bool) -> None:
        self.definition_context = None
        self.inspection = None
        self.selected_event = None
        self.analysis_complete = False
        self.analysis_profile_path = None
        self.wazuh_export_complete = False
        if not self.is_mounted:
            return
        if clear_selection:
            self.query_one("#telemetry-select", Select).clear()
        self.query_one("#event-table", DataTable).clear(columns=False)
        self.query_one("#overview", Static).update(
            "Acquire telemetry to view its overview."
        )
        self.query_one("#event-detail", Static).update(
            "Inspect telemetry to view events."
        )
        self.query_one("#xml-preview", Static).update(
            "Select an event to preview its verified XML artifact."
        )
        self.query_one("#findings", Static).update(
            "Run detection after reviewing the profile."
        )
        self.query_one("#wazuh-result", Static).update(
            "Inspect telemetry before exporting it."
        )

    def _refresh_catalog(self, selected_telemetry: Path | None = None) -> None:
        self.catalog = discover_workflow_catalog(self.project_root, self.output_root)
        selector = self.query_one("#telemetry-select", Select)
        selector.set_options(self._path_options(self.catalog.telemetry_bundles))
        if selected_telemetry is not None:
            selector.value = str(selected_telemetry.resolve())

    def _refresh_environment_page(self) -> None:
        selector = self.query_one("#environment-select", Select)
        locked = self.inspection is not None
        selector.disabled = locked
        self.query_one("#environment-picker").display = not locked
        if locked:
            self.query_one("#environment-context", Static).update(
                Text(self._render_recorded_environment())
            )
            self.query_one("#environment-next", Button).label = "Return to Inspect"
        else:
            self._preview_environment(self._selected_path("#environment-select"))
            self.query_one("#environment-next", Button).label = "Next: Route"

    def _refresh_route_page(self) -> None:
        selector = self.query_one("#route-select", Select)
        locked = self.inspection is not None
        selector.disabled = locked
        self.query_one("#route-picker").display = not locked
        if locked:
            self.query_one("#route-context", Static).update(
                Text(self._render_recorded_route())
            )
            self.query_one("#route-next", Button).label = "Return to Inspect"
        else:
            self._preview_route(self._selected_path("#route-select"))
            self.query_one("#route-next", Button).label = "Next: Acquire"

    def _refresh_acquire_page(self) -> None:
        locked = self.inspection is not None
        existing = self.mode is WorkflowMode.EXISTING
        self.query_one("#telemetry-picker").display = existing and not locked
        self.query_one("#telemetry-choice-context").display = existing or locked
        self.query_one("#inspect", Button).display = existing and not locked
        self.query_one("#generate", Button).display = not existing and not locked
        self.query_one("#restart-simulation", Button).display = locked
        self.query_one("#acquire-back", Button).label = (
            "Back to Inspect" if locked else "Back"
        )
        if locked:
            assert self.inspection is not None
            self.query_one("#acquire-context", Static).update(
                "Telemetry has been acquired. Environment, route, and bundle "
                "identity are now read-only provenance for this workflow."
            )
            self.query_one("#telemetry-choice-context", Static).update(
                Text(self._render_acquired_telemetry())
            )
        elif existing:
            self.query_one("#acquire-context", Static).update(
                "Choose an exact current telemetry bundle. Its manifest records the "
                "environment and scenario identity; local definitions only enrich "
                "that recorded context."
            )
            self._preview_telemetry(self._selected_path("#telemetry-select"))
        else:
            self.query_one("#acquire-context", Static).update(
                Text(self._render_generation_context())
            )

    def _refresh_detection_page(self) -> None:
        locked = self.analysis_complete
        self.query_one("#profile-picker").display = not locked
        self.query_one("#profile-select", Select).disabled = locked
        self.query_one("#detect", Button).display = not locked
        self.query_one("#new-analysis", Button).display = locked
        if locked and self.analysis_profile_path is not None:
            try:
                profile_context = self._render_detection_profile(
                    load_password_spray_profile(self.analysis_profile_path)
                )
            except (OSError, ValueError):
                profile_context = self._display_path(self.analysis_profile_path)
            self.query_one("#detection-context", Static).update(
                Text(
                    f"{profile_context}\n\n"
                    "Analysis result locked to this profile. "
                    "Use New analysis to evaluate the same telemetry with another "
                    "profile."
                )
            )

    def _refresh_inspection_page(self) -> None:
        if self.inspection is None:
            self.query_one("#inspection-context", Static).update(
                "Acquire telemetry before inspection."
            )
            return
        self.query_one("#inspection-context", Static).update(
            Text(self._render_expectation_comparison())
        )

    def _refresh_export_page(self) -> None:
        if self.inspection is None:
            self.query_one("#export-context", Static).update(
                "Inspect telemetry before preparing a Wazuh replay export."
            )
            return
        supported = sum(
            count
            for event_id, count in self.inspection.overview.event_counts
            if event_id in SUPPORTED_EVENT_IDS
        )
        omitted = self.inspection.overview.event_count - supported
        supported_ids = ", ".join(str(event_id) for event_id in SUPPORTED_EVENT_IDS)
        self.query_one("#export-context", Static).update(
            Text(
                "\n".join(
                    (
                        f"Supported event IDs: {supported_ids}",
                        f"Expected export: {supported} events; {omitted} omitted",
                        f"Wazuh manager target: {WAZUH_MANAGER_VERSION}",
                        "Representation: derived pending observed fixture",
                        "Manager ingestion time controls Wazuh frequency windows.",
                        "Docker and wazuh-logtest remain a separate workflow.",
                    )
                )
            )
        )

    def _preview_environment(self, path: Path | None) -> None:
        if self.mode is WorkflowMode.EXISTING and self.inspection is not None:
            return
        if path is None:
            content = "Select an environment to review its security context."
        else:
            try:
                content = self._render_environment(load_environment(path))
            except (OSError, ValueError) as error:
                content = f"Unable to load environment: {error}"
        self.query_one("#environment-context", Static).update(Text(content))

    def _preview_route(self, path: Path | None) -> None:
        if self.mode is WorkflowMode.EXISTING and self.inspection is not None:
            return
        if path is None or self.environment_path is None:
            content = "Choose a compatible route to review its expected telemetry."
        else:
            try:
                environment = load_environment(self.environment_path)
                scenario = load_authentication_scenario(path, environment)
                content = self._render_route(scenario, environment)
            except (OSError, ValueError) as error:
                content = f"Unable to load route: {error}"
        self.query_one("#route-context", Static).update(Text(content))

    def _preview_telemetry(self, path: Path | None) -> None:
        if path is None:
            content = "Select a bundle to preview its recorded identity."
        else:
            try:
                manifest = AuthenticationTelemetryManifest.model_validate_json(
                    (path / "manifest.json").read_bytes()
                )
                content = "\n".join(
                    (
                        f"Telemetry: {manifest.telemetry_id}",
                        f"Environment: {manifest.environment_id}",
                        f"Scenario: {manifest.scenario_id}",
                        f"Recorded events: {manifest.event_count}",
                        f"Path: {path}",
                        "Inspection will verify every stored event, XML file, and "
                        "checksum before displaying evidence.",
                    )
                )
            except (OSError, ValueError) as error:
                content = f"Unable to read telemetry manifest: {error}"
        self.query_one("#telemetry-choice-context", Static).update(Text(content))

    def _preview_detection_profile(self, path: Path | None) -> None:
        if path is None:
            content = "Select a profile to review its signals and thresholds."
        else:
            try:
                content = self._render_detection_profile(
                    load_password_spray_profile(path)
                )
            except (OSError, ValueError) as error:
                content = f"Unable to load detection profile: {error}"
        self.query_one("#detection-context", Static).update(Text(content))

    def _render_environment(self, environment: CorporateEnvironment) -> str:
        domains = ", ".join(
            f"{domain.dns_name} ({domain.netbios_name})"
            for domain in environment.domains
        )
        hosts = ", ".join(
            f"{host.hostname} [{host.role.value}]" for host in environment.hosts
        )
        services = (
            ", ".join(
                f"{service.kind.value.upper()} on {service.host_id}:{service.port}"
                for service in environment.services
            )
            or "None"
        )
        identities = ", ".join(identity.username for identity in environment.identities)
        policies = [
            f"- {policy.name}: "
            + ", ".join(
                f"{setting.category.value}="
                f"{'/'.join(sorted(outcome.value for outcome in setting.outcomes))}"
                for setting in policy.settings
            )
            for policy in environment.audit_policies
        ]
        return "\n".join(
            (
                f"{environment.name} ({environment.id})",
                f"AD domains: {domains}",
                f"Hosts: {hosts}",
                f"Services: {services}",
                f"Identities: {identities}",
                "Audit coverage:",
                *policies,
                "",
                "What to expect: this selection defines the available actors, "
                "systems, and observability. It does not generate events.",
            )
        )

    def _render_route(
        self,
        scenario: AuthenticationScenario,
        environment: CorporateEnvironment,
    ) -> str:
        identities = {
            identity.id: identity.username for identity in environment.identities
        }
        hosts = {host.id: host.hostname for host in environment.hosts}
        attempts = [
            f"- +{attempt.offset_seconds}s "
            f"{identities.get(attempt.identity_id, attempt.identity_id)}: "
            f"{hosts.get(attempt.source_host_id, attempt.source_host_id)} -> "
            f"{hosts.get(attempt.destination_host_id, attempt.destination_host_id)} "
            f"via {hosts.get(attempt.authority_host_id, attempt.authority_host_id)} "
            f"[{attempt.outcome.value}]"
            for attempt in scenario.attempts
        ]
        expected = [
            f"- Event {item.event_id} x{item.count} on {item.host_id}"
            for item in scenario.expected_events
        ]
        return "\n".join(
            (
                f"{scenario.name} ({scenario.id})",
                scenario.description,
                f"Protocol: {scenario.protocol.value.upper()}",
                f"Flow: {scenario.flow.value}",
                f"Service: {scenario.service_id or 'interactive logon'}",
                "Attempts:",
                *attempts,
                "Expected Windows telemetry:",
                *expected,
                "",
                "These expectations are scenario assertions. Inspection verifies "
                "what was actually generated and stored.",
            )
        )

    def _render_generation_context(self) -> str:
        if self.environment_path is None or self.route_path is None:
            return "Choose an environment and route before generating telemetry."
        try:
            environment = load_environment(self.environment_path)
            scenario = load_authentication_scenario(self.route_path, environment)
        except (OSError, ValueError) as error:
            return f"Unable to prepare generation: {error}"
        expected = ", ".join(
            f"{item.event_id} x{item.count} on {item.host_id}"
            for item in scenario.expected_events
        )
        return "\n".join(
            (
                f"Environment: {environment.name} ({environment.id})",
                f"Route: {scenario.name} ({scenario.id})",
                f"Protocol: {scenario.protocol.value.upper()}",
                f"Expected telemetry: {expected}",
                "Generation is deterministic: unchanged validated inputs reuse the "
                "same content-addressed telemetry bundle.",
            )
        )

    def _render_acquired_telemetry(self) -> str:
        assert self.inspection is not None
        overview = self.inspection.overview
        return "\n".join(
            (
                f"Telemetry: {overview.telemetry_id}",
                f"Environment: {overview.environment_id}",
                f"Scenario: {overview.scenario_id}",
                f"Verified events: {overview.event_count}",
                f"Path: {overview.path}",
                "Start new simulation clears only this TUI workflow. Stored "
                "telemetry, analyses, and exports remain unchanged.",
            )
        )

    def _render_expectation_comparison(self) -> str:
        assert self.inspection is not None
        overview = self.inspection.overview
        lines = [
            "Scenario expectations versus verified telemetry",
            "Expectations are declarative; observed counts come from the "
            "integrity-checked bundle.",
        ]
        scenario = self._matching_scenario()
        if scenario is None:
            status = (
                self.definition_context.scenario.status.value
                if self.definition_context is not None
                else "unavailable"
            )
            lines.extend(
                (
                    f"Exact local route definition: {status}",
                    "Expected-versus-observed comparison is unavailable, but the "
                    "recorded telemetry remains inspectable.",
                )
            )
            return "\n".join(lines)

        observed = {
            (host_id, event_id): count
            for host_id, event_id, count in overview.host_event_counts
        }
        expected_keys: set[tuple[str, int]] = set()
        for expectation in scenario.expected_events:
            key = (expectation.host_id, expectation.event_id)
            expected_keys.add(key)
            actual = observed.get(key, 0)
            result = "match" if actual == expectation.count else f"observed {actual}"
            lines.append(
                f"- Event {expectation.event_id} on {expectation.host_id}: "
                f"expected {expectation.count}; {result}"
            )
        for (host_id, event_id), count in sorted(observed.items()):
            if (host_id, event_id) not in expected_keys:
                lines.append(
                    f"- Additional observed event {event_id} on {host_id}: {count}"
                )
        return "\n".join(lines)

    def _render_recorded_environment(self) -> str:
        assert self.inspection is not None
        assert self.definition_context is not None
        context = self.definition_context.environment
        lines = [
            f"Recorded environment: {context.identifier}",
            f"Recorded definition digest: {context.canonical_sha256}",
            f"Local definition status: {context.status.value}",
            f"Local path: {context.path or 'unavailable'}",
        ]
        if context.path is not None:
            with suppress(OSError, ValueError):
                lines.extend(
                    ("", self._render_environment(load_environment(context.path)))
                )
        if context.status is DefinitionStatus.CHANGED:
            lines.extend(
                (
                    "",
                    "The local definition is shown only as current context; it is "
                    "not the exact definition recorded by this telemetry.",
                )
            )
        return "\n".join(lines)

    def _render_recorded_route(self) -> str:
        assert self.inspection is not None
        assert self.definition_context is not None
        context = self.definition_context.scenario
        lines = [
            f"Recorded scenario: {context.identifier}",
            f"Recorded definition digest: {context.canonical_sha256}",
            f"Local definition status: {context.status.value}",
            f"Local path: {context.path or 'unavailable'}",
        ]
        environment_context = self.definition_context.environment
        if context.path is not None and environment_context.path is not None:
            with suppress(OSError, ValueError):
                environment = load_environment(environment_context.path)
                scenario = AuthenticationScenario.model_validate(
                    read_yaml(context.path)
                )
                lines.extend(("", self._render_route(scenario, environment)))
        if context.status is DefinitionStatus.CHANGED:
            lines.extend(
                (
                    "",
                    "The current route may explain the scenario ID, but its content "
                    "does not match the definition recorded by this telemetry.",
                )
            )
        return "\n".join(lines)

    def _matching_scenario(self) -> AuthenticationScenario | None:
        if self.inspection is None:
            return None
        path = (
            self.definition_context.scenario.path
            if self.definition_context is not None
            and self.definition_context.scenario.status is DefinitionStatus.MATCHING
            else None
        )
        if path is None:
            return None
        try:
            return AuthenticationScenario.model_validate(read_yaml(path))
        except (OSError, ValueError):
            return None

    def _render_detection_profile(
        self,
        profile: PasswordSprayDetectionProfile,
    ) -> str:
        credential = profile.signals.domain_credential_validation
        destination = profile.signals.destination_logon
        return "\n".join(
            (
                f"{profile.name} ({profile.id})",
                f"Finding type: {profile.finding_type}",
                f"Threshold: {profile.minimum_distinct_users} distinct users within "
                f"{profile.window_seconds}s ({profile.window_mode} window)",
                f"Signal 1: Event {credential.event_id}, status {credential.status}",
                f"Signal 2: Event {destination.event_id}, status "
                f"{destination.status}/{destination.sub_status}, logon type "
                f"{destination.logon_type}, {destination.authentication_package}",
                f"MITRE ATT&CK: {', '.join(profile.mitre_attack_ids)}",
                "Limitations:",
                *(f"- {limitation}" for limitation in profile.limitations),
                "",
                "These are observable criteria, not a prediction that the selected "
                "telemetry will produce a finding.",
            )
        )

    def _render_overview(self, inspection: TelemetryInspection) -> str:
        overview = inspection.overview
        event_counts = ", ".join(
            f"{event_id}: {count}" for event_id, count in overview.event_counts
        )
        host_counts = ", ".join(
            f"{host_id}: {count}" for host_id, count in overview.host_counts
        )
        started_at = overview.started_at.isoformat() if overview.started_at else "-"
        ended_at = overview.ended_at.isoformat() if overview.ended_at else "-"
        definition_lines: tuple[str, ...] = ()
        if self.definition_context is not None:
            definition_lines = (
                "Local definitions: environment "
                f"{self.definition_context.environment.status.value}; scenario "
                f"{self.definition_context.scenario.status.value}",
            )
        return "\n".join(
            (
                f"Telemetry ID: {overview.telemetry_id}",
                f"Path: {overview.path}",
                f"Environment: {overview.environment_id}",
                f"Scenario: {overview.scenario_id}",
                *definition_lines,
                f"Events: {overview.event_count} ({event_counts})",
                f"Hosts: {host_counts}",
                f"First event: {started_at}",
                f"Last event: {ended_at}",
                f"Event profiles: {', '.join(overview.event_profile_ids)}",
                f"Audit policies: {', '.join(overview.audit_policy_ids)}",
                "",
                "Open Events to inspect evidence and provenance, or XML to review "
                "the matching native event representation.",
            )
        )

    def _render_findings(
        self,
        path: Path,
        created: bool,
        findings: tuple[AuthenticationFinding, ...],
    ) -> str:
        lines = [
            f"Analysis: {'created' if created else 'reused'}",
            f"Path: {path}",
            f"Findings: {len(findings)}",
        ]
        if not findings:
            lines.extend(("", "No finding met the selected profile thresholds."))
            return "\n".join(lines)

        for finding in findings:
            signals = ", ".join(signal.signal_type for signal in finding.signals)
            window = (
                f"{finding.started_at.isoformat()} to {finding.ended_at.isoformat()}"
            )
            lines.extend(
                (
                    "",
                    finding.title,
                    f"ID: {finding.finding_id}",
                    f"Severity: {finding.severity}",
                    f"Confidence: {finding.confidence}",
                    f"Source host: {finding.source_host_id or 'unresolved'}",
                    f"Users: {', '.join(finding.target_usernames)}",
                    f"Signals: {signals}",
                    f"MITRE ATT&CK: {', '.join(finding.mitre_attack_ids)}",
                    f"Window: {window}",
                    "Limitations:",
                    *(f"- {limitation}" for limitation in finding.limitations),
                )
            )
        return "\n".join(lines)

    def _stage_available(self, stage: WorkflowStage) -> bool:
        if self.mode is None:
            return False
        if self.mode is WorkflowMode.EXISTING and stage is WorkflowStage.ACQUIRE:
            return True
        if self.mode is WorkflowMode.EXISTING and stage is WorkflowStage.EXPORT:
            return self.analysis_complete or self.wazuh_export_complete
        if self.mode is WorkflowMode.EXISTING:
            return self.inspection is not None
        availability = {
            WorkflowStage.ENVIRONMENT: True,
            WorkflowStage.ROUTE: self.environment_path is not None,
            WorkflowStage.ACQUIRE: self.route_path is not None,
            WorkflowStage.INSPECT: self.inspection is not None,
            WorkflowStage.DETECT: self.inspection is not None,
            WorkflowStage.EXPORT: (
                self.analysis_complete or self.wazuh_export_complete
            ),
        }
        return availability[stage]

    def _stage_complete(self, stage: WorkflowStage) -> bool:
        if self.mode is WorkflowMode.EXISTING and stage in {
            WorkflowStage.ENVIRONMENT,
            WorkflowStage.ROUTE,
            WorkflowStage.ACQUIRE,
            WorkflowStage.INSPECT,
        }:
            return self.inspection is not None
        completion = {
            WorkflowStage.ENVIRONMENT: self.environment_path is not None,
            WorkflowStage.ROUTE: self.route_path is not None,
            WorkflowStage.ACQUIRE: self.inspection is not None,
            WorkflowStage.INSPECT: self.inspection is not None,
            WorkflowStage.DETECT: self.analysis_complete,
            WorkflowStage.EXPORT: self.wazuh_export_complete,
        }
        return completion[stage]

    def _update_ui(self) -> None:
        if not self.is_mounted:
            return
        state_markers = {
            "active": "▶",
            "done": "✓",
            "open": "○",
            "locked": "×",
        }
        for index, stage in enumerate(STAGE_ORDER, start=1):
            button = self.query_one(f"#nav-{stage.value}", Button)
            available = self._stage_available(stage)
            complete = self._stage_complete(stage)
            if stage is self.active_stage:
                state = "active"
            elif complete:
                state = "done"
            elif available:
                state = "open"
            else:
                state = "locked"
            button.variant = "default"
            for candidate in state_markers:
                button.set_class(candidate == state, f"nav-{candidate}")
            button.label = f"{state_markers[state]} {index} {stage.value.title()}"
            button.tooltip = f"{stage.value.title()}: {state}"
            button.disabled = not available

        existing = self.mode is WorkflowMode.EXISTING
        self.query_one("#environment-next", Button).disabled = (
            not (existing and self.inspection is not None)
            and self._selected_path("#environment-select") is None
        )
        self.query_one("#route-next", Button).disabled = (
            not (existing and self.inspection is not None)
            and self._selected_path("#route-select") is None
        )
        self.query_one("#generate", Button).disabled = not (
            self.mode is WorkflowMode.NEW
            and self.environment_path is not None
            and self.route_path is not None
        )
        self.query_one("#inspect", Button).disabled = not (
            self.mode is WorkflowMode.EXISTING
            and self._selected_path("#telemetry-select") is not None
        )
        profile_selected = self._selected_path("#profile-select") is not None
        self.query_one("#detect", Button).disabled = not (
            self.inspection is not None and profile_selected
        )
        self.query_one("#detect-next", Button).disabled = not self.analysis_complete
        self.query_one("#export-wazuh", Button).disabled = not (
            self.inspection is not None
            and (self.analysis_complete or self.wazuh_export_complete)
        )
        self.query_one("#findings").set_class(
            self.analysis_complete,
            "has-output",
        )
        self.query_one("#wazuh-result").set_class(
            self.wazuh_export_complete,
            "has-output",
        )
        self._refresh_detection_page()
        self._update_commands()

    def _update_commands(self) -> None:
        commands = ["Equivalent CLI commands"]
        if (
            self.mode is WorkflowMode.NEW
            and self.environment_path is not None
            and self.route_path is not None
        ):
            commands.append(
                shell_join(
                    (
                        "uv",
                        "run",
                        "simlab",
                        "generate",
                        "authentication",
                        "--environment",
                        self._display_path(self.environment_path),
                        "--route",
                        self._display_path(self.route_path),
                        "--output-root",
                        self._display_path(self.output_root),
                    )
                )
            )
        profile = self._selected_path("#profile-select")
        telemetry = self._inspected_path()
        if telemetry is not None and profile is not None:
            commands.append(
                shell_join(
                    (
                        "uv",
                        "run",
                        "simlab",
                        "detect",
                        "authentication",
                        "--telemetry",
                        self._display_path(telemetry),
                        "--profile",
                        self._display_path(profile),
                        "--output-root",
                        self._display_path(self.analysis_root),
                    )
                )
            )
        if telemetry is not None:
            commands.append(
                shell_join(
                    (
                        "uv",
                        "run",
                        "simlab",
                        "export",
                        "wazuh",
                        "--telemetry",
                        self._display_path(telemetry),
                        "--output-root",
                        self._display_path(self.wazuh_root),
                    )
                )
            )
        self.query_one("#commands", Static).update(Text("\n".join(commands)))

    def _has_environment_dependents(self) -> bool:
        return self.route_path is not None or self.inspection is not None

    def _selected_path(self, selector: str) -> Path | None:
        return self._selection_path(self.query_one(selector, Select))

    @staticmethod
    def _selection_path(selector: Select) -> Path | None:
        selection = selector.selection
        return Path(str(selection)) if selection is not None else None

    def _inspected_path(self) -> Path | None:
        return self.inspection.overview.path if self.inspection is not None else None

    def _path_options(self, paths: tuple[Path, ...]) -> list[tuple[str, str]]:
        return [(self._display_path(path), str(path)) for path in paths]

    def _display_path(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.project_root).as_posix()
        except ValueError:
            return str(path)

    def _show_error(self, error: Exception) -> None:
        self.notify(str(error), title="Workflow error", severity="error", timeout=8)


def run_tui(project_root: str | Path = ".") -> None:
    """Launch the guided SimLab terminal interface."""

    SimLabApp(project_root).run()

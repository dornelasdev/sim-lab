"""Guided full-screen terminal interface for SimLab workflows."""

from pathlib import Path
from shlex import join as shell_join

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
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
from simlab.detection import AuthenticationFinding
from simlab.workflow import (
    TelemetryEventView,
    TelemetryInspection,
    discover_workflow_catalog,
    inspect_telemetry_bundle,
    run_detection_stage,
    run_generation_stage,
    run_wazuh_export_stage,
)


class SimLabApp(App[None]):
    """Guide one authentication workflow through explicit observable stages."""

    TITLE = "SimLab"
    SUB_TITLE = "Guided authentication workflow"
    BINDINGS = [("q", "quit", "Quit")]
    CSS = """
    Screen {
        layout: vertical;
    }

    #selectors {
        grid-size: 2 2;
        grid-columns: 1fr 1fr;
        grid-rows: auto auto;
        height: auto;
        padding: 0 1;
    }

    .selector {
        height: auto;
        margin: 0 1 1 0;
    }

    .selector Label {
        color: $text-muted;
    }

    #actions {
        height: 3;
        padding: 0 1;
    }

    #actions Button {
        margin-right: 1;
    }

    #stage-status {
        height: 3;
        padding: 1 2;
        background: $panel;
    }

    #results {
        height: 1fr;
    }

    #overview, #findings, #wazuh-result, #xml-preview {
        padding: 1 2;
    }

    #event-layout {
        height: 1fr;
    }

    #event-table {
        width: 3fr;
        height: 1fr;
    }

    #event-detail-scroll {
        width: 2fr;
        height: 1fr;
        border-left: solid $accent;
    }

    #event-detail {
        padding: 1 2;
    }

    #commands {
        height: 7;
        padding: 1 2;
        background: $surface;
        border-top: solid $accent;
        overflow-y: auto;
    }
    """

    def __init__(
        self,
        project_root: str | Path,
        output_root: str | Path | None = None,
    ) -> None:
        super().__init__()
        self.project_root = Path(project_root).resolve()
        self.output_root = (
            Path(output_root).resolve()
            if output_root is not None
            else self.project_root / "outputs"
        )
        self.analysis_root = self.output_root / "analyses"
        self.wazuh_root = self.output_root / "wazuh"
        self.catalog = discover_workflow_catalog(
            self.project_root,
            self.output_root,
        )
        self.inspection: TelemetryInspection | None = None
        self.selected_event: TelemetryEventView | None = None
        self.analysis_complete = False
        self.wazuh_export_complete = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Grid(id="selectors"):
            with Vertical(classes="selector"):
                yield Label("Environment")
                yield Select(
                    self._path_options(self.catalog.environments),
                    prompt="Select an environment",
                    allow_blank=True,
                    id="environment-select",
                )
            with Vertical(classes="selector"):
                yield Label("Authentication route")
                yield Select(
                    self._path_options(self.catalog.routes),
                    prompt="Select a route",
                    allow_blank=True,
                    id="route-select",
                )
            with Vertical(classes="selector"):
                yield Label("Detection profile")
                yield Select(
                    self._path_options(self.catalog.detection_profiles),
                    prompt="Select a detection profile",
                    allow_blank=True,
                    id="profile-select",
                )
            with Vertical(classes="selector"):
                yield Label("Exact telemetry bundle")
                yield Select(
                    self._path_options(self.catalog.telemetry_bundles),
                    prompt="Select an existing bundle",
                    allow_blank=True,
                    id="telemetry-select",
                )

        with Horizontal(id="actions"):
            yield Button("Generate", id="generate", variant="primary")
            yield Button("Inspect telemetry", id="inspect")
            yield Button("Run detection", id="detect")
            yield Button("Export Wazuh", id="export-wazuh")

        yield Static("", id="stage-status", markup=False)

        with TabbedContent(id="results"):
            with TabPane("Overview", id="overview-pane"):
                yield Static(
                    "Select an environment and route to begin.",
                    id="overview",
                    markup=False,
                )
            with TabPane("Events", id="events-pane"):
                with Horizontal(id="event-layout"):
                    yield DataTable(
                        id="event-table",
                        cursor_type="row",
                        zebra_stripes=True,
                    )
                    with VerticalScroll(id="event-detail-scroll"):
                        yield Static(
                            "Inspect a telemetry bundle to view events.",
                            id="event-detail",
                            markup=False,
                        )
            with TabPane("XML", id="xml-pane"):
                with VerticalScroll():
                    yield Static(
                        "Select an event to preview its verified XML artifact.",
                        id="xml-preview",
                        markup=False,
                    )
            with TabPane("Findings", id="findings-pane"):
                with VerticalScroll():
                    yield Static(
                        "Run detection after inspecting telemetry.",
                        id="findings",
                        markup=False,
                    )
            with TabPane("Wazuh", id="wazuh-pane"):
                with VerticalScroll():
                    yield Static(
                        "Export an inspected bundle to prepare Wazuh replay input.",
                        id="wazuh-result",
                        markup=False,
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
        self._update_controls()
        self._update_commands()

    @on(Select.Changed)
    def selection_changed(self, event: Select.Changed) -> None:
        if event.select.id == "telemetry-select":
            selection = event.select.selection
            selected_path = Path(str(selection)) if selection is not None else None
            inspected_path = (
                self.inspection.overview.path if self.inspection is not None else None
            )
            if selected_path != inspected_path:
                self._clear_inspection()
        self._update_controls()
        self._update_commands()

    @on(Button.Pressed, "#generate")
    def generate(self) -> None:
        environment_path = self._selected_path("#environment-select")
        route_path = self._selected_path("#route-select")
        if environment_path is None or route_path is None:
            self.notify(
                "Select an environment and authentication route.",
                severity="warning",
            )
            return

        try:
            bundle = run_generation_stage(
                environment_path,
                route_path,
                self.output_root,
            )
            self._refresh_catalog(selected_telemetry=bundle.path)
            self._load_inspection(bundle.path)
        except (OSError, ValueError) as error:
            self._show_error(error)
            return

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
        self.query_one("#findings", Static).update(
            Text(self._render_findings(analysis.path, analysis.created, findings))
        )
        self.query_one("#results", TabbedContent).active = "findings-pane"
        self._update_controls()
        action = "Created" if analysis.created else "Reused"
        self.notify(f"{action} analysis {analysis.manifest.analysis_id}")

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
        self.query_one("#results", TabbedContent).active = "wazuh-pane"
        self._update_controls()
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

    def _load_inspection(self, path: Path) -> None:
        inspection = inspect_telemetry_bundle(path)
        self.inspection = inspection
        self.analysis_complete = False
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
        self.query_one("#results", TabbedContent).active = "overview-pane"
        self._update_controls()
        self._update_commands()

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

    def _clear_inspection(self) -> None:
        self.inspection = None
        self.selected_event = None
        self.analysis_complete = False
        self.wazuh_export_complete = False
        if not self.is_mounted:
            return
        self.query_one("#event-table", DataTable).clear(columns=False)
        self.query_one("#overview", Static).update(
            "Select or generate an exact telemetry bundle."
        )
        self.query_one("#event-detail", Static).update(
            "Inspect a telemetry bundle to view events."
        )
        self.query_one("#xml-preview", Static).update(
            "Select an event to preview its verified XML artifact."
        )
        self.query_one("#findings", Static).update(
            "Run detection after inspecting telemetry."
        )
        self.query_one("#wazuh-result", Static).update(
            "Export an inspected bundle to prepare Wazuh replay input."
        )

    def _refresh_catalog(self, selected_telemetry: Path | None = None) -> None:
        self.catalog = discover_workflow_catalog(
            self.project_root,
            self.output_root,
        )
        selector = self.query_one("#telemetry-select", Select)
        selector.set_options(self._path_options(self.catalog.telemetry_bundles))
        if selected_telemetry is not None:
            selector.value = str(selected_telemetry.resolve())

    def _update_controls(self) -> None:
        environment_selected = self._selected_path("#environment-select") is not None
        route_selected = self._selected_path("#route-select") is not None
        telemetry_selected = self._selected_path("#telemetry-select") is not None
        profile_selected = self._selected_path("#profile-select") is not None
        inspected = self.inspection is not None

        self.query_one("#generate", Button).disabled = not (
            environment_selected and route_selected
        )
        self.query_one("#inspect", Button).disabled = not telemetry_selected
        self.query_one("#detect", Button).disabled = not (
            inspected and profile_selected
        )
        self.query_one("#export-wazuh", Button).disabled = not inspected

        stage_status = " | ".join(
            (
                "Generate: "
                + (
                    "ready"
                    if environment_selected and route_selected
                    else "needs input"
                ),
                f"Telemetry: {'inspected' if inspected else 'not inspected'}",
                "Detection: "
                + self._stage_state(
                    completed=self.analysis_complete,
                    available=inspected and profile_selected,
                ),
                "Wazuh export: "
                + self._stage_state(
                    completed=self.wazuh_export_complete,
                    available=inspected,
                ),
            )
        )
        self.query_one("#stage-status", Static).update(Text(stage_status))

    def _update_commands(self) -> None:
        commands = ["Equivalent CLI commands"]
        environment = self._selected_path("#environment-select")
        route = self._selected_path("#route-select")
        profile = self._selected_path("#profile-select")
        telemetry = self._inspected_path() or self._selected_path("#telemetry-select")

        if environment is not None and route is not None:
            commands.append(
                shell_join(
                    (
                        "uv",
                        "run",
                        "simlab",
                        "generate",
                        "authentication",
                        "--environment",
                        self._display_path(environment),
                        "--route",
                        self._display_path(route),
                        "--output-root",
                        self._display_path(self.output_root),
                    )
                )
            )
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

    def _selected_path(self, selector: str) -> Path | None:
        selection = self.query_one(selector, Select).selection
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
        return "\n".join(
            (
                f"Telemetry ID: {overview.telemetry_id}",
                f"Path: {overview.path}",
                f"Environment: {overview.environment_id}",
                f"Scenario: {overview.scenario_id}",
                f"Events: {overview.event_count} ({event_counts})",
                f"Hosts: {host_counts}",
                f"First event: {started_at}",
                f"Last event: {ended_at}",
                f"Event profiles: {', '.join(overview.event_profile_ids)}",
                f"Audit policies: {', '.join(overview.audit_policy_ids)}",
                "",
                "Select the Events tab to inspect focused evidence and provenance.",
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

    @staticmethod
    def _stage_state(*, completed: bool, available: bool) -> str:
        if completed:
            return "completed"
        if available:
            return "available"
        return "unavailable"

    def _show_error(self, error: Exception) -> None:
        self.notify(str(error), title="Workflow error", severity="error", timeout=8)


def run_tui(project_root: str | Path = ".") -> None:
    """Launch the guided SimLab terminal interface."""

    SimLabApp(project_root).run()

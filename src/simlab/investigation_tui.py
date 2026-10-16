"""A compact analyst workspace over saved case evidence and Wazuh results."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Checkbox,
    ContentSwitcher,
    DataTable,
    Footer,
    Header,
    Input,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from simlab.assessment import (
    DISPOSITION_LABELS,
    NOTE_LABELS,
    AssessmentNotes,
    SavedAssessment,
    load_assessment,
    load_latest_assessment,
    save_assessment,
)
from simlab.investigation import (
    InvestigationEvidence,
    evidence_account,
    evidence_source_ip,
    filter_investigation_evidence,
    parse_investigation_time,
)
from simlab.investigation_guidance import WINDOWS_EVENT_NOTES, investigation_context
from simlab.wazuh_evaluation import SavedInvestigation, load_saved_investigation


class AssessmentExitScreen(ModalScreen[bool]):
    """Prevent leaving an investigation from silently dropping an unsaved draft."""

    BINDINGS = [("escape", "stay", "Keep working")]

    def __init__(self, *, quitting: bool = False) -> None:
        super().__init__()
        self.quitting = quitting

    def compose(self) -> ComposeResult:
        with Vertical(id="assessment-exit-dialog", classes="panel") as dialog:
            dialog.border_title = "Unsaved assessment"
            yield Static(
                "Your notes or evidence selection have unsaved changes. "
                "Keep working to save them, or discard this draft. "
                "Existing saved reports will not be deleted.",
                markup=False,
            )
            with Horizontal(classes="case-actions"):
                yield Button("Keep working", id="assessment-stay", variant="primary")
                yield Button(
                    "Discard draft and quit"
                    if self.quitting
                    else "Discard draft and leave",
                    id="assessment-discard",
                    variant="warning",
                )

    @on(Button.Pressed, "#assessment-stay")
    def action_stay(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#assessment-discard")
    def discard(self) -> None:
        self.dismiss(True)


class InvestigationScreen(Screen):
    """Open an existing evaluation and investigate without running Docker."""

    CSS_PATH = "investigation.tcss"
    BINDINGS = [
        ("escape", "back", "Back"),
        ("g", "guide", "Guide"),
        ("ctrl+s", "save_assessment", "Save assessment"),
        Binding(
            "1",
            "section('alert')",
            "Alert",
            group=Binding.Group("Sections", compact=True),
        ),
        Binding(
            "2",
            "section('evidence')",
            "Evidence",
            group=Binding.Group("Sections", compact=True),
        ),
        Binding(
            "3",
            "section('context')",
            "Context",
            group=Binding.Group("Sections", compact=True),
        ),
        Binding(
            "4",
            "section('assessment')",
            "Assessment",
            group=Binding.Group("Sections", compact=True),
        ),
        Binding("slash", "focus_filters", "Filters"),
        Binding("space", "toggle_current_evidence", "Toggle evidence"),
        Binding(
            "left_square_bracket",
            "change_match(-1)",
            "Previous match",
            group=Binding.Group("Match", compact=True),
        ),
        Binding(
            "right_square_bracket",
            "change_match(1)",
            "Next match",
            group=Binding.Group("Match", compact=True),
        ),
    ]

    def __init__(
        self, output_root: Path, *, evaluation_path: Path | None = None
    ) -> None:
        super().__init__()
        self.output_root = output_root
        self.initial_evaluation_path = evaluation_path
        self.options: dict[str, tuple[Path, Path]] = {}
        self.investigation: SavedInvestigation | None = None
        self.alert_index = 0
        self.visible_evidence: tuple[InvestigationEvidence, ...] = ()
        self.selected_event: InvestigationEvidence | None = None
        self.selected_evidence: set[str] = set()
        self.saved_assessment: SavedAssessment | None = None
        self.saved_draft_state: dict[str, object] = {}

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action not in {
            "section",
            "focus_filters",
            "toggle_current_evidence",
            "change_match",
        }:
            return super().check_action(action, parameters)
        if self.investigation is None or self.app.screen is not self:
            return False
        # Printable shortcuts must not steal text or dropdown-search keystrokes.
        focused = self.focused
        if focused is not None and any(
            isinstance(widget, (Input, TextArea, Select))
            for widget in focused.ancestors_with_self
        ):
            return False
        if action == "toggle_current_evidence":
            if not self.query_one("#case-event-table", DataTable).has_focus:
                return False
            return True if self.visible_evidence else None
        if action == "change_match":
            index = self.alert_index + int(parameters[0])
            return True if 0 <= index < len(self.investigation.alerts) else None
        return True

    def action_section(self, section: str) -> None:
        tabs = self.query_one("#case-tabs", TabbedContent)
        pane_id = f"case-{section}-pane"
        tabs.active = pane_id
        target = (
            self.query_one("#case-event-table", DataTable)
            if section == "evidence"
            else tabs.get_tab(pane_id)
        )
        self.call_after_refresh(target.focus)

    def action_focus_filters(self) -> None:
        self.query_one("#case-tabs", TabbedContent).active = "case-evidence-pane"
        self.call_after_refresh(self.query_one("#case-account", Input).focus)

    def action_toggle_current_evidence(self) -> None:
        table = self.query_one("#case-event-table", DataTable)
        if 0 <= table.cursor_row < len(self.visible_evidence):
            # Use the cursor itself, even if its highlight message is still queued.
            self.show_event(self.visible_evidence[table.cursor_row])
            self.toggle_evidence()

    def action_change_match(self, direction: int) -> None:
        # Reuse the dropdown handler so filter and alert behavior stay identical.
        self.query_one("#case-alert-select", Select).value = str(
            self.alert_index + direction
        )

    @on(TabbedContent.TabActivated, "#case-tabs")
    def refresh_section_bindings(self) -> None:
        self.refresh_bindings()

    def compose(self) -> ComposeResult:
        yield Header()
        with ContentSwitcher(id="investigation-content", initial="case-picker"):
            with (
                VerticalScroll(id="case-picker"),
                Vertical(id="case-picker-card", classes="panel") as card,
            ):
                card.border_title = "Open prepared investigation"
                yield Static(
                    "Open saved evidence and Wazuh rule-test results. "
                    "Docker does not need to be running.",
                    markup=False,
                )
                yield Select([], prompt="Choose a prepared case", id="case-select")
                yield Static("", id="case-picker-status", markup=False)
                with Horizontal(classes="case-actions"):
                    yield Button(
                        "Open case",
                        id="case-open",
                        variant="primary",
                        disabled=True,
                    )
                    yield Button("Refresh", id="case-refresh")
                    yield Button("Main menu", id="case-menu")

            with Vertical(id="case-workspace"):
                with Horizontal(id="case-toolbar"):
                    yield Button("Back to cases", id="case-back")
                    yield Select(
                        [], prompt="Choose a Wazuh match", id="case-alert-select"
                    )
                    yield Button("Guide", id="case-guide")
                yield Static("", id="case-context", markup=False)
                with TabbedContent(id="case-tabs"):
                    with TabPane("Alert", id="case-alert-pane"):
                        with VerticalScroll(id="case-alert-scroll", classes="panel"):
                            yield Static("", id="case-alert-details", markup=False)
                        yield Button(
                            "View supporting events",
                            id="case-supporting",
                            variant="primary",
                        )
                    with TabPane("Evidence", id="case-evidence-pane"):
                        with Vertical(id="case-filters", classes="panel"):
                            with Horizontal(classes="case-filter-row"):
                                yield Input(placeholder="Account", id="case-account")
                                yield Input(placeholder="Event host", id="case-host")
                                yield Input(placeholder="Source IP", id="case-ip")
                            with Horizontal(classes="case-filter-row"):
                                yield Input(
                                    placeholder="From UTC: HH:MM[:SS] / ISO",
                                    id="case-from",
                                )
                                yield Input(
                                    placeholder="To UTC: HH:MM[:SS] / ISO",
                                    id="case-to",
                                )
                                yield Select(
                                    [("All event IDs", "all")],
                                    value="all",
                                    allow_blank=False,
                                    id="case-event-id",
                                )
                            with Horizontal(classes="case-actions"):
                                yield Button(
                                    "Apply", id="case-apply", variant="primary"
                                )
                                yield Button("Clear filters", id="case-clear")
                                yield Checkbox(
                                    "Alert evidence only", id="case-alert-only"
                                )
                                yield Checkbox("Selected only", id="case-selected-only")
                            yield Static("", id="case-filter-status", markup=False)
                        with Horizontal(id="case-evidence-body"):
                            yield DataTable(
                                id="case-event-table",
                                classes="panel",
                                cursor_type="row",
                                zebra_stripes=False,
                            )
                            with Vertical(id="case-detail-panel", classes="panel"):
                                with VerticalScroll(id="case-event-scroll"):
                                    yield Static(
                                        "", id="case-event-details", markup=False
                                    )
                                yield Button(
                                    "Select evidence", id="case-pin", disabled=True
                                )
                    with TabPane("Context", id="case-context-pane"):
                        with VerticalScroll(id="case-brief-scroll", classes="panel"):
                            yield Static("", id="case-brief", markup=False)
                        with Horizontal(classes="case-actions"):
                            yield Button("Source timeline", id="case-pivot-source")
                            yield Button("Earlier activity", id="case-pivot-earlier")
                            yield Button("Successful logons", id="case-pivot-success")
                            yield Button("Windows event IDs", id="case-event-notes")
                    with TabPane("Assessment", id="case-assessment-pane"):
                        yield Static("", id="assessment-draft-status", markup=False)
                        with VerticalScroll(id="assessment-form", classes="panel"):
                            yield Static(
                                "Assess the whole case, including both independent "
                                "matches. Record your reasoning, not the "
                                "scenario-author answer. All fields and at least "
                                "one selected evidence event are required.",
                                classes="assessment-guidance",
                                markup=False,
                            )
                            yield Static("Analyst decision", classes="assessment-label")
                            yield Select(
                                [
                                    (label, value)
                                    for value, label in DISPOSITION_LABELS.items()
                                ],
                                prompt="Choose your decision",
                                id="assessment-decision",
                            )
                            for field, label in NOTE_LABELS.items():
                                yield Static(label, classes="assessment-label")
                                yield TextArea(
                                    id=self.note_id(field),
                                    soft_wrap=True,
                                    tab_behavior="focus",
                                    classes="assessment-note",
                                )
                        yield Static("", id="assessment-status", markup=False)
                        with Horizontal(classes="case-actions"):
                            yield Button(
                                "Save assessment",
                                id="assessment-save",
                                variant="primary",
                                disabled=True,
                            )
                            yield Button(
                                "View saved report",
                                id="assessment-view",
                                disabled=True,
                            )
                yield Static("", id="case-selection-status", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        for identifier, title in {
            "case-filters": "Filters",
            "case-event-table": "Evidence",
            "case-detail-panel": "Current event",
            "case-alert-scroll": "Wazuh rule-test match",
            "case-brief-scroll": "Investigation context",
            "assessment-form": "Assessment",
        }.items():
            self.query_one(f"#{identifier}").border_title = title
        self.query_one("#case-event-table", DataTable).add_columns(
            "Pick",
            "Event time (UTC)",
            "Host",
            "Event",
            "Account",
            "Source IP",
            "Status",
        )
        self.refresh_cases()
        if self.initial_evaluation_path is not None:
            key = str(self.initial_evaluation_path)
            if key in self.options:
                self.query_one("#case-select", Select).value = key
                self.call_after_refresh(self.open_case)
            else:
                self.query_one("#case-picker-status", Static).update(
                    Text(
                        "The prepared evaluation could not be listed. "
                        "It may have been moved or damaged; choose a saved case "
                        "or return to retry preparation."
                    )
                )

    def refresh_cases(self) -> None:
        options = []
        self.options.clear()
        skipped = 0
        for manifest_path in self.output_root.glob(
            "evaluations/case-*/evaluation-*/manifest.json"
        ):
            try:
                manifest = json.loads(manifest_path.read_text())
                evaluation = manifest_path.parent
                case = (
                    self.output_root / "cases" / "password-spray" / manifest["case_id"]
                )
                if not (case / "manifest.json").is_file():
                    continue
                alerts = json.loads((evaluation / "alerts.json").read_text())
                detected = max(
                    datetime.fromisoformat(alert["detected_at"]) for alert in alerts
                )
                label = (
                    f"Password spray · {detected.astimezone(UTC):%Y-%m-%d %H:%M:%S} "
                    "UTC "
                    f"· {evaluation.name.removeprefix('evaluation-')[:8]}"
                )
                key = str(evaluation)
                self.options[key] = (case, evaluation)
                options.append((detected, label, key))
            except (OSError, ValueError, KeyError, TypeError):
                skipped += 1
        options.sort(reverse=True)
        selector = self.query_one("#case-select", Select)
        selector.set_options([(label, key) for _, label, key in options])
        if len(options) == 1:
            selector.value = options[0][2]
        self.query_one("#case-open", Button).disabled = selector.selection is None
        self.query_one(
            "#case-picker-card"
        ).border_subtitle = f"{len(options)} saved evaluation(s)"
        message = (
            f"{len(options)} saved evaluation(s). Integrity is checked when opened."
            if options
            else "No prepared investigations found. "
            "Run: uv run simlab prepare password-spray"
        )
        if skipped:
            message += f" {skipped} unreadable evaluation(s) skipped."
        self.query_one("#case-picker-status", Static).update(Text(message))

    @on(Select.Changed)
    def selection_changed(self, event: Select.Changed) -> None:
        event.stop()
        if event.select.id == "case-select":
            self.query_one("#case-open", Button).disabled = (
                event.select.selection is None
            )
        elif (
            event.select.id == "case-alert-select"
            and event.select.selection is not None
        ):
            self.alert_index = int(event.select.selection)
            self.render_alert()
            self.apply_filters()
        elif event.select.id == "case-event-id":
            self.apply_filters()
        elif event.select.id == "assessment-decision":
            self.update_selection_status()

    @on(Button.Pressed, "#case-open")
    def open_case(self) -> None:
        choice = self.query_one("#case-select", Select).selection
        if choice is None:
            return
        try:
            loaded = load_saved_investigation(*self.options[str(choice)])
            if not loaded.alerts:
                raise ValueError(
                    "This evaluation has no alert-producing matches to open."
                )
        except (OSError, ValueError, KeyError, TypeError) as error:
            self.query_one("#case-picker-status", Static).update(
                Text(f"Cannot open case: {error}")
            )
            return
        self.investigation = loaded
        self.selected_evidence.clear()
        self.selected_event = None
        self.alert_index = 0
        selector = self.query_one("#case-alert-select", Select)
        ids = sorted({item.event.event_id for item in loaded.case.evidence})
        with self.prevent(Select.Changed):
            selector.set_options(
                [
                    (f"Wazuh rule {alert.rule_id} · level {alert.level}", str(index))
                    for index, alert in enumerate(loaded.alerts)
                ]
            )
            selector.value = "0"
            self.query_one("#case-event-id", Select).set_options(
                [
                    ("All event IDs", "all"),
                    *((str(event_id), str(event_id)) for event_id in ids),
                ]
            )
        self.query_one(
            "#investigation-content", ContentSwitcher
        ).current = "case-workspace"
        self.query_one("#case-context", Static).update(
            Text(
                f"{loaded.case.manifest.title} · "
                f"{loaded.case.manifest.environment_id}\n"
                "Supplied event range: "
                f"{loaded.case.manifest.evidence_started_at.isoformat()} "
                f"to {loaded.case.manifest.evidence_ended_at.isoformat()}. "
                "Selected modeled activity; complete host logs and later evidence "
                "are unavailable."
            )
        )
        self.query_one("#case-tabs", TabbedContent).active = "case-alert-pane"
        self.restore_assessment()
        self.clear_filters()
        self.query_one("#case-brief", Static).update(
            self.titled_text(investigation_context(loaded))
        )
        self.render_alert()

    def titled_text(self, content: str) -> Text:
        """Highlight a panel's first line without changing its underlying text."""

        text = Text(content)
        title_color = self.app.get_css_variables()["title-color"]
        text.stylize(f"bold {title_color}", 0, len(content.split("\n", 1)[0]))
        return text

    def render_alert(self) -> None:
        if self.investigation is None:
            return
        loaded = self.investigation
        alert = loaded.alerts[self.alert_index]
        self.query_one(
            "#case-alert-scroll"
        ).border_subtitle = f"Match {self.alert_index + 1} of {len(loaded.alerts)}"
        by_id = {item.event_instance_id: item for item in loaded.case.evidence}
        records = [by_id[reference] for reference in alert.supporting_event_ids]
        hosts = sorted({item.event.computer for item in records})
        accounts = sorted({evidence_account(item) for item in records})
        sources = sorted({evidence_source_ip(loaded.case, item)[0] for item in records})
        self.query_one("#case-pivot-source", Button).disabled = (
            len(sources) != 1 or not sources[0]
        )
        window_start = self.active_window_start(loaded)
        self.query_one("#case-pivot-earlier", Button).disabled = not any(
            item.event.occurred_at < window_start for item in loaded.case.evidence
        )
        self.query_one("#case-pivot-success", Button).disabled = not any(
            item.event.event_id == 4624 for item in loaded.case.evidence
        )
        self.query_one("#case-alert-details", Static).update(
            self.titled_text(
                "\n".join(
                    (
                        f"Wazuh {loaded.manager_version} · rule-test result · "
                        f"{len(loaded.alerts)} independent matches",
                        f"Rule: {alert.rule_id} | Wazuh level: {alert.level}",
                        alert.description,
                        "",
                        "Detected (actual processing time): "
                        f"{alert.detected_at.isoformat()}",
                        "Supporting event times: "
                        f"{alert.evidence_started_at.isoformat()} "
                        f"to {alert.evidence_ended_at.isoformat()}",
                        f"Event hosts: {', '.join(hosts)}",
                        f"Target accounts: {', '.join(accounts)}",
                        f"Source IP context: {', '.join(sources)} "
                        "(inventory resolution where needed)",
                        f"Supporting records: {len(records)} | MITRE ATT&CK: "
                        f"{', '.join(alert.mitre_attack_ids)}",
                        "",
                        "The match supports investigation; password reuse, "
                        "operator identity, "
                        "and account compromise are not established by these events.",
                        "This is saved output from Wazuh rule testing, "
                        "not a persisted SIEM alert. "
                        "Correlation used processing time; investigate "
                        "the original event timeline separately.",
                    )
                )
            )
        )

    @on(Button.Pressed, "#case-supporting")
    def supporting_events(self) -> None:
        with self.prevent(Checkbox.Changed):
            self._reset_filters()
            self.query_one("#case-alert-only", Checkbox).value = True
        self.query_one("#case-tabs", TabbedContent).active = "case-evidence-pane"
        self.apply_filters()
        self.query_one("#case-event-table", DataTable).focus()

    def active_window_start(self, loaded: SavedInvestigation) -> datetime:
        trigger = loaded.alerts[self.alert_index].triggering_event_id
        return next(
            window.evidence_started_at
            for window in loaded.windows
            if any(result.event_instance_id == trigger for result in window.results)
        )

    @on(Button.Pressed, "#case-pivot-source")
    @on(Button.Pressed, "#case-pivot-earlier")
    @on(Button.Pressed, "#case-pivot-success")
    def context_pivot(self, event: Button.Pressed) -> None:
        event.stop()
        if self.investigation is None:
            return
        loaded = self.investigation
        alert = loaded.alerts[self.alert_index]
        source = None
        if event.button.id == "case-pivot-source":
            references = set(alert.supporting_event_ids)
            sources = {
                evidence_source_ip(loaded.case, item)[0]
                for item in loaded.case.evidence
                if item.event_instance_id in references
            }
            if len(sources) != 1 or not next(iter(sources)):
                self.app.notify("No unambiguous source IP for this match.")
                return
            source = next(iter(sources))
        with self.prevent(Select.Changed):
            self._reset_filters()
            if source is not None:
                self.query_one("#case-ip", Input).value = source
            elif event.button.id == "case-pivot-earlier":
                before = self.active_window_start(loaded) - timedelta(microseconds=1)
                self.query_one("#case-to", Input).value = before.isoformat()
            else:
                self.query_one("#case-event-id", Select).value = "4624"
        self.query_one("#case-tabs", TabbedContent).active = "case-evidence-pane"
        self.apply_filters()
        self.query_one("#case-event-table", DataTable).focus()

    @on(Button.Pressed, "#case-event-notes")
    def event_notes(self) -> None:
        from simlab.tui import GuideScreen

        self.app.push_screen(
            GuideScreen("Windows event-ID reference", WINDOWS_EVENT_NOTES)
        )

    @on(Button.Pressed, "#case-apply")
    @on(Input.Submitted)
    @on(Checkbox.Changed)
    def apply_filters(self, event=None) -> None:
        if event is not None:
            event.stop()
        if self.investigation is None:
            return
        case = self.investigation.case
        try:
            started = parse_investigation_time(
                self.query_one("#case-from", Input).value, case
            )
            ended = parse_investigation_time(
                self.query_one("#case-to", Input).value, case
            )
            event_id = self.query_one("#case-event-id", Select).selection
            references = None
            if self.query_one("#case-alert-only", Checkbox).value:
                references = set(
                    self.investigation.alerts[self.alert_index].supporting_event_ids
                )
            if self.query_one("#case-selected-only", Checkbox).value:
                references = (
                    references & self.selected_evidence
                    if references is not None
                    else self.selected_evidence.copy()
                )
            evidence = filter_investigation_evidence(
                case,
                account=self.query_one("#case-account", Input).value,
                host=self.query_one("#case-host", Input).value,
                source_ip=self.query_one("#case-ip", Input).value,
                event_id=int(event_id) if event_id not in {None, "all"} else None,
                started_at=started,
                ended_at=ended,
                references=references,
            )
        except ValueError as error:
            self.query_one("#case-filter-status", Static).update(
                Text(f"Invalid filter: {error}")
            )
            return
        previous_reference = (
            self.selected_event.event_instance_id
            if self.selected_event is not None
            else None
        )
        current_row = next(
            (
                index
                for index, item in enumerate(evidence)
                if item.event_instance_id == previous_reference
            ),
            0,
        )
        self.visible_evidence = evidence
        table = self.query_one("#case-event-table", DataTable)
        with self.prevent(DataTable.RowHighlighted):
            table.clear()
            for item in evidence:
                payload = item.event.data
                source, derived = evidence_source_ip(case, item)
                table.add_row(
                    "●" if item.event_instance_id in self.selected_evidence else "",
                    item.event.occurred_at.astimezone(UTC).isoformat(
                        timespec="milliseconds"
                    ),
                    item.host_id,
                    str(item.event.event_id),
                    evidence_account(item),
                    source + ("*" if derived else ""),
                    getattr(payload, "status", "0x0"),
                    key=item.event_instance_id,
                )
            if evidence:
                table.move_cursor(row=current_row)
        status = (
            f"{len(evidence)} / {len(case.evidence)} events. "
            "* = source IP resolved from inventory."
        )
        if (
            (started and started < case.manifest.evidence_started_at)
            or (ended and ended > case.manifest.evidence_ended_at)
            or (started and started > case.manifest.evidence_ended_at)
            or (ended and ended < case.manifest.evidence_started_at)
        ):
            status += " Outside the supplied range, evidence is unavailable."
        self.query_one("#case-filter-status", Static).update(Text(status))
        self.show_event(evidence[current_row] if evidence else None)
        self.update_selection_status()

    @on(Button.Pressed, "#case-clear")
    def clear_filters(self) -> None:
        self._reset_filters()
        self.apply_filters()

    def _reset_filters(self) -> None:
        """Reset controls without queuing intermediate filter refreshes."""

        with self.prevent(Checkbox.Changed, Select.Changed):
            for name in ("account", "host", "ip", "from", "to"):
                self.query_one(f"#case-{name}", Input).value = ""
            self.query_one("#case-event-id", Select).value = "all"
            self.query_one("#case-alert-only", Checkbox).value = False
            self.query_one("#case-selected-only", Checkbox).value = False

    @on(DataTable.RowHighlighted, "#case-event-table")
    def event_highlighted(self, event: DataTable.RowHighlighted) -> None:
        event.stop()
        if not self.visible_evidence:
            return
        table = self.query_one("#case-event-table", DataTable)
        current_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        if event.row_key != current_key:
            return
        self.show_event(
            next(
                (
                    item
                    for item in self.visible_evidence
                    if item.event_instance_id == event.row_key.value
                ),
                None,
            )
        )

    def show_event(self, item: InvestigationEvidence | None) -> None:
        self.selected_event = item
        self.query_one("#case-pin", Button).disabled = item is None
        panel = self.query_one("#case-detail-panel")
        if item is None:
            panel.border_subtitle = "No matching event"
            self.query_one("#case-pin", Button).label = "Select evidence"
            self.query_one("#case-event-details", Static).update(
                "No events match these filters."
            )
            return
        selection = (
            "Selected"
            if item.event_instance_id in self.selected_evidence
            else "Not selected"
        )
        panel.border_subtitle = f"Event {item.event.event_id} | {selection}"
        payload = item.event.data.model_dump(mode="json", by_alias=True)
        lines = [
            f"Windows event {item.event.event_id} · {item.event.computer}",
            f"Event time: {item.event.occurred_at.isoformat()}",
            f"Record ID: {item.event.record_id}",
            "",
        ]
        if self.investigation is not None:
            result = next(
                (
                    result
                    for window in self.investigation.windows
                    for result in window.results
                    if result.event_instance_id == item.event_instance_id
                ),
                None,
            )
            if result is None:
                lines.append("Wazuh: context only; this event was not evaluated.")
            else:
                rule = result.output.get("rule", {})
                lines.append(
                    f"Wazuh rule-test match: {rule.get('id', '-')} "
                    f"| level {rule.get('level', '-')}"
                )
        lines.extend(("", "Windows fields and simulation value origins"))
        for name, value in payload.items():
            origin = next(
                (
                    origin
                    for origin in ("documented", "derived", "synthetic", "unavailable")
                    if f"event_data.{name}" in getattr(item.field_provenance, origin)
                ),
                "unknown",
            )
            lines.append(f"{name}: {value} [{origin}]")
        self.query_one("#case-event-details", Static).update(
            self.titled_text("\n".join(lines))
        )
        self.query_one("#case-pin", Button).label = (
            "Remove selection"
            if item.event_instance_id in self.selected_evidence
            else "Select evidence"
        )

    @on(Button.Pressed, "#case-pin")
    def toggle_evidence(self) -> None:
        if self.selected_event is None:
            return
        reference = self.selected_event.event_instance_id
        if reference in self.selected_evidence:
            self.selected_evidence.remove(reference)
        else:
            self.selected_evidence.add(reference)
        self.apply_filters()

    def update_selection_status(self) -> None:
        self.refresh_bindings()
        self.query_one("#case-selection-status", Static).update(
            Text(
                f"Selected evidence: {len(self.selected_evidence)}. "
                "Save notes and evidence references in Assessment. "
                "Case evidence and Wazuh results remain read-only."
            )
        )
        if self.investigation is None:
            return
        self.query_one("#case-event-table").border_subtitle = (
            f"{len(self.visible_evidence)}/{len(self.investigation.case.evidence)}"
            " shown"
            f" | {len(self.selected_evidence)} selected"
        )
        dirty = self.draft_state() != self.saved_draft_state
        self.query_one("#assessment-save", Button).disabled = not dirty
        self.query_one("#assessment-view", Button).disabled = (
            self.saved_assessment is None
        )
        self.query_one("#assessment-draft-status", Static).update(
            Text(
                "Unsaved changes — save to retain notes and selected evidence."
                if dirty
                else "Saved assessment loaded. Editing creates a new snapshot."
                if self.saved_assessment is not None
                else "No saved assessment. Your notes and decision start blank."
            )
        )

    @staticmethod
    def note_id(field: str) -> str:
        return "assessment-" + field.replace("_", "-")

    def draft_state(self) -> dict[str, object]:
        return {
            **{
                field: self.query_one(f"#{self.note_id(field)}", TextArea).text.strip()
                for field in NOTE_LABELS
            },
            "disposition": self.query_one("#assessment-decision", Select).selection,
            "selected_event_ids": tuple(sorted(self.selected_evidence)),
        }

    @on(TextArea.Changed)
    def notes_changed(self, event: TextArea.Changed) -> None:
        event.stop()
        self.update_selection_status()

    def restore_assessment(self) -> None:
        self.saved_assessment = None
        status = ""
        if self.investigation is not None:
            try:
                self.saved_assessment = load_latest_assessment(
                    self.investigation, self.output_root
                )
            except (OSError, ValueError) as error:
                status = (
                    f"Saved assessment could not be restored: {error}. "
                    "Existing reports are untouched; this draft starts blank."
                )
                self.app.notify(
                    "Saved assessment could not be restored. "
                    "See Assessment for details; existing reports are untouched.",
                    severity="warning",
                )
        saved = self.saved_assessment
        self.selected_evidence = (
            set(saved.assessment.selected_event_ids) if saved else set()
        )
        for field in NOTE_LABELS:
            self.query_one(f"#{self.note_id(field)}", TextArea).load_text(
                getattr(saved.assessment, field) if saved else ""
            )
        self.query_one("#assessment-decision", Select).value = (
            saved.assessment.disposition if saved else Select.NULL
        )
        self.saved_draft_state = self.draft_state()
        if saved is not None:
            status = self.saved_report_status(saved)
        self.query_one("#assessment-status", Static).update(Text(status))
        self.update_selection_status()

    @on(Button.Pressed, "#assessment-save")
    def action_save_assessment(self) -> None:
        if self.investigation is None:
            return
        self.query_one("#case-tabs", TabbedContent).active = "case-assessment-pane"
        self.query_one("#assessment-save", Button).focus()
        state = self.draft_state()
        if state == self.saved_draft_state:
            return
        try:
            notes = AssessmentNotes.model_validate(
                {name: state[name] for name in (*NOTE_LABELS, "disposition")}
            )
        except ValidationError as error:
            fields = ", ".join(
                NOTE_LABELS.get(str(item["loc"][0]), "Analyst decision")
                for item in error.errors()
            )
            self.query_one("#assessment-status", Static).update(
                Text(
                    f"Cannot save: check {fields}. Choose a decision; "
                    "each note must contain 1–12000 characters."
                )
            )
            return
        try:
            saved = save_assessment(
                self.investigation, self.output_root, notes, self.selected_evidence
            )
        except (OSError, ValueError) as error:
            self.query_one("#assessment-status", Static).update(
                Text(f"Cannot save assessment: {error}. Your draft is still open.")
            )
            return
        self.saved_assessment = saved
        self.saved_draft_state = state
        self.query_one("#assessment-status", Static).update(
            Text(self.saved_report_status(saved))
        )
        self.update_selection_status()

    def saved_report_status(self, saved: SavedAssessment) -> str:
        report = saved.path / "report.md"
        try:
            display = str(report.relative_to(self.output_root.parent))
        except ValueError:
            display = str(report)
        return f"Saved {saved.assessment.created_at.isoformat()} · {display}"

    @on(Button.Pressed, "#assessment-view")
    def view_saved_report(self) -> None:
        if self.saved_assessment is None or self.investigation is None:
            return
        try:
            saved = load_assessment(self.saved_assessment.path, self.investigation)
            report = (saved.path / "report.md").read_text(encoding="utf-8")
        except (OSError, ValueError) as error:
            self.query_one("#assessment-status", Static).update(
                Text(f"Cannot view saved report: {error}")
            )
            return
        from simlab.tui import GuideScreen

        self.app.push_screen(
            GuideScreen("Saved report · excludes unsaved edits", report)
        )

    @on(Button.Pressed, "#case-refresh")
    def refresh_button(self) -> None:
        self.refresh_cases()

    @property
    def has_unsaved_assessment(self) -> bool:
        """Share the same draft guard for leaving a case and quitting the app."""

        return (
            self.investigation is not None
            and self.draft_state() != self.saved_draft_state
        )

    @on(Button.Pressed, "#case-back")
    def action_back(self) -> None:
        if (
            self.query_one("#investigation-content", ContentSwitcher).current
            == "case-workspace"
        ):
            if self.has_unsaved_assessment:
                self.app.push_screen(AssessmentExitScreen(), self.confirm_leave)
            else:
                self.leave_case()
        else:
            self.app.pop_screen()

    def confirm_leave(self, discard: bool | None) -> None:
        if discard:
            self.leave_case()

    def leave_case(self) -> None:
        self.query_one(
            "#investigation-content", ContentSwitcher
        ).current = "case-picker"
        self.query_one("#case-open", Button).focus()
        self.investigation = None
        self.selected_evidence.clear()
        self.saved_assessment = None
        self.selected_event = None
        self.visible_evidence = ()
        self.refresh_cases()
        self.refresh_bindings()

    @on(Button.Pressed, "#case-menu")
    def main_menu(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#case-guide")
    def action_guide(self) -> None:
        from simlab.tui import GuideScreen

        self.app.push_screen(
            GuideScreen(
                "Investigation guide",
                (
                    "Keyboard\n1 Alert, 2 Evidence, 3 Context, 4 Assessment. "
                    "Evidence opens with the table focused: arrows inspect rows, "
                    "Space selects or removes the current evidence reference. "
                    "/ opens Evidence and focuses the account filter without "
                    "applying it. [ and ] move to the previous/next Wazuh match "
                    "without wrapping. These shortcuts are inactive while typing "
                    "or using dropdowns; TAB and the visible controls still work. "
                    "The footer shows shortcuts available at the current focus.\n\n"
                    "Alert\nEach entry is an independent Wazuh rule-test match. "
                    "Detection time is the actual processing clock; supporting "
                    "event times belong to the scenario.\n\n"
                    "Evidence\nView supporting events narrows to records returned "
                    "in Wazuh's correlation output. Clear filters widens back to "
                    "the full case. Filters combine with AND. "
                    "Text fields apply with Apply or Enter; Event ID and "
                    "checkboxes apply the current form immediately. Clock-only time "
                    "inputs use the case date in UTC; ISO datetimes can include "
                    "an explicit offset. Event host means the system that recorded "
                    "the event. IP filtering includes inventory lookups from logged "
                    "workstation names; an asterisk marks those derived addresses.\n\n"
                    "Evidence limits\nNo results outside the supplied range means "
                    "unavailable evidence, not proof that nothing happened. "
                    "Kerberos context has not been evaluated by the Wazuh adapter. "
                    "Scenario-author answers are not shown.\n\n"
                    "Selection\nSelect records to support your assessment. "
                    "Filters and the active match do not change that set. "
                    "The reverse-highlighted row is the event being inspected; "
                    "it remains highlighted when focus moves away. The Pick marker "
                    "shows evidence included in your assessment, not keyboard focus. "
                    "A left | marker shows keyboard focus; underline indicates "
                    "mouse hover. Panel captions show visible and selected counts.\n\n"
                    "Context\nRead the saved inventory brief and the questions "
                    "between Evidence and Assessment. Pivot buttons reuse existing "
                    "records without changing notes or selected evidence. Missing "
                    "business/endpoint context is a proposed request, not a "
                    "hidden answer. Windows event IDs opens the short reference.\n\n"
                    "Assessment\nThe notes cover the whole case and evaluation. "
                    "Separate logged facts from your hypothesis and state what "
                    "additional evidence is needed. Benign activity means the "
                    "pattern happened but has an authorized explanation; a false "
                    "positive means the detection is not evidence of the suspected "
                    "behavior. Neither is an automatic conclusion.\n\n"
                    "Save assessment writes a separate JSON record and Markdown "
                    "report with your selected event references. All five notes, "
                    "a decision, and at least one selected event are required. "
                    "Editing and saving creates a new snapshot; reopening this "
                    "evaluation restores the latest verified snapshot. Back/Escape "
                    "prompts before discarding unsaved changes. Quit also asks "
                    "before discarding; keep working to save first. There is no "
                    "autosave, and forced terminal closure bypasses these guards. "
                    "TAB moves between fields; "
                    "Enter inserts a new line. Ctrl+S saves.\n\n"
                    "Recommended next steps are practice escalation/collection "
                    "notes, not actions performed on a SIEM or endpoint. View saved "
                    "report shows the last saved snapshot, not the current draft.\n\n"
                    + WINDOWS_EVENT_NOTES
                ),
            )
        )

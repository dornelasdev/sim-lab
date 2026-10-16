import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.text import Text
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    Select,
    Static,
    TabbedContent,
    TextArea,
)

from simlab.assessment import (
    NOTE_LABELS,
    AssessmentNotes,
    load_latest_assessment,
    save_assessment,
)
from simlab.investigation import (
    filter_investigation_evidence,
    load_investigation_case,
    parse_investigation_time,
)
from simlab.investigation_guidance import WINDOWS_EVENT_NOTES, investigation_context
from simlab.investigation_tui import AssessmentExitScreen, InvestigationScreen
from simlab.tui import GuideScreen, SimLabApp
from simlab.wazuh_evaluation import (
    load_saved_investigation,
    prepare_password_spray_investigation,
)
from tests.test_investigation import _engine_response

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "simlab.wazuh_evaluation.subprocess.run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=json.dumps(_engine_response(json.loads(kwargs["input"]))),
        ),
    )
    investigation = prepare_password_spray_investigation(PROJECT_ROOT, tmp_path)

    def no_runtime(*args, **kwargs):
        raise AssertionError("Opening/filtering a saved case must not invoke Docker")

    monkeypatch.setattr("simlab.wazuh_evaluation.subprocess.run", no_runtime)
    return investigation


def test_saved_case_roundtrip_verifies_results_without_runtime(prepared):
    loaded = load_saved_investigation(prepared.case.path, prepared.evaluation_path)
    assert loaded.case == prepared.case
    assert loaded.alerts == prepared.alerts
    assert len(loaded.windows) == 2


@pytest.mark.parametrize("artifact", ["events.jsonl", "alerts.json", "SHA256SUMS"])
def test_saved_case_rejects_modified_artifacts(prepared, artifact):
    root = prepared.evaluation_path if artifact == "alerts.json" else prepared.case.path
    (root / artifact).write_text("[]\n")
    with pytest.raises((ValueError, OSError)):
        load_saved_investigation(prepared.case.path, prepared.evaluation_path)


def test_case_filters_use_event_time_and_explicit_inventory_context(prepared):
    case = load_investigation_case(prepared.case.path)
    assert len(filter_investigation_evidence(case, account="BOB")) == 5
    assert len(filter_investigation_evidence(case, host="DC01")) == 8
    assert len(filter_investigation_evidence(case, source_ip="10.10.0.101")) == 15
    assert len(filter_investigation_evidence(case, event_id=4769)) == 1
    assert (
        len(
            filter_investigation_evidence(
                case,
                started_at=parse_investigation_time("09:15", case),
                ended_at=parse_investigation_time("09:16", case),
            )
        )
        == 6
    )
    assert parse_investigation_time(
        "2026-09-14T10:15:00+01:00", case
    ) == parse_investigation_time("09:15", case)
    with pytest.raises(ValueError):
        filter_investigation_evidence(case, source_ip="invalid")
    with pytest.raises(ValueError, match="From"):
        filter_investigation_evidence(
            case,
            started_at=parse_investigation_time("09:16", case),
            ended_at=parse_investigation_time("09:15", case),
        )


def test_context_brief_uses_saved_inventory_without_author_answers(prepared):
    loaded = load_saved_investigation(prepared.case.path, prepared.evaluation_path)
    brief = investigation_context(loaded)
    for host in loaded.case.environment.hosts:
        assert host.hostname in brief and str(host.ipv4_address) in brief
    assert "SMB on port 445" in brief
    assert "alice, bob, carol" in brief
    assert "not event evidence" in brief
    assert "Context you would request — unavailable" in brief
    assert "No ticket search, endpoint query, or collection is performed" in brief
    assert "not a normal-activity baseline or a scenario answer" in brief
    assert "source_attempt_id" not in brief and "case-spray-window" not in brief
    for event_id in (4624, 4625, 4648, 4672, 4688, 4740, 4768, 4769, 4771, 4776):
        assert str(event_id) in WINDOWS_EVENT_NOTES
    assert "Status 0xC000006A" in WINDOWS_EVENT_NOTES
    assert "SubStatus" in WINDOWS_EVENT_NOTES
    assert "Kerberos codes" in WINDOWS_EVENT_NOTES
    assert "not added to this case" in WINDOWS_EVENT_NOTES


def test_context_pivots_and_event_notes_preserve_evidence_and_draft(prepared, tmp_path):
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            for button in screen.query(Button):
                button.active_effect_duration = 0
            await pilot.click("#case-open")
            await pilot.pause()
            assert screen.investigation is not None
            tabs = screen.query_one("#case-tabs", TabbedContent)
            assert [pane.id for pane in tabs.query("TabPane")] == [
                "case-alert-pane",
                "case-evidence-pane",
                "case-context-pane",
                "case-assessment-pane",
            ]
            await pilot.click("#case-supporting")
            await pilot.pause()
            assert await pilot.click("#case-pin")
            await pilot.pause()
            selected = screen.selected_evidence.copy()
            notes = screen.query_one("#assessment-observed-facts", TextArea)
            notes.load_text("My draft stays unchanged by context pivots.")
            await pilot.pause()
            state = screen.draft_state()
            screen.query_one("#case-account", Input).value = "alice"

            async def context_tab():
                assert await pilot.click(tabs.get_tab("case-context-pane"))
                await pilot.pause()
                assert tabs.active == "case-context-pane"

            await context_tab()
            assert await pilot.click("#case-pivot-source")
            await pilot.pause()
            assert tabs.active == "case-evidence-pane"
            assert len(screen.visible_evidence) == 15
            assert screen.query_one("#case-ip", Input).value == "10.10.0.101"
            assert screen.query_one("#case-account", Input).value == ""
            assert not screen.query_one("#case-alert-only", Checkbox).value

            await context_tab()
            assert await pilot.click("#case-pivot-earlier")
            await pilot.pause()
            assert len(screen.visible_evidence) == 9
            assert all(
                item.event.occurred_at
                < screen.active_window_start(screen.investigation)
                for item in screen.visible_evidence
            )
            # Both observer matches use the same evaluation-window boundary.
            screen.query_one("#case-alert-select", Select).value = "1"
            await pilot.pause()
            await context_tab()
            assert await pilot.click("#case-pivot-earlier")
            await pilot.pause()
            assert len(screen.visible_evidence) == 9

            await context_tab()
            assert await pilot.click("#case-pivot-success")
            await pilot.pause()
            assert tabs.active == "case-evidence-pane"
            assert len(screen.visible_evidence) == 1
            assert screen.visible_evidence[0].event.event_id == 4624
            assert screen.query_one("#case-ip", Input).value == ""
            assert screen.query_one("#case-to", Input).value == ""
            assert screen.selected_evidence == selected
            assert screen.draft_state() == state

            await context_tab()
            assert await pilot.click("#case-event-notes")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            assert app.screen.guide_content == WINDOWS_EVENT_NOTES
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is screen and tabs.active == "case-context-pane"
            await pilot.press("g")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            assert WINDOWS_EVENT_NOTES in app.screen.guide_content
            await pilot.press("escape")
            await pilot.pause()
            assert screen.draft_state() == state

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original


def test_investigation_opens_filters_and_selects_evidence_read_only(prepared, tmp_path):
    original_files = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            # Exercise actions without depending on the button debounce animation.
            for button in screen.query(Button):
                button.active_effect_duration = 0
            await pilot.click("#case-open")
            await pilot.pause()
            assert screen.investigation is not None
            alert = screen.query_one("#case-alert-details", Static).content
            assert isinstance(alert, Text)
            assert alert.spans[0].start == 0
            assert alert.spans[0].end == alert.plain.index("\n")
            assert alert.spans[0].style == (
                f"bold {app.get_css_variables()['title-color']}"
            )
            assert "rule-test result" in alert.plain
            assert "2026-10-12" in alert.plain  # processing time
            assert "2026-09-14" in alert.plain  # event time
            await pilot.click("#case-supporting")
            await pilot.pause()
            table = screen.query_one("#case-event-table", DataTable)
            assert (
                screen.query_one("#case-tabs", TabbedContent).active
                == "case-evidence-pane"
            )
            assert table.row_count == 3
            assert await pilot.click("#case-pin")
            await pilot.pause()
            selected = screen.selected_evidence.copy()
            assert len(selected) == 1

            await pilot.click("#case-clear")
            await pilot.pause()
            assert table.row_count == 15
            assert screen.selected_evidence == selected
            screen.query_one("#case-account", Input).value = "bob"
            await pilot.click("#case-apply")
            await pilot.pause()
            assert table.row_count == 5
            assert any(item.event.event_id == 4624 for item in screen.visible_evidence)
            assert screen.query_one("#case-pin", Button).disabled is False

            screen.query_one("#case-from", Input).value = "09:15"
            screen.query_one("#case-to", Input).value = "09:16"
            await pilot.click("#case-apply")
            await pilot.pause()
            assert table.row_count == 2
            before = screen.visible_evidence
            screen.query_one("#case-from", Input).value = "bad time"
            await pilot.click("#case-apply")
            await pilot.pause()
            assert screen.visible_evidence == before
            status = screen.query_one("#case-filter-status", Static).content
            assert isinstance(status, Text) and "Invalid filter" in status.plain

            await pilot.click("#case-clear")
            await pilot.pause()
            screen.query_one("#case-from", Input).value = "09:16"
            await pilot.click("#case-apply")
            await pilot.pause()
            assert table.row_count == 0
            assert screen.query_one("#case-pin", Button).disabled is True
            status = screen.query_one("#case-filter-status", Static).content
            assert isinstance(status, Text) and "unavailable" in status.plain

            await pilot.click("#case-clear")
            await pilot.pause()
            screen.query_one("#case-selected-only", Checkbox).value = True
            await pilot.pause()
            assert table.row_count == 1
            await pilot.press("g")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is screen
            assert screen.selected_evidence == selected

            tabs = screen.query_one("#case-tabs", TabbedContent)
            assert await pilot.click(tabs.get_tab("case-alert-pane"))
            await pilot.pause()
            assert tabs.active == "case-alert-pane"
            screen.query_one("#case-alert-select", Select).value = "1"
            await pilot.pause()
            assert screen.alert_index == 1
            assert await pilot.click("#case-supporting")
            await pilot.pause()
            assert table.row_count == 3
            assert {item.event.event_id for item in screen.visible_evidence} == {4625}
            assert screen.selected_evidence == selected

            await pilot.click("#case-back")
            await pilot.pause()
            assert isinstance(app.screen, AssessmentExitScreen)
            assert screen.selected_evidence == selected
            await pilot.click("#assessment-discard")
            await pilot.pause()
            assert screen.selected_evidence == set()
            await pilot.click("#case-menu")
            await pilot.pause()
            assert not isinstance(app.screen, InvestigationScreen)

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original_files


def test_filter_actions_refresh_once_without_changing_picks_or_notes(
    prepared, tmp_path, monkeypatch
):
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }
    calls = []

    def counted_filter(case, **filters):
        calls.append(filters)
        return filter_investigation_evidence(case, **filters)

    monkeypatch.setattr(
        "simlab.investigation_tui.filter_investigation_evidence", counted_filter
    )

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            for button in screen.query(Button):
                button.active_effect_duration = 0
            assert await pilot.click("#case-open")
            await pilot.pause()
            assert len(calls) == 1
            table = screen.query_one("#case-event-table", DataTable)
            assert table.border_subtitle == "15/15 shown | 0 selected"
            calls.clear()
            assert await pilot.click("#case-supporting")
            await pilot.pause()
            assert len(calls) == 1
            table = screen.query_one("#case-event-table", DataTable)
            assert table.row_count == 3
            assert table.border_subtitle == "3/15 shown | 0 selected"
            table.move_cursor(row=2)
            await pilot.pause()
            current = screen.selected_event
            assert current is not None
            calls.clear()
            assert await pilot.click("#case-pin")
            await pilot.pause()
            assert len(calls) == 1 and screen.selected_event == current
            assert table.border_subtitle == "3/15 shown | 1 selected"
            assert screen.query_one("#case-detail-panel").border_subtitle == (
                f"Event {current.event.event_id} | Selected"
            )
            screen.query_one("#assessment-observed-facts", TextArea).load_text(
                "My draft must survive changing evidence filters."
            )
            await pilot.pause()
            draft = screen.draft_state()

            calls.clear()
            screen.query_one("#case-selected-only", Checkbox).value = True
            await pilot.pause()
            assert len(calls) == 1 and table.row_count == 1
            assert screen.selected_event == current
            calls.clear()
            screen.query_one("#case-event-id", Select).value = "4624"
            await pilot.pause()
            assert len(calls) == 1 and table.row_count == 0
            assert table.border_subtitle == "0/15 shown | 1 selected"
            assert screen.query_one("#case-detail-panel").border_subtitle == (
                "No matching event"
            )
            calls.clear()
            assert await pilot.click("#case-clear")
            await pilot.pause()
            assert len(calls) == 1 and table.row_count == 15
            assert screen.draft_state() == draft

            tabs = screen.query_one("#case-tabs", TabbedContent)
            for button, count in (
                ("case-pivot-source", 15),
                ("case-pivot-earlier", 9),
                ("case-pivot-success", 1),
            ):
                assert await pilot.click(tabs.get_tab("case-context-pane"))
                await pilot.pause()
                assert tabs.active == "case-context-pane"
                calls.clear()
                assert await pilot.click(f"#{button}")
                await pilot.pause()
                assert len(calls) == 1 and table.row_count == count
                assert table.border_subtitle == f"{count}/15 shown | 1 selected"
                assert tabs.active == "case-evidence-pane"
                assert screen.draft_state() == draft

            # Switching matches refreshes once, without accumulating callbacks.
            calls.clear()
            screen.query_one("#case-alert-select", Select).value = "1"
            await pilot.pause()
            assert len(calls) == 1 and screen.alert_index == 1
            assert screen.query_one("#case-alert-scroll").border_subtitle == (
                "Match 2 of 2"
            )
            assert screen.draft_state() == draft

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original


def test_filter_refresh_keeps_cursor_details_and_empty_states_in_sync(
    prepared, tmp_path, monkeypatch
):
    calls = []

    def counted_filter(case, **filters):
        calls.append(filters)
        return filter_investigation_evidence(case, **filters)

    monkeypatch.setattr(
        "simlab.investigation_tui.filter_investigation_evidence", counted_filter
    )

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            for button in screen.query(Button):
                button.active_effect_duration = 0
            assert await pilot.click("#case-open")
            await pilot.pause()
            tabs = screen.query_one("#case-tabs", TabbedContent)
            tabs.active = "case-evidence-pane"
            await pilot.pause()
            table = screen.query_one("#case-event-table", DataTable)
            stale_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            target = next(
                item
                for item in reversed(screen.visible_evidence)
                if item.event.event_id == 4776
                and item.event.data.target_user_name == "bob"
            )
            table.move_cursor(row=screen.visible_evidence.index(target))
            await pilot.pause()
            assert screen.selected_event == target

            def assert_current(item):
                assert screen.selected_event == item
                row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
                assert row_key.value == item.event_instance_id
                details = screen.query_one("#case-event-details", Static).content
                assert isinstance(details, Text)
                assert f"Windows event {item.event.event_id}" in details.plain
                assert f"Record ID: {item.event.record_id}" in details.plain

            calls.clear()
            account = screen.query_one("#case-account", Input)
            account.value = "bob"
            account.focus()
            await pilot.pause()
            assert calls == [] and table.row_count == 15
            await pilot.press("enter")
            await pilot.pause()
            assert len(calls) == 1 and table.row_count == 5
            assert_current(target)

            # An old highlight notification must not replace the current detail.
            table.post_message(DataTable.RowHighlighted(table, 0, stale_key))
            await pilot.pause()
            assert_current(target)

            calls.clear()
            event_id = screen.query_one("#case-event-id", Select)
            event_id.value = "4776"
            await pilot.pause()
            assert len(calls) == 1 and table.row_count == 1
            assert_current(target)

            before = screen.visible_evidence
            screen.query_one("#case-from", Input).value = "invalid time"
            assert await pilot.click("#case-apply")
            await pilot.pause()
            assert screen.visible_evidence == before
            assert_current(target)
            status = screen.query_one("#case-filter-status", Static).content
            assert isinstance(status, Text) and "Invalid filter" in status.plain

            calls.clear()
            screen.query_one("#case-from", Input).value = ""
            event_id.value = "4625"
            await pilot.pause()
            assert len(calls) == 1 and table.row_count == 1
            replacement = screen.visible_evidence[0]
            assert replacement != target
            assert_current(replacement)

            calls.clear()
            assert await pilot.click("#case-clear")
            await pilot.pause()
            assert len(calls) == 1 and table.row_count == 15
            assert_current(replacement)
            screen.query_one("#case-selected-only", Checkbox).value = True
            await pilot.pause()
            assert table.row_count == 0 and screen.selected_event is None
            assert screen.query_one("#case-pin", Button).disabled
            assert not screen.selected_evidence
            assert not screen.has_unsaved_assessment

    asyncio.run(exercise())


def test_investigation_shortcuts_navigate_select_and_reuse_match_filters(
    prepared, tmp_path, monkeypatch
):
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }
    calls = []

    def counted_filter(case, **filters):
        calls.append(filters)
        return filter_investigation_evidence(case, **filters)

    monkeypatch.setattr(
        "simlab.investigation_tui.filter_investigation_evidence", counted_filter
    )

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            for button in screen.query(Button):
                button.active_effect_duration = 0
            screen.query_one("#case-open", Button).focus()
            await pilot.press(
                "1",
                "2",
                "3",
                "4",
                "slash",
                "left_square_bracket",
                "right_square_bracket",
            )
            assert screen.investigation is None
            assert await pilot.click("#case-open")
            await pilot.pause()
            screen.query_one("#case-back", Button).focus()
            tabs = screen.query_one("#case-tabs", TabbedContent)
            for key, section in (
                ("4", "assessment"),
                ("3", "context"),
                ("1", "alert"),
                ("2", "evidence"),
            ):
                await pilot.press(key)
                await pilot.pause()
                assert tabs.active == f"case-{section}-pane"
            table = screen.query_one("#case-event-table", DataTable)
            assert table.has_focus
            assert screen.active_bindings["space"].enabled
            await pilot.press("down", "space")
            await pilot.pause()
            reference = screen.visible_evidence[table.cursor_row].event_instance_id
            assert screen.selected_evidence == {reference}
            assert table.has_focus
            await pilot.press("space", "enter")
            await pilot.pause()
            assert not screen.selected_evidence
            await pilot.press("space")
            await pilot.pause()
            screen.query_one("#case-selected-only", Checkbox).value = True
            await pilot.pause()
            assert table.row_count == 1
            await pilot.press("space")
            await pilot.pause()
            assert table.row_count == 0 and screen.selected_event is None
            assert not screen.selected_evidence
            assert not screen.active_bindings["space"].enabled
            await pilot.press("space")
            assert not screen.selected_evidence

            assert await pilot.click("#case-clear")
            await pilot.pause()
            table.focus()
            await pilot.press("space")
            await pilot.pause()
            selected = screen.selected_evidence.copy()
            screen.query_one("#case-alert-only", Checkbox).value = True
            await pilot.pause()
            for key, expected, refreshes in (
                ("left_square_bracket", 0, 0),
                ("right_square_bracket", 1, 1),
                ("right_square_bracket", 1, 0),
                ("left_square_bracket", 0, 1),
            ):
                calls.clear()
                await pilot.press(key)
                await pilot.pause()
                assert screen.alert_index == expected
                assert screen.query_one("#case-alert-select", Select).value == str(
                    expected
                )
                assert len(calls) == refreshes
                assert {item.event_instance_id for item in screen.visible_evidence} == (
                    set(screen.investigation.alerts[expected].supporting_event_ids)
                )
                assert screen.selected_evidence == selected
            before = screen.visible_evidence
            calls.clear()
            await pilot.press("1", "slash")
            await pilot.pause()
            assert tabs.active == "case-evidence-pane"
            assert screen.query_one("#case-account", Input).has_focus
            assert screen.visible_evidence == before
            assert screen.selected_evidence == selected
            assert not calls

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original


def test_investigation_shortcuts_do_not_steal_text_dropdown_or_modal_keys(
    prepared, tmp_path
):
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }
    keys = ("1", "2", "3", "4", "slash", "left_square_bracket", "right_square_bracket")

    def active_shortcuts(screen):
        return {
            entry.binding.action.split("(")[0]
            for entry in screen.active_bindings.values()
        } & {"section", "focus_filters", "toggle_current_evidence", "change_match"}

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            assert await pilot.click("#case-open")
            await pilot.pause()
            screen.query_one("#case-back", Button).focus()
            await pilot.press("slash")
            await pilot.pause()
            tabs = screen.query_one("#case-tabs", TabbedContent)
            account = screen.query_one("#case-account", Input)
            assert not active_shortcuts(screen)
            await pilot.press(*keys, "space")
            assert account.value == "1234/[] "
            assert tabs.active == "case-evidence-pane"
            assert len(screen.visible_evidence) == 15
            account.value = ""
            screen.query_one("#case-back", Button).focus()
            await pilot.press("4")
            await pilot.pause()
            note = screen.query_one("#assessment-observed-facts", TextArea)
            note.focus()
            await pilot.pause()
            assert not active_shortcuts(screen)
            await pilot.press(*keys, "space")
            assert note.text == "1234/[] "
            assert tabs.active == "case-assessment-pane"
            assert screen.alert_index == 0 and not screen.selected_evidence
            draft = screen.draft_state()

            for identifier in ("case-alert-select", "assessment-decision"):
                selector = screen.query_one(f"#{identifier}", Select)
                selector.focus()
                await pilot.pause()
                value = selector.value
                assert not active_shortcuts(screen)
                await pilot.press(*keys)
                assert not selector.expanded
                await pilot.press("enter")
                await pilot.pause()
                assert selector.expanded
                assert not active_shortcuts(screen)
                await pilot.press(*keys, "space")
                assert selector.value == value
                assert selector.expanded
                assert tabs.active == "case-assessment-pane"
                assert screen.alert_index == 0
                assert screen.draft_state() == draft
                await pilot.press("escape")
                await pilot.pause()
                assert not selector.expanded

            screen.query_one("#case-back", Button).focus()
            await pilot.press("g")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            assert not active_shortcuts(app.screen)
            await pilot.press(*keys)
            assert isinstance(app.screen, GuideScreen)
            assert tabs.active == "case-assessment-pane"
            assert screen.draft_state() == draft
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, AssessmentExitScreen)
            assert not active_shortcuts(app.screen)
            await pilot.press(*keys)
            assert isinstance(app.screen, AssessmentExitScreen)
            assert screen.draft_state() == draft

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original


@pytest.mark.parametrize("terminal_size", [(150, 50), (208, 47)])
def test_titled_panels_and_current_row_remain_clear_when_focus_moves(
    prepared, tmp_path, terminal_size
):
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=terminal_size) as pilot:
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            assert await pilot.click("#case-open")
            await pilot.pause()
            assert await pilot.click("#case-supporting")
            await pilot.pause()
            for identifier, title in {
                "case-filters": "Filters",
                "case-event-table": "Evidence",
                "case-detail-panel": "Current event",
            }.items():
                panel = screen.query_one(f"#{identifier}")
                assert panel.border_title == title
                assert panel.styles.border.top[0] == "ascii"
            table = screen.query_one("#case-event-table", DataTable)
            detail = screen.query_one("#case-detail-panel")
            assert table.region.right <= detail.region.x
            assert detail.region.right <= screen.region.right
            assert table.region.height >= 8
            table.move_cursor(row=2)
            table.focus()
            await pilot.pause()
            current = screen.selected_event
            assert current is not None
            focused = table.get_component_rich_style("datatable--cursor")
            assert focused.reverse and focused.bold
            pin = screen.query_one("#case-pin", Button)
            pin.focus()
            await pilot.pause()
            blurred = table.get_component_rich_style("datatable--cursor")
            assert blurred.reverse and not blurred.bold
            assert screen.selected_event == current
            assert not screen.selected_evidence
            assert pin.size.height == 1
            assert pin.styles.border.left[0] == "ascii"
            assert not pin.styles.border.top[0]

            tabs = screen.query_one("#case-tabs", TabbedContent)
            assert await pilot.click(tabs.get_tab("case-assessment-pane"))
            await pilot.pause()
            form = screen.query_one("#assessment-form")
            assert form.border_title == "Assessment"
            assert form.styles.border.top[0] == "ascii"
            note = screen.query_one("#assessment-observed-facts", TextArea)
            note.focus()
            await pilot.pause()
            assert note.styles.border.left[0] == "ascii"
            assert not note.styles.border.top[0]
            assert not screen.has_unsaved_assessment

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original


def test_assessment_ui_saves_restores_and_protects_unsaved_work(
    prepared, tmp_path, monkeypatch
):
    original = {
        path: path.read_bytes()
        for root in (prepared.case.path, prepared.evaluation_path)
        for path in root.rglob("*")
        if path.is_file()
    }

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            for button in screen.query(Button):
                button.active_effect_duration = 0
            await pilot.click("#case-open")
            await pilot.pause()
            await pilot.click("#case-supporting")
            await pilot.pause()
            assert await pilot.click("#case-pin")
            await pilot.pause()
            selected = screen.selected_evidence.copy()

            tabs = screen.query_one("#case-tabs", TabbedContent)
            assert await pilot.click(tabs.get_tab("case-assessment-pane"))
            await pilot.pause()
            assert screen.query_one("#assessment-decision", Select).selection is None
            assert all(
                screen.query_one(f"#{screen.note_id(field)}", TextArea).text == ""
                for field in NOTE_LABELS
            )
            assert await pilot.click("#assessment-save")
            await pilot.pause()
            assert screen.saved_assessment is None
            status = screen.query_one("#assessment-status", Static).content
            assert isinstance(status, Text) and "Cannot save" in status.plain

            for field in NOTE_LABELS:
                screen.query_one(f"#{screen.note_id(field)}", TextArea).load_text(
                    f"Analyst-authored {field} for this exercise."
                )
            screen.query_one("#assessment-decision", Select).value = "escalate"
            await pilot.pause()
            # TAB must navigate notes rather than inserting indentation.
            facts = screen.query_one("#assessment-observed-facts", TextArea)
            facts.focus()
            await pilot.pause()
            before = facts.text
            await pilot.press("tab")
            await pilot.pause()
            assert facts.text == before
            assert app.focused is screen.query_one(
                "#assessment-working-hypothesis", TextArea
            )
            await pilot.press("ctrl+s")
            await pilot.pause()
            first = screen.saved_assessment
            assert first is not None
            assert set(first.assessment.selected_event_ids) == selected
            assert screen.query_one("#assessment-save", Button).disabled
            assert screen.draft_state() == screen.saved_draft_state
            first_files = {path: path.read_bytes() for path in first.path.iterdir()}

            assert await pilot.click("#assessment-view")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            assert first.assessment.observed_facts in app.screen.guide_content
            assert next(iter(selected)) in app.screen.guide_content
            await pilot.press("escape")
            await pilot.pause()

            changed = "Revised hypothesis; still not proof of compromise."
            screen.query_one("#assessment-working-hypothesis", TextArea).load_text(
                changed
            )
            await pilot.pause()
            assert not screen.query_one("#assessment-save", Button).disabled

            def fail_write(*args, **kwargs):
                raise OSError("simulated disk error")

            with monkeypatch.context() as patch:
                patch.setattr("simlab.assessment.write_verified_directory", fail_write)
                assert await pilot.click("#assessment-save")
                await pilot.pause()
                assert screen.saved_assessment == first
                assert (
                    screen.query_one("#assessment-working-hypothesis", TextArea).text
                    == changed
                )
                status = screen.query_one("#assessment-status", Static).content
                assert isinstance(status, Text) and "disk error" in status.plain

            assert await pilot.click("#assessment-save")
            await pilot.pause()
            second = screen.saved_assessment
            assert second is not None and second.path != first.path
            assert {
                path: path.read_bytes() for path in first.path.iterdir()
            } == first_files
            assert load_latest_assessment(screen.investigation, tmp_path) == second
            assert await pilot.click("#case-back")
            await pilot.pause()
            assert app.screen is screen  # no discard prompt for saved work
            assert screen.investigation is None
            assert await pilot.click("#case-open")
            await pilot.pause()
            assert screen.saved_assessment == second
            assert screen.selected_evidence == selected
            assert (
                screen.query_one("#assessment-working-hypothesis", TextArea).text
                == changed
            )

            screen.query_one("#assessment-observed-facts", TextArea).load_text(
                "An unsaved revision."
            )
            await pilot.pause()
            assert await pilot.click("#case-back")
            await pilot.pause()
            assert isinstance(app.screen, AssessmentExitScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is screen
            assert screen.query_one("#assessment-observed-facts", TextArea).text == (
                "An unsaved revision."
            )
            assert await pilot.click("#case-back")
            await pilot.pause()
            assert await pilot.click("#assessment-discard")
            await pilot.pause()
            assert screen.investigation is None
            assert await pilot.click("#case-open")
            await pilot.pause()
            assert screen.saved_assessment == second
            assert screen.query_one("#assessment-observed-facts", TextArea).text == (
                second.assessment.observed_facts
            )

    asyncio.run(exercise())
    assert {path: path.read_bytes() for path in original} == original


def test_assessment_ui_rejects_corrupt_restore_and_requires_selected_evidence(
    prepared, tmp_path
):
    investigation = load_saved_investigation(
        prepared.case.path, prepared.evaluation_path
    )
    notes = AssessmentNotes(
        disposition="needs_evidence",
        **{field: f"Analyst note for {field}." for field in NOTE_LABELS},
    )
    saved = save_assessment(
        investigation,
        tmp_path,
        notes,
        {investigation.case.evidence[0].event_instance_id},
    )
    (saved.path / "SHA256SUMS").write_text("corrupt\n")

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            for button in screen.query(Button):
                button.active_effect_duration = 0
            await pilot.click("#case-open")
            await pilot.pause()
            assert screen.investigation is not None
            assert screen.saved_assessment is None
            assert screen.selected_evidence == set()
            status = screen.query_one("#assessment-status", Static).content
            assert isinstance(status, Text) and "could not be restored" in status.plain
            tabs = screen.query_one("#case-tabs", TabbedContent)
            assert await pilot.click(tabs.get_tab("case-assessment-pane"))
            await pilot.pause()
            for field in NOTE_LABELS:
                screen.query_one(f"#{screen.note_id(field)}", TextArea).load_text(
                    getattr(notes, field)
                )
            screen.query_one("#assessment-decision", Select).value = "needs_evidence"
            await pilot.pause()
            assert await pilot.click("#assessment-save")
            await pilot.pause()
            status = screen.query_one("#assessment-status", Static).content
            assert isinstance(status, Text) and "Select at least one" in status.plain
            assert screen.saved_assessment is None
            assert len(list(saved.path.parent.glob("assessment-*"))) == 1
            assert (saved.path / "SHA256SUMS").read_text() == "corrupt\n"

    asyncio.run(exercise())


def test_investigation_menu_handles_empty_and_corrupt_cases(prepared, tmp_path):
    (prepared.evaluation_path / "SHA256SUMS").write_text("invalid\n")

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            await pilot.click("#case-open")
            await pilot.pause()
            assert screen.investigation is None
            content = screen.query_one("#case-picker-status", Static).content
            assert isinstance(content, Text) and "Cannot open case" in content.plain
            await pilot.press("escape")
            await pilot.pause()

        empty_app = SimLabApp(PROJECT_ROOT, tmp_path / "empty")
        async with empty_app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-investigation")
            await pilot.pause()
            screen = empty_app.screen
            assert screen.query_one("#case-open", Button).disabled is True
            content = screen.query_one("#case-picker-status", Static).content
            assert (
                isinstance(content, Text) and "prepare password-spray" in content.plain
            )

    asyncio.run(exercise())

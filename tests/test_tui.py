import asyncio
from pathlib import Path

import pytest
from textual.color import Color
from textual.content import Content
from textual.widgets import Button, OptionList, Select, Static, TabbedContent, TextArea

from simlab.assessment import NOTE_LABELS, AssessmentNotes, save_assessment
from simlab.investigation_tui import AssessmentExitScreen, InvestigationScreen
from simlab.preparation_tui import PreparationScreen
from simlab.tui import GuideScreen, SimLabApp
from simlab.wazuh_evaluation import load_saved_investigation
from tests.test_investigation_tui import prepared as prepared

PROJECT_ROOT = Path(__file__).resolve().parents[1]


async def request_quit(app, pilot, source):
    if source == "palette":
        command = next(
            command
            for command in app.get_system_commands(app.screen)
            if command.title == "Quit"
        )
        await command.callback()
    else:
        await pilot.press(source)
    await pilot.pause()


def test_main_menu_has_only_investigation_entries_and_shared_guide(tmp_path):
    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            root = app.screen
            assert app.theme == "simlab-soc"
            assert root.styles.background.ansi == -1
            card = root.query_one("#welcome-card")
            assert card.styles.background.ansi == -1
            assert card.styles.border.top[0] == "ascii"
            start = root.query_one("#start-preparation", Button)
            assert start.styles.background.ansi == -1
            assert not start.styles.border.top[0]
            assert start.size.height == 1
            colors = app.get_css_variables()
            assert root.query_one("#welcome-guide", Button).styles.color == Color.parse(
                colors["action-color"]
            )
            assert card.border_title == "SOC investigation workspace"
            assert card.styles.border_title_color == Color.parse(colors["title-color"])
            start.focus()
            await pilot.pause()
            assert start.styles.color == Color.parse(colors["action-focus-color"])
            assert start.styles.border.left[0] == "ascii"
            assert start.styles.border.left[1] == Color.parse(colors["accent"])
            assert {button.id for button in root.query(Button)} == {
                "start-preparation",
                "start-investigation",
                "welcome-guide",
            }
            assert not root.query("#workflow-shell")
            assert not root.query("#start-new")
            assert not root.query("#start-existing")
            assert await pilot.click("#welcome-guide")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            assert app.screen.styles.background.ansi == -1
            assert app.screen.query_one("#guide-dialog").styles.border.top[0] == "ascii"
            assert "Docker startup/shutdown stays manual" in app.screen.guide_content
            assert "Alert → Evidence → Context → Assessment" in app.screen.guide_content
            assert "old/" not in app.screen.guide_content
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is root

            await pilot.press("g")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            await pilot.press("g")
            await pilot.pause()
            assert app.screen is root

    asyncio.run(exercise())


def test_start_and_resume_return_to_the_same_main_menu_without_generating(tmp_path):
    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            root = app.screen
            assert await pilot.click("#start-preparation")
            await pilot.pause()
            assert isinstance(app.screen, PreparationScreen)
            assert app.screen.styles.background.ansi == -1
            card = app.screen.query_one("#preparation-card")
            assert card.styles.background.ansi == -1
            assert card.styles.border.top[0] == "ascii"
            assert app.screen.prepared is None
            assert await pilot.click("#prepare-back")
            await pilot.pause()
            assert app.screen is root

            assert await pilot.click("#start-investigation")
            await pilot.pause()
            assert isinstance(app.screen, InvestigationScreen)
            assert app.screen.styles.background.ansi == -1
            card = app.screen.query_one("#case-picker-card")
            assert card.styles.background.ansi == -1
            assert card.styles.border.top[0] == "ascii"
            assert app.screen.query_one("#case-open", Button).disabled
            assert await pilot.click("#case-menu")
            await pilot.pause()
            assert app.screen is root

    asyncio.run(exercise())
    assert list(tmp_path.iterdir()) == []


def test_hover_focus_and_disabled_buttons_have_distinct_styles(tmp_path):
    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            guide = app.screen.query_one("#welcome-guide", Button)
            start = app.screen.query_one("#start-preparation", Button)
            start.focus()
            await pilot.pause()
            assert await pilot.hover("#welcome-guide")
            await pilot.pause()
            assert not guide.has_focus
            assert guide.styles.text_style.underline
            assert guide.styles.border.left[0] == "blank"
            guide.focus()
            await pilot.pause()
            assert guide.styles.border.left[0] == "ascii"
            assert guide.styles.text_style.bold
            assert not guide.styles.text_style.underline
            assert not guide.styles.border.top[0]
            start.disabled = True
            await pilot.pause()
            assert start.styles.text_style.strike
            assert start.styles.border.left[0] == "blank"
            assert start.size.height == guide.size.height == 1

    asyncio.run(exercise())


@pytest.mark.parametrize("identifier", ["case-select", "case-alert-select"])
def test_dropdown_options_have_visible_hover_and_keyboard_row_backgrounds(
    prepared, tmp_path, identifier
):
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            if identifier == "case-alert-select":
                assert await pilot.click("#case-open")
                await pilot.pause()
            selector = screen.query_one(f"#{identifier}", Select)
            previous_value = selector.value
            previous_match = screen.alert_index
            selector.focus()
            await pilot.press("enter")
            await pilot.pause()
            overlay = selector.query_one("SelectOverlay", OptionList)
            assert selector.expanded and overlay.has_focus
            # Both selectors include a prompt followed by at least one real option.
            await pilot.press("home", "down")
            await pilot.pause()
            assert overlay.highlighted == 1
            assert await pilot.hover(overlay, offset=(3, 1))
            await pilot.pause()
            colors = app.get_css_variables()
            active_color = Color.parse(colors["dropdown-active-background"])
            hover_color = Color.parse(colors["dropdown-hover-background"])
            assert active_color != hover_color
            assert (
                overlay.get_component_styles(
                    "option-list--option-highlighted"
                ).background
                == active_color
            )
            assert (
                overlay.get_component_styles("option-list--option-hover").background
                == hover_color
            )
            # Verify rendered row fills, not just declared CSS flags.
            for line, expected in ((0, hover_color), (1, active_color)):
                assert any(
                    segment.style is not None
                    and segment.style.bgcolor == expected.rich_color
                    for segment in overlay.render_line(line)
                )
            assert selector.value == previous_value
            assert screen.alert_index == previous_match
            await pilot.press("escape")
            await pilot.pause()
            assert not selector.expanded
            assert app.screen.styles.background.ansi == -1

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original


def test_shared_overlay_treats_content_as_read_only_text(tmp_path):
    content = "[red]literal text[/red] and a saved reference"

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            root = app.screen
            await app.push_screen(GuideScreen("Reference", content))
            await pilot.pause()
            shown = app.screen.query_one("#guide-content", Static)
            assert shown.content == content
            rendered = shown.render()
            assert isinstance(rendered, Content)
            assert rendered.plain == content
            assert await pilot.click("#close-guide")
            await pilot.pause()
            assert app.screen is root

    asyncio.run(exercise())


def test_builtin_themes_remain_usable_with_guides_and_screen_styles(tmp_path):
    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            root = app.screen
            for theme in ("textual-dark", "textual-light", "ansi-dark", "simlab-soc"):
                app.theme = theme
                await pilot.pause()
                assert app.theme == theme
                assert {
                    "title-color",
                    "action-color",
                    "action-focus-color",
                } <= app.get_css_variables().keys()
                assert "Theme" in {
                    command.title for command in app.get_system_commands(app.screen)
                }
                assert await pilot.click("#welcome-guide")
                await pilot.pause()
                assert isinstance(app.screen, GuideScreen)
                await pilot.press("escape")
                await pilot.pause()
                assert app.screen is root

            app.theme = "textual-dark"
            await pilot.pause()
            assert await pilot.click("#start-preparation")
            await pilot.pause()
            assert isinstance(app.screen, PreparationScreen)
            assert await pilot.click("#prepare-back")
            await pilot.pause()
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            assert isinstance(app.screen, InvestigationScreen)

    asyncio.run(exercise())


def test_clean_main_menu_and_guide_allow_all_normal_quit_actions(tmp_path, monkeypatch):
    exits = []

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        monkeypatch.setattr(app, "exit", lambda *args, **kwargs: exits.append(True))
        async with app.run_test(size=(150, 50)) as pilot:
            for source in ("q", "ctrl+q", "palette"):
                await request_quit(app, pilot, source)
            assert exits == [True, True, True]
            assert await pilot.click("#welcome-guide")
            await pilot.pause()
            await request_quit(app, pilot, "ctrl+q")
            assert exits == [True, True, True, True]

    asyncio.run(exercise())


def test_busy_preparation_blocks_quit_under_guide_and_palette(tmp_path, monkeypatch):
    exits = []
    notices = []

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        monkeypatch.setattr(app, "exit", lambda *args, **kwargs: exits.append(True))
        monkeypatch.setattr(
            app, "notify", lambda message, **kwargs: notices.append(message)
        )
        async with app.run_test(size=(150, 50)) as pilot:
            assert await pilot.click("#start-preparation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, PreparationScreen)
            # Exercise the guard without launching a Docker worker.
            screen.busy = True
            screen.update_controls()
            for source in ("q", "ctrl+q", "palette"):
                await request_quit(app, pilot, source)
                assert exits == [] and screen.busy
            assert await pilot.click("#prepare-guide")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            for source in ("q", "ctrl+q", "palette"):
                await request_quit(app, pilot, source)
                assert exits == [] and screen.busy
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("ctrl+p")
            await pilot.pause()
            assert app.screen is not screen
            await request_quit(app, pilot, "ctrl+q")
            assert exits == [] and screen.busy
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is screen
            assert len(notices) == 7
            assert all("Preparation is still running" in notice for notice in notices)
            screen.busy = False
            screen.update_controls()
            await request_quit(app, pilot, "q")
            assert exits == [True]

    asyncio.run(exercise())
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("source", ["q", "ctrl+q", "palette"])
def test_quit_protects_unsaved_selection_and_notes_through_overlays(
    prepared, tmp_path, monkeypatch, source
):
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }
    exits = []

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        monkeypatch.setattr(app, "exit", lambda *args, **kwargs: exits.append(True))
        async with app.run_test(size=(150, 50)) as pilot:
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            for button in screen.query(Button):
                button.active_effect_duration = 0
            assert await pilot.click("#case-open")
            await pilot.pause()
            assert not screen.has_unsaved_assessment
            assert await pilot.click("#case-supporting")
            await pilot.pause()
            assert await pilot.click("#case-pin")
            await pilot.pause()
            selected = screen.selected_evidence.copy()
            assert selected and screen.has_unsaved_assessment
            assert await pilot.click("#case-guide")
            await pilot.pause()
            guide = app.screen
            assert isinstance(guide, GuideScreen)
            await request_quit(app, pilot, source)
            prompt = app.screen
            assert isinstance(prompt, AssessmentExitScreen) and prompt.quitting
            assert "quit" in str(prompt.query_one("#assessment-discard", Button).label)
            await request_quit(app, pilot, "ctrl+q")
            assert app.screen is prompt
            assert len(app.screen_stack) == 4
            assert exits == [] and screen.selected_evidence == selected
            assert await pilot.click("#assessment-stay")
            await pilot.pause()
            assert app.screen is guide
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is screen

            # Notes alone must be protected even with no selected evidence.
            screen.selected_evidence.clear()
            screen.update_selection_status()
            assert not screen.has_unsaved_assessment
            note = screen.query_one("#assessment-observed-facts", TextArea)
            note.load_text("Unsaved analyst reasoning.")
            await pilot.pause()
            assert screen.has_unsaved_assessment
            tabs = screen.query_one("#case-tabs", TabbedContent)
            tabs.active = "case-assessment-pane"
            await pilot.pause()
            note.focus()
            await pilot.pause()
            before_typing = note.text
            await pilot.press("q")
            await pilot.pause()
            assert len(note.text) == len(before_typing) + 1
            assert app.screen is screen and exits == []
            typed_note = note.text
            screen.query_one("#case-back", Button).focus()
            await pilot.pause()
            screen.action_back()
            await pilot.pause()
            leave_prompt = app.screen
            assert isinstance(leave_prompt, AssessmentExitScreen)
            assert not leave_prompt.quitting
            await request_quit(app, pilot, source)
            assert app.screen is leave_prompt and exits == []
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is screen and note.text == typed_note
            await request_quit(app, pilot, source)
            assert isinstance(app.screen, AssessmentExitScreen)
            assert app.screen.quitting
            assert await pilot.click("#assessment-discard")
            await pilot.pause()
            assert exits == [True]

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original


@pytest.mark.parametrize("saved", [False, True])
def test_unchanged_investigations_can_quit_without_a_prompt(
    prepared, tmp_path, monkeypatch, saved
):
    if saved:
        investigation = load_saved_investigation(
            prepared.case.path, prepared.evaluation_path
        )
        save_assessment(
            investigation,
            tmp_path,
            AssessmentNotes(
                disposition="needs_evidence",
                **{field: f"Saved analyst {field}." for field in NOTE_LABELS},
            ),
            {prepared.case.evidence[0].event_instance_id},
        )
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }
    exits = []

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        monkeypatch.setattr(app, "exit", lambda *args, **kwargs: exits.append(True))
        async with app.run_test(size=(150, 50)) as pilot:
            assert await pilot.click("#start-investigation")
            await pilot.pause()
            assert await pilot.click("#case-open")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, InvestigationScreen)
            assert not screen.has_unsaved_assessment
            assert (screen.saved_assessment is not None) is saved
            # Theme changes must also permit rerendering an open investigation.
            app.theme = "textual-dark"
            await pilot.pause()
            screen.render_alert()
            screen.apply_filters()
            assert not screen.has_unsaved_assessment
            screen.query_one("#case-back", Button).focus()
            await pilot.pause()
            if saved:
                screen.view_saved_report()
                await pilot.pause()
                assert isinstance(app.screen, GuideScreen)
            for source in ("q", "ctrl+q", "palette"):
                await request_quit(app, pilot, source)
            assert exits == [True, True, True]
            assert not any(
                isinstance(item, AssessmentExitScreen) for item in app.screen_stack
            )

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original

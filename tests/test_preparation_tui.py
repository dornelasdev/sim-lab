import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from threading import Event, get_ident
from types import SimpleNamespace

import pytest
from rich.text import Text
from textual.widgets import Button, Static

from simlab.investigation_tui import InvestigationScreen
from simlab.preparation_tui import PreparationScreen
from simlab.tui import GuideScreen, SimLabApp
from simlab.wazuh_evaluation import prepare_password_spray_investigation
from tests.test_investigation import _engine_response
from tests.test_investigation_tui import prepared as prepared

PROJECT_ROOT = Path(__file__).resolve().parents[1]


async def open_preparation(app, pilot):
    assert await pilot.click("#start-preparation")
    await pilot.pause()
    screen = app.screen
    assert isinstance(screen, PreparationScreen)
    for button in screen.query(Button):
        button.active_effect_duration = 0
    return screen


def test_start_investigation_prepares_with_existing_backend_and_opens_exact_run(
    tmp_path, monkeypatch
):
    requests = []

    def engine(command, **kwargs):
        requests.append(command)
        response = _engine_response(json.loads(kwargs["input"]))
        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(response))

    monkeypatch.setattr("simlab.wazuh_evaluation.subprocess.run", engine)

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            screen = await open_preparation(app, pilot)
            assert requests == []
            assert not (tmp_path / "cases").exists()
            assert screen.query_one("#prepare-open", Button).disabled
            await pilot.press("g")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            assert "Docker" in app.screen.guide_content
            await pilot.press("escape")
            await pilot.pause()

            assert await pilot.click("#prepare-case")
            await pilot.pause()
            assert screen.worker is not None
            await screen.worker.wait()
            await pilot.pause()
            target = screen.prepared
            assert target is not None and target.case.manifest.event_count == 15
            assert len(target.alerts) == 2
            assert len(requests) == 2
            assert all(
                "exec" in command and "up" not in command for command in requests
            )
            assert screen.query_one("#prepare-case", Button).disabled
            assert not screen.query_one("#prepare-open", Button).disabled

            # Save a newer valid run to ensure Open doesn't pick the latest by accident.
            def newer_engine(command, **kwargs):
                response = _engine_response(json.loads(kwargs["input"]))
                for result in response["results"]:
                    result["processed_at"] = (
                        datetime.fromisoformat(result["processed_at"])
                        + timedelta(days=1)
                    ).isoformat()
                return SimpleNamespace(
                    returncode=0, stderr="", stdout=json.dumps(response)
                )

            with monkeypatch.context() as patch:
                patch.setattr("simlab.wazuh_evaluation.subprocess.run", newer_engine)
                newer = prepare_password_spray_investigation(PROJECT_ROOT, tmp_path)
            assert newer.evaluation_path != target.evaluation_path

            def no_docker(*args, **kwargs):
                raise AssertionError("Opening saved results must not invoke Docker")

            monkeypatch.setattr("simlab.wazuh_evaluation.subprocess.run", no_docker)
            assert await pilot.click("#prepare-open")
            await pilot.pause()
            investigation = app.screen
            assert isinstance(investigation, InvestigationScreen)
            assert investigation.investigation is not None
            assert investigation.investigation.evaluation_path == target.evaluation_path
            assert len(investigation.options) == 2
            assert await pilot.click("#case-back")
            await pilot.pause()
            assert investigation.investigation is None
            assert await pilot.click("#case-menu")
            await pilot.pause()
            assert app.screen is app.screen_stack[0]

    asyncio.run(exercise())


def test_preparation_stays_responsive_and_prevents_duplicate_runs(
    prepared, tmp_path, monkeypatch
):
    entered = Event()
    release = Event()
    threads = []

    def blocking_prepare(*args):
        threads.append(get_ident())
        entered.set()
        if not release.wait(5):
            raise RuntimeError("test release timed out")
        return prepared

    monkeypatch.setattr(
        "simlab.preparation_tui.prepare_password_spray_investigation", blocking_prepare
    )

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            screen = await open_preparation(app, pilot)
            try:
                assert await pilot.click("#prepare-case")
                assert await asyncio.to_thread(entered.wait, 2)
                assert screen.busy
                assert len(threads) == 1 and threads[0] != get_ident()
                assert screen.query_one("#prepare-case", Button).disabled
                assert screen.query_one("#prepare-back", Button).disabled
                screen.start_preparation()
                assert len(threads) == 1
                await pilot.press("escape")
                await pilot.pause()
                assert app.screen is screen
                assert await pilot.click("#prepare-guide")
                await pilot.pause()
                assert isinstance(app.screen, GuideScreen)
                await pilot.press("escape")
                await pilot.pause()
                assert app.screen is screen and screen.busy
            finally:
                release.set()
            assert screen.worker is not None
            await screen.worker.wait()
            await pilot.pause()
            assert not screen.busy
            assert screen.prepared == prepared
            assert not screen.query_one("#prepare-back", Button).disabled

    asyncio.run(exercise())


@pytest.mark.parametrize("error_type", [ValueError, OSError, RuntimeError])
def test_failed_preparation_can_retry_without_local_fallback_or_app_exit(
    prepared, tmp_path, monkeypatch, error_type
):
    calls = []
    original = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }

    def prepare(*args):
        calls.append(args)
        if len(calls) == 1:
            raise error_type("manager unavailable")
        return prepared

    monkeypatch.setattr(
        "simlab.preparation_tui.prepare_password_spray_investigation", prepare
    )

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            screen = await open_preparation(app, pilot)
            assert await pilot.click("#prepare-case")
            await pilot.pause()
            assert screen.worker is not None
            await screen.worker.wait()
            await pilot.pause()
            assert screen.prepared is None and not screen.busy
            assert screen.query_one("#prepare-open", Button).disabled
            assert not screen.query_one("#prepare-case", Button).disabled
            status = screen.query_one("#preparation-status", Static).content
            assert isinstance(status, Text)
            assert "manager unavailable" in status.plain
            assert "No fallback detector" in status.plain
            assert await pilot.click("#prepare-case")
            await pilot.pause()
            await screen.worker.wait()
            await pilot.pause()
            assert screen.prepared == prepared and len(calls) == 2
            assert not screen.query_one("#prepare-open", Button).disabled

    asyncio.run(exercise())
    assert {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    } == original


def test_prepared_result_is_verified_before_direct_open(
    prepared, tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "simlab.preparation_tui.prepare_password_spray_investigation",
        lambda *args: prepared,
    )

    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            screen = await open_preparation(app, pilot)
            assert await pilot.click("#prepare-case")
            await pilot.pause()
            assert screen.worker is not None
            await screen.worker.wait()
            await pilot.pause()
            (prepared.case.path / "SHA256SUMS").write_text("corrupt\n")
            assert await pilot.click("#prepare-open")
            await pilot.pause()
            investigation = app.screen
            assert isinstance(investigation, InvestigationScreen)
            assert investigation.investigation is None
            status = investigation.query_one("#case-picker-status", Static).content
            assert isinstance(status, Text) and "Cannot open case" in status.plain

    asyncio.run(exercise())


def test_missing_target_does_not_auto_open_a_different_saved_evaluation(
    prepared, tmp_path
):
    async def exercise():
        app = SimLabApp(PROJECT_ROOT, tmp_path)
        async with app.run_test(size=(150, 50)) as pilot:
            screen = InvestigationScreen(
                tmp_path,
                evaluation_path=prepared.evaluation_path.parent / "evaluation-missing",
            )
            await app.push_screen(screen)
            await pilot.pause()
            assert screen.investigation is None
            assert len(screen.options) == 1
            status = screen.query_one("#case-picker-status", Static).content
            assert isinstance(status, Text) and "could not be listed" in status.plain

    asyncio.run(exercise())

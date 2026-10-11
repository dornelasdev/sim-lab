import asyncio
from pathlib import Path

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Select, Static

from simlab.tui import GuideScreen, SimLabApp, WorkflowMode, WorkflowStage
from simlab.workflow import DefinitionStatus, run_generation_stage

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_PATH = PROJECT_ROOT / "environments" / "corp-lab.yaml"
ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication"
SPRAY_ROUTE_PATH = ROUTE_PATH / "password-spray.yaml"


@pytest.mark.parametrize("existing", [False, True])
def test_kerberos_workflow_explains_detection_coverage(tmp_path, existing) -> None:
    output_root = tmp_path / "outputs"
    route_path = ROUTE_PATH / "kerberos-logon-failure.yaml"
    generated = (
        run_generation_stage(ENVIRONMENT_PATH, route_path, output_root)
        if existing
        else None
    )

    async def exercise() -> None:
        app = SimLabApp(PROJECT_ROOT, output_root)
        async with app.run_test(size=(150, 50)) as pilot:
            if generated is not None:
                await pilot.click("#start-existing")
                await pilot.pause()
                app.query_one("#telemetry-select", Select).value = str(
                    generated.path.resolve()
                )
                await pilot.pause()
                await pilot.click("#inspect")
            else:
                await pilot.click("#start-new")
                await pilot.pause()
                await pilot.click("#environment-next")
                await pilot.pause()
                app.query_one("#route-select", Select).value = str(route_path.resolve())
                await pilot.pause()
                await pilot.click("#route-next")
                await pilot.pause()
                await pilot.click("#generate")
            await pilot.pause()

            assert app.inspection is not None
            assert app.inspection.overview.scenario_id == "failed-kerberos-domain-logon"
            assert app.query_one("#event-table", DataTable).row_count == 2
            assert app.selected_event is not None
            assert app.selected_event.event_id == 4771
            assert '<Data Name="Status">0x18</Data>' in app.selected_event.xml

            await pilot.click("#inspect-next")
            await pilot.pause()
            context = app.query_one("#detection-context", Static).content
            assert isinstance(context, Text)
            assert "Not assessed:" in context.plain
            assert "Kerberos activity is not assessed" in context.plain
            await pilot.click("#detect")
            await pilot.pause()
            findings = app.query_one("#findings", Static).content
            assert isinstance(findings, Text)
            assert "Findings: 0" in findings.plain
            assert "Not assessed:" in findings.plain
            assert app.analysis_complete is True
            assert app.query_one("#profile-select", Select).disabled is True

    asyncio.run(exercise())


def test_guides_new_simulation_through_context_and_outputs(tmp_path) -> None:
    async def exercise() -> None:
        output_root = tmp_path / "outputs"
        app = SimLabApp(PROJECT_ROOT, output_root)

        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-new")
            await pilot.pause()

            assert app.mode is WorkflowMode.NEW
            assert app.active_stage is WorkflowStage.ENVIRONMENT
            assert app.theme == "simlab-soc"
            assert app.query_one("#nav-environment", Button).has_class("nav-active")
            assert app.query_one("#nav-route", Button).disabled is True
            assert app.query_one("#nav-route", Button).has_class("nav-locked")

            await pilot.click("#environment-next")
            await pilot.pause()
            assert app.active_stage is WorkflowStage.ROUTE

            route = app.query_one("#route-select", Select)
            route.value = str(SPRAY_ROUTE_PATH.resolve())
            await pilot.pause()
            await pilot.click("#route-next")
            await pilot.pause()

            assert app.active_stage is WorkflowStage.ACQUIRE
            assert app.query_one("#generate", Button).disabled is False

            await pilot.click("#generate")
            await pilot.pause()

            assert app.active_stage is WorkflowStage.INSPECT
            assert app.inspection is not None
            assert app.inspection.overview.scenario_id == "internal-password-spray"
            assert app.query_one("#event-table", DataTable).row_count == 6
            assert app.selected_event is not None
            assert app.selected_event.xml.startswith("<?xml")
            assert app.query_one("#nav-detect", Button).disabled is False
            assert app.query_one("#nav-export", Button).disabled is True
            assert app.query_one("#nav-inspect", Button).has_class("nav-active")
            assert app.query_one("#nav-acquire", Button).has_class("nav-done")

            inspection = app.inspection
            await pilot.click("#workflow-guide")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            guide_content = app.screen.query_one("#guide-content", Static).content
            guide_text = (
                guide_content.plain
                if isinstance(guide_content, Text)
                else str(guide_content)
            )
            assert "Field origin labels" in guide_text
            assert "not fields a defender would receive" in guide_text
            await pilot.press("g")
            await pilot.pause()
            assert not isinstance(app.screen, GuideScreen)
            assert app.inspection is inspection
            assert app.active_stage is WorkflowStage.INSPECT

            await pilot.press("g")
            await pilot.pause()
            assert isinstance(app.screen, GuideScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, GuideScreen)

            comparison_content = app.query_one("#inspection-context", Static).content
            assert isinstance(comparison_content, Text)
            comparison = comparison_content.plain
            assert "Event 4776 on dc01: expected 3; match" in comparison
            assert "Event 4625 on fs01: expected 3; match" in comparison

            await pilot.click("#nav-route")
            await pilot.pause()
            assert app.query_one("#route-picker").display is False
            assert app.query_one("#route-select", Select).disabled is True
            await pilot.click("#route-next")
            await pilot.pause()
            assert app.active_stage is WorkflowStage.INSPECT

            await pilot.click("#inspect-next")
            await pilot.pause()
            detection_content = app.query_one("#detection-context", Static).content
            assert isinstance(detection_content, Text)
            detection_context = detection_content.plain
            assert "3 distinct users within 60s" in detection_context
            await pilot.click("#detect")
            await pilot.pause()

            assert app.analysis_complete is True
            assert app.query_one("#detect-next", Button).disabled is False
            assert app.query_one("#nav-export", Button).disabled is False
            assert app.query_one("#profile-picker").display is False
            assert app.query_one("#profile-select", Select).disabled is True
            assert app.query_one("#detect", Button).display is False
            assert app.query_one("#new-analysis", Button).display is True
            assert app.query_one("#findings").has_class("has-output")
            assert len(list((output_root / "analyses").glob("*/*/manifest.json"))) == 1

            telemetry_path = app.inspection.overview.path
            await pilot.click("#new-analysis")
            await pilot.pause()
            assert app.analysis_complete is False
            assert app.inspection.overview.path == telemetry_path
            assert app.query_one("#profile-picker").display is True
            assert app.query_one("#profile-select", Select).disabled is False
            assert app.query_one("#detect", Button).display is True
            assert app.query_one("#new-analysis", Button).display is False
            assert not app.query_one("#findings").has_class("has-output")

            await pilot.click("#detect")
            await pilot.pause()
            await pilot.click("#detect-next")
            await pilot.pause()
            await pilot.click("#export-wazuh")
            await pilot.pause()

            assert app.wazuh_export_complete is True
            assert app.query_one("#wazuh-result").has_class("has-output")
            assert len(list((output_root / "wazuh").glob("*/*/manifest.json"))) == 1

    asyncio.run(exercise())


def test_opens_existing_telemetry_with_recorded_definition_context(tmp_path) -> None:
    output_root = tmp_path / "outputs"
    generated = run_generation_stage(
        ENVIRONMENT_PATH,
        SPRAY_ROUTE_PATH,
        output_root,
    )

    async def exercise() -> None:
        app = SimLabApp(PROJECT_ROOT, output_root)

        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-existing")
            await pilot.pause()

            assert app.mode is WorkflowMode.EXISTING
            assert app.active_stage is WorkflowStage.ACQUIRE
            assert app.query_one("#nav-environment", Button).disabled is True

            telemetry = app.query_one("#telemetry-select", Select)
            telemetry.value = str(generated.path.resolve())
            await pilot.pause()
            await pilot.click("#inspect")
            await pilot.pause()

            assert app.active_stage is WorkflowStage.INSPECT
            assert app.inspection is not None
            assert app.definition_context is not None
            assert (
                app.definition_context.environment.status is DefinitionStatus.MATCHING
            )
            assert app.definition_context.scenario.status is DefinitionStatus.MATCHING
            assert app.query_one("#nav-environment", Button).disabled is False

            await pilot.click("#nav-environment")
            await pilot.pause()
            assert app.active_stage is WorkflowStage.ENVIRONMENT
            assert app.query_one("#environment-picker").display is False
            assert app.query_one("#environment-select", Select).disabled is True

            await pilot.click("#environment-next")
            await pilot.pause()
            assert app.active_stage is WorkflowStage.INSPECT

    asyncio.run(exercise())


def test_acquired_telemetry_requires_restart_to_change_simulation(tmp_path) -> None:
    async def exercise() -> None:
        output_root = tmp_path / "outputs"
        app = SimLabApp(PROJECT_ROOT, output_root)

        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.click("#start-new")
            await pilot.pause()
            await pilot.click("#environment-next")
            await pilot.pause()
            route = app.query_one("#route-select", Select)
            route.value = str(SPRAY_ROUTE_PATH.resolve())
            await pilot.pause()
            await pilot.click("#route-next")
            await pilot.pause()
            await pilot.click("#generate")
            await pilot.pause()

            assert app.inspection is not None
            telemetry_path = app.inspection.overview.path
            await pilot.click("#nav-route")
            await pilot.pause()
            assert app.query_one("#route-picker").display is False
            assert route.disabled is True

            await pilot.click("#nav-acquire")
            await pilot.pause()
            assert app.query_one("#generate", Button).display is False
            assert app.query_one("#restart-simulation", Button).display is True

            await pilot.click("#restart-simulation")
            await pilot.pause()

            assert app.inspection is None
            assert app.route_path is None
            assert app.analysis_complete is False
            assert app.wazuh_export_complete is False
            assert app.active_stage is WorkflowStage.ENVIRONMENT
            assert app.query_one("#environment-picker").display is True
            assert app.query_one("#environment-select", Select).disabled is False
            assert app.query_one("#nav-inspect", Button).disabled is True
            assert telemetry_path.exists()

    asyncio.run(exercise())

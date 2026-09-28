import asyncio
from pathlib import Path

from textual.widgets import Button, DataTable, Select

from simlab.tui import SimLabApp

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SPRAY_ROUTE_PATH = PROJECT_ROOT / "routes" / "ad-authentication" / "password-spray.yaml"


def test_guides_generation_inspection_detection_and_wazuh_export(tmp_path) -> None:
    async def exercise() -> None:
        output_root = tmp_path / "outputs"
        app = SimLabApp(PROJECT_ROOT, output_root)

        async with app.run_test(size=(150, 50)) as pilot:
            route = app.query_one("#route-select", Select)
            route.value = str(SPRAY_ROUTE_PATH.resolve())
            await pilot.pause()

            assert app.query_one("#generate", Button).disabled is False
            assert app.query_one("#detect", Button).disabled is True
            assert app.query_one("#export-wazuh", Button).disabled is True

            await pilot.click("#generate")
            await pilot.pause()

            assert app.inspection is not None
            assert app.inspection.overview.scenario_id == "internal-password-spray"
            assert app.query_one("#event-table", DataTable).row_count == 6
            assert app.selected_event is not None
            assert app.selected_event.xml.startswith("<?xml")
            assert app.query_one("#detect", Button).disabled is False
            assert app.query_one("#export-wazuh", Button).disabled is False

            await pilot.click("#detect")
            await pilot.pause()
            assert app.analysis_complete is True
            assert len(list((output_root / "analyses").glob("*/*/manifest.json"))) == 1

            await pilot.click("#export-wazuh")
            await pilot.pause()
            assert app.wazuh_export_complete is True
            assert len(list((output_root / "wazuh").glob("*/*/manifest.json"))) == 1

    asyncio.run(exercise())

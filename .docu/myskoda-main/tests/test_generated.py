"""Unit tests for generated fixtures."""

import re
from pathlib import Path

import pytest
from aioresponses import aioresponses

from myskoda.anonymize import VIN
from myskoda.const import BASE_URL_SKODA
from myskoda.models.fixtures import Fixture, FixtureReportGet
from myskoda.myskoda import MySkoda

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.mark.asyncio
async def test_report_get(
    report: FixtureReportGet, responses: aioresponses, myskoda: MySkoda
) -> None:
    # Check if the URL contains a query string
    if report.url and "?" in report.url:
        url_pattern = re.compile(rf"{BASE_URL_SKODA}/api{report.url.split('?')[0]}\?.*")
    else:
        url_pattern = re.compile(rf"{BASE_URL_SKODA}/api{report.url}")
    responses.get(url=url_pattern, body=report.raw)

    result = await myskoda.get_endpoint(VIN, report.endpoint, anonymize=True)
    result = result.result.to_dict()

    # Remove timestamp
    result["timestamp"] = None
    if (res := report.result) is not None:
        if "timestamp" in res:
            res["timestamp"] = None
        mr = res.get("maintenance_report")
        if mr:
            mr["timestamp"] = None
            result["maintenance_report"]["timestamp"] = None

    assert result == report.result


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    parameters = []

    for file in FIXTURES_DIR.glob("**/*.yaml"):
        text = file.read_text(encoding="utf-8")
        fixture = Fixture.from_yaml(text)
        if fixture.reports is None:
            continue
        for report in fixture.reports:
            if not report.success:
                continue
            parameters.append(report)

    metafunc.parametrize("report", parameters)

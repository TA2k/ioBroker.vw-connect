"""Tests for trip statistics models."""

import json
from pathlib import Path

from myskoda.models.trip_statistics import SingleTrips, TripStatistics

FIXTURES_DIR = Path(__file__).parent.joinpath("fixtures")


def test_parse_single_trips() -> None:
    """Test parsing SingleTrips from real-world fixture."""
    fixture_path = FIXTURES_DIR.joinpath("superb/single-trips-iV.json")
    json_data = fixture_path.read_text()

    parsed = SingleTrips.from_json(json_data)

    assert parsed is not None
    assert parsed.daily_trips is not None
    assert len(parsed.daily_trips) > 0

    raw_data = json.loads(json_data)
    assert parsed.daily_trips[0].date == raw_data["dailyTrips"][0]["date"]

    if parsed.daily_trips[0].trips:
        assert (
            parsed.daily_trips[0].trips[0].end_time
            == raw_data["dailyTrips"][0]["trips"][0]["endTime"]
        )


def test_parse_trip_statistics() -> None:
    """Test parsing TripStatistics from real-world fixture."""
    fixture_path = FIXTURES_DIR.joinpath("superb/trip-statistics-iV.json")
    json_data = fixture_path.read_text()

    parsed = TripStatistics.from_json(json_data)

    assert parsed is not None

    raw_data = json.loads(json_data)
    assert parsed.overall_mileage_in_km == raw_data.get("overallMileageInKm")
    assert parsed.overall_average_speed_in_kmph == raw_data.get("overallAverageSpeedInKmph")

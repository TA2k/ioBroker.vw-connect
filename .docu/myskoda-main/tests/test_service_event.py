"""Unit tests for myskoda.models.service_event.

This module partially repeats test_mqtt.py tests but is more isolated:
here we have unit tests for service_event module only.
"""

from pathlib import Path

import pytest

from myskoda.models.charging import ChargeMode, ChargingState
from myskoda.models.event import (
    BaseEvent,
    ServiceEvent,
    ServiceEventChangeSoc,
    ServiceEventChangeSocData,
    ServiceEventChargingError,
    ServiceEventData,
    ServiceEventDepartureErrorPlug,
    ServiceEventError,
    ServiceEventErrorData,
)

FIXTURES_DIR = Path(__file__).parent.joinpath("fixtures")


@pytest.fixture(name="service_events")
def load_service_events() -> list[tuple[str, str]]:
    """Load service_events fixture. Return topic, payload."""
    vin = "TMOCKAA0AA000000"
    user_id = "b8bc126c-ee36-402b-8723-2c1c3dff8dec"
    topic_base = f"{user_id}/{vin}/service-event/"
    file_base = FIXTURES_DIR / "events"
    return [
        (
            f"{topic_base}charging",
            (file_base / "service_event_charging_change_soc.json").read_text(),
        ),
        (
            f"{topic_base}charging",
            (file_base / "service_event_charging_charging_status_changed.json").read_text(),
        ),
        (
            f"{topic_base}charging",
            (file_base / "service_event_charging_charging_error.json").read_text(),
        ),
        (
            f"{topic_base}departure",
            (file_base / "service_event_departure_ready.json").read_text(),
        ),
        (
            f"{topic_base}departure",
            (file_base / "service_event_departure_status_changed.json").read_text(),
        ),
        (
            f"{topic_base}departure",
            (file_base / "service_event_departure_error_plug.json").read_text(),
        ),
    ]


def test_parse_service_events(service_events: list[str]) -> None:
    for service_event in service_events:
        topic, payload = service_event
        event = BaseEvent.from_mqtt_message(topic=topic, payload=payload)

        assert isinstance(event, ServiceEvent)
        if isinstance(event, ServiceEventChangeSoc):
            assert event.data == ServiceEventChangeSocData(
                charged_range=195,
                mode=ChargeMode.MANUAL,
                soc=50,
                state=ChargingState.CHARGING,
                time_to_finish=440,
                user_id="ad0d7945-4814-43d0-801f-change-soc",
                vin="TMBAXXXXXXXXXXXXX",
            )
        elif isinstance(event, ServiceEventChargingError):
            assert event.data == ServiceEventErrorData(
                user_id=f"ad0d7945-4814-43d0-801f-{event.name.value}",
                vin="TMBAXXXXXXXXXXXXX",
                error_code=ServiceEventError.STOPPED_DEVICE,
            )
        elif isinstance(event, ServiceEventDepartureErrorPlug):
            assert event.data == ServiceEventErrorData(
                user_id=f"ad0d7945-4814-43d0-801f-{event.name.value}",
                vin="TMBAXXXXXXXXXXXXX",
                error_code=ServiceEventError.CLIMA,
            )
        else:
            assert event.data == ServiceEventData(
                user_id=f"ad0d7945-4814-43d0-801f-{event.name.value}",
                vin="TMBAXXXXXXXXXXXXX",
            )

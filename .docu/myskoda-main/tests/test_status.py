"""Unit tests for myskoda.models.status."""

import json
from pathlib import Path

import pytest

from myskoda.models.status import DoorWindowState, Status

FIXTURES_DIR = Path(__file__).parent.joinpath("fixtures")


@pytest.fixture(name="vehicle_status")
def load_vehicle_status() -> dict:
    """Load vehicle-status fixture."""
    vehicle_status = (FIXTURES_DIR / "superb/vehicle-status-doors-closed.json").read_text()
    return json.loads(vehicle_status)


def _get_config_with_lightmode_onex_url(full_config: dict, onex_url: str) -> dict:
    full_config["renders"]["lightMode"]["oneX"] = onex_url
    return full_config


def test_door_window_states_all_closed_parsed_ok(vehicle_status: dict) -> None:
    """Test various door and window states."""
    test_json = _get_config_with_lightmode_onex_url(
        vehicle_status,
        "https://mysmob.api.connect.skoda-auto.cz/api/v2/vehicle-status/render?carType=LIMOUSINE&"
        "vehicleState=1-1-1-1-0-0-1-1-2"
        "&lastModifiedAt=1723053261&dimension=1x&theme=LIGHT",
    )
    status = Status.from_dict(test_json)
    assert status.left_front_door == DoorWindowState.CLOSED
    assert status.right_front_door == DoorWindowState.CLOSED
    assert status.left_back_door == DoorWindowState.CLOSED
    assert status.right_back_door == DoorWindowState.CLOSED


def test_door_window_states_doors_and_windows_opened_ok(vehicle_status: dict) -> None:
    """Test various door and window states."""
    test_json = _get_config_with_lightmode_onex_url(
        vehicle_status,
        "https://mysmob.api.connect.skoda-auto.cz/api/v2/vehicle-status/render?carType=LIMOUSINE&"
        "vehicleState=1-2-3-1-0-0-1-1-2"
        "&lastModifiedAt=1723053261&dimension=1x&theme=LIGHT",
    )
    status = Status.from_dict(test_json)
    assert status.left_front_door == DoorWindowState.CLOSED
    assert status.right_front_door == DoorWindowState.WINDOW_OPEN
    assert status.left_back_door == DoorWindowState.DOOR_OPEN
    assert status.right_back_door == DoorWindowState.CLOSED


def test_door_window_states_doors_with_windows_opened_ok(vehicle_status: dict) -> None:
    """Test various door and window states."""
    test_json = _get_config_with_lightmode_onex_url(
        vehicle_status,
        "https://mysmob.api.connect.skoda-auto.cz/api/v2/vehicle-status/render?carType=LIMOUSINE&"
        "vehicleState=1-2-3-4-0-0-1-1-2"
        "&lastModifiedAt=1723053261&dimension=1x&theme=LIGHT",
    )
    status = Status.from_dict(test_json)
    assert status.left_front_door == DoorWindowState.CLOSED
    assert status.right_front_door == DoorWindowState.WINDOW_OPEN
    assert status.left_back_door == DoorWindowState.DOOR_OPEN
    assert status.right_back_door == DoorWindowState.ALL_OPEN


def test_door_window_states_url_parsing_fails(vehicle_status: dict) -> None:
    """Test various door and window states."""
    test_json = _get_config_with_lightmode_onex_url(
        vehicle_status,
        r"htmob.api.connect.skoda-auto.cz/api\v2\vehicle-status/render+carType=LIMOUSINE&"
        "vehicleState=1-2-3-1-0-0-1-1-2&lastModifiedAt=1723053261&dimension=1x&theme=LIGHT",
    )
    status = Status.from_dict(test_json)
    assert status.left_front_door == DoorWindowState.UNKNOWN
    assert status.right_front_door == DoorWindowState.UNKNOWN
    assert status.left_back_door == DoorWindowState.UNKNOWN
    assert status.right_back_door == DoorWindowState.UNKNOWN


def test_door_window_states_no_query(vehicle_status: dict) -> None:
    """Test various door and window states."""
    test_json = _get_config_with_lightmode_onex_url(
        vehicle_status,
        "https://mysmob.api.connect.skoda-auto.cz/api/v2/vehicle-status/render?carType=LIMOUSINE&"
        "lastModifiedAt=1723053261&dimension=1x&theme=LIGHT",
    )
    status = Status.from_dict(test_json)
    assert status.left_front_door == DoorWindowState.UNKNOWN
    assert status.right_front_door == DoorWindowState.UNKNOWN
    assert status.left_back_door == DoorWindowState.UNKNOWN
    assert status.right_back_door == DoorWindowState.UNKNOWN


def test_door_window_states_query_has_nonint_values(vehicle_status: dict) -> None:
    """Test various door and window states."""
    test_json = _get_config_with_lightmode_onex_url(
        vehicle_status,
        "https://mysmob.api.connect.skoda-auto.cz/api/v2/vehicle-status/render?carType=LIMOUSINE&"
        "vehicleState=1-1-1-g-0-0-1-1-2"
        "&lastModifiedAt=1723053261&dimension=1x&theme=LIGHT",
    )
    status = Status.from_dict(test_json)
    assert status.left_front_door == DoorWindowState.CLOSED
    assert status.right_front_door == DoorWindowState.CLOSED
    assert status.left_back_door == DoorWindowState.CLOSED
    assert status.right_back_door == DoorWindowState.UNKNOWN


def test_door_window_states_query_has_illegal_value(vehicle_status: dict) -> None:
    """Test various door and window states."""
    test_json = _get_config_with_lightmode_onex_url(
        vehicle_status,
        "https://mysmob.api.connect.skoda-auto.cz/api/v2/vehicle-status/render?carType=LIMOUSINE&"
        "vehicleState=1-3-1-5-0-0-1-1-2"
        "&lastModifiedAt=1723053261&dimension=1x&theme=LIGHT",
    )
    status = Status.from_dict(test_json)
    assert status.left_front_door == DoorWindowState.CLOSED
    assert status.right_front_door == DoorWindowState.DOOR_OPEN
    assert status.left_back_door == DoorWindowState.CLOSED
    assert status.right_back_door == DoorWindowState.UNKNOWN

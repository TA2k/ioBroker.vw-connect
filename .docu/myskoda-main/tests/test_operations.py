"""Basic unit tests for operations."""

from unittest.mock import AsyncMock, patch

import pytest
from aioresponses import aioresponses

from myskoda.anonymize import ACCESS_TOKEN, LOCATION, USER_ID, VIN
from myskoda.const import BASE_URL_SKODA
from myskoda.models.air_conditioning import (
    AirConditioning,
    AirConditioningAtUnlock,
    AirConditioningWithoutExternalPower,
    HeaterSource,
    SeatHeating,
    TargetTemperature,
    WindowHeating,
)
from myskoda.models.auxiliary_heating import AuxiliaryConfig, AuxiliaryHeating, AuxiliaryStartMode
from myskoda.models.charging import ChargeMode
from myskoda.models.departure import DepartureInfo
from myskoda.myskoda import MySkoda

from .conftest import FIXTURES_DIR, FakeMqttClientWrapper, create_aiomqtt_message


@pytest.mark.asyncio
async def test_stop_air_conditioning(
    responses: aioresponses, myskoda: MySkoda, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/stop"
    responses.post(url=url)

    future = myskoda.stop_air_conditioning(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/start-stop-air-conditioning"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="stop-air-conditioning")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("temperature", "expected"), [(21.5, "21.5"), (23.2, "23.0"), (10.01, "10.0")]
)
async def test_start_air_conditioning(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    temperature: float,
    expected: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/start"
    responses.post(url=url)

    future = myskoda.start_air_conditioning(VIN, temperature)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/start-stop-air-conditioning"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="start-air-conditioning")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={
            "heaterSource": "ELECTRIC",
            "targetTemperature": {"temperatureValue": float(expected), "unitInCar": "CELSIUS"},
        },
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("temperature", "expected"), [(21.5, "21.5"), (23.2, "23.0"), (10.01, "10.0")]
)
async def test_set_target_temperature(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    temperature: float,
    expected: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/settings/target-temperature"
    responses.post(url=url)

    future = myskoda.set_target_temperature(VIN, temperature)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/set-target-temperature"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="set-air-conditioning-target-temperature")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"temperatureValue": float(expected), "unitInCar": "CELSIUS"},
    )


@pytest.mark.asyncio
async def test_start_window_heating(
    responses: aioresponses, myskoda: MySkoda, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/start-window-heating"
    responses.post(url=url)

    future = myskoda.start_window_heating(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/start-stop-window-heating"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="start-window-heating")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=None,
    )


@pytest.mark.asyncio
async def test_stop_window_heating(
    responses: aioresponses, myskoda: MySkoda, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/stop-window-heating"
    responses.post(url=url)

    future = myskoda.stop_window_heating(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/start-stop-window-heating"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="stop-window-heating")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [50, 70, 90, 100])
async def test_set_charge_limit(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    limit: int,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/charging/{VIN}/set-charge-limit"
    responses.put(url=url)

    future = myskoda.set_charge_limit(VIN, limit)

    topic = f"{USER_ID}/{VIN}/operation-request/charging/update-charge-limit"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="update-charge-limit")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="PUT",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"targetSOCInPercent": limit},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, 20, 30, 50])
async def test_set_minimum_charge_limit(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    limit: int,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/vehicle-automatization/{VIN}/departure/timers/settings"
    responses.post(url=url)

    future = myskoda.set_minimum_charge_limit(VIN, limit)

    topic = f"{USER_ID}/{VIN}/operation-request/departure/update-minimal-soc"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="update-minimal-soc")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"minimumBatteryStateOfChargeInPercent": limit},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("enabled", "expected"), [(True, "ACTIVATED"), (False, "DEACTIVATED")])
async def test_set_battery_care_mode(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    enabled: bool,
    expected: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/charging/{VIN}/set-care-mode"
    responses.put(url=url)

    future = myskoda.set_battery_care_mode(VIN, enabled)

    topic = f"{USER_ID}/{VIN}/operation-request/charging/update-care-mode"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="update-care-mode")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="PUT",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"chargingCareMode": expected},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("enabled", "expected"), [(True, "PERMANENT"), (False, "OFF")])
async def test_set_auto_unlock_plug(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    enabled: bool,
    expected: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/charging/{VIN}/set-auto-unlock-plug"
    responses.put(url=url)

    future = myskoda.set_auto_unlock_plug(VIN, enabled)

    topic = f"{USER_ID}/{VIN}/operation-request/charging/update-auto-unlock-plug"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="update-auto-unlock-plug")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="PUT",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"autoUnlockPlug": expected},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("reduced", "expected"), [(True, "REDUCED"), (False, "MAXIMUM")])
async def test_set_reduced_current_limit(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    reduced: bool,
    expected: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/charging/{VIN}/set-charging-current"
    responses.put(url=url)

    future = myskoda.set_reduced_current_limit(VIN, reduced)

    topic = f"{USER_ID}/{VIN}/operation-request/charging/update-charging-current"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="update-charging-current")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="PUT",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"chargingCurrent": expected},
    )


@pytest.mark.asyncio
async def test_start_charging(
    responses: aioresponses, myskoda: MySkoda, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/charging/{VIN}/start"
    responses.post(url=url)

    future = myskoda.start_charging(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/charging/start-stop-charging"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="start-charging")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=None,
    )


@pytest.mark.asyncio
async def test_stop_charging(
    responses: aioresponses, myskoda: MySkoda, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/charging/{VIN}/stop"
    responses.post(url=url)

    future = myskoda.stop_charging(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/charging/start-stop-charging"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="stop-charging")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=None,
    )


@pytest.mark.asyncio
async def test_wakeup(
    responses: aioresponses, myskoda: MySkoda, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/vehicle-wakeup/{VIN}?applyRequestLimiter=true"
    responses.post(url=url)

    future = myskoda.wakeup(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/vehicle-wakeup/wakeup"
    fake_mqtt_client_wrapper.set_messages([create_aiomqtt_message(topic=topic, operation="wakeup")])

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ChargeMode)
async def test_set_charge_mode(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    mode: ChargeMode,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/charging/{VIN}/set-charge-mode"
    responses.post(url=url)

    future = myskoda.set_charge_mode(VIN, mode)

    topic = f"{USER_ID}/{VIN}/operation-request/charging/update-charge-mode"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="update-charge-mode")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"chargeMode": mode.value},
    )


@pytest.mark.asyncio
async def test_honk_and_flash(
    responses: aioresponses,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    myskoda: MySkoda,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/vehicle-access/{VIN}/honk-and-flash"
    responses.post(url=url)

    lat = LOCATION["latitude"]
    lng = LOCATION["longitude"]

    responses.get(
        url=f"{BASE_URL_SKODA}/api/v1/maps/positions?vin={VIN}",
        body=(FIXTURES_DIR / "enyaq" / "positions.json").read_text(),
    )

    future = myskoda.honk_flash(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/vehicle-access/honk-and-flash"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="start-honk")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"mode": "HONK_AND_FLASH", "vehiclePosition": {"latitude": lat, "longitude": lng}},
    )


@pytest.mark.asyncio
async def test_flash(
    responses: aioresponses,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    myskoda: MySkoda,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/vehicle-access/{VIN}/honk-and-flash"
    responses.post(url=url)

    lat = LOCATION["latitude"]
    lng = LOCATION["longitude"]

    responses.get(
        url=f"{BASE_URL_SKODA}/api/v1/maps/positions?vin={VIN}",
        body=(FIXTURES_DIR / "enyaq" / "positions.json").read_text(),
    )

    future = myskoda.flash(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/vehicle-access/honk-and-flash"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="start-flash")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"mode": "FLASH", "vehiclePosition": {"latitude": lat, "longitude": lng}},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("spin", ["1234", "4321"])
async def test_lock(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    spin: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/vehicle-access/{VIN}/lock"
    responses.post(url=url)

    future = myskoda.lock(VIN, spin)

    topic = f"{USER_ID}/{VIN}/operation-request/vehicle-access/lock-vehicle"
    fake_mqtt_client_wrapper.set_messages([create_aiomqtt_message(topic=topic, operation="lock")])

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"currentSpin": spin},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("spin", ["1234", "4321"])
async def test_unlock(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    spin: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/vehicle-access/{VIN}/unlock"
    responses.post(url=url)

    future = myskoda.unlock(VIN, spin)

    topic = f"{USER_ID}/{VIN}/operation-request/vehicle-access/lock-vehicle"
    fake_mqtt_client_wrapper.set_messages([create_aiomqtt_message(topic=topic, operation="unlock")])

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"currentSpin": spin},
    )


@pytest.mark.asyncio
async def test_stop_auxiliary_heater(
    responses: aioresponses, myskoda: MySkoda, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/auxiliary-heating/stop"
    responses.post(url=url)

    future = myskoda.stop_auxiliary_heating(VIN)

    topic = f"{USER_ID}/{VIN}/operation-request/auxiliary-heating/start-stop-auxiliary-heating"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="stop-auxiliary-heating")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("spin", "config", "expected"),
    [
        ("1234", AuxiliaryConfig(TargetTemperature(temperature_value=22.3)), "22.5"),
        ("1234", AuxiliaryConfig(duration_in_seconds=600), "600"),
        ("1234", AuxiliaryConfig(start_mode=AuxiliaryStartMode.HEATING), "HEATING"),
        ("1234", AuxiliaryConfig(heater_source=HeaterSource.AUTOMATIC), "AUTOMATIC"),
    ],
)
async def test_start_auxiliary_heater(  # noqa: PLR0913
    responses: aioresponses,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    myskoda: MySkoda,
    spin: str,
    config: AuxiliaryConfig,
    expected: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/auxiliary-heating/start"
    responses.post(url=url)

    future = myskoda.start_auxiliary_heating(VIN, spin, config)

    topic = f"{USER_ID}/{VIN}/operation-request/auxiliary-heating/start-stop-auxiliary-heating"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="start-auxiliary-heating")]
    )

    json_data: dict[str, object] = {"spin": spin}
    if config is not None:
        if config.target_temperature is not None:
            json_data["targetTemperature"] = {
                "temperatureValue": float(expected),
                "unitInCar": "CELSIUS",
            }
        if config.duration_in_seconds is not None:
            json_data["durationInSeconds"] = int(expected)
        if config.heater_source is not None:
            json_data["heaterSource"] = expected
        if config.start_mode is not None:
            json_data["startMode"] = expected

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=json_data,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (
            AirConditioningWithoutExternalPower(
                air_conditioning_without_external_power_enabled=True
            ),
            True,
        ),
        (
            AirConditioningWithoutExternalPower(
                air_conditioning_without_external_power_enabled=False
            ),
            False,
        ),
    ],
)
async def test_set_ac_without_external_power(
    responses: aioresponses,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    myskoda: MySkoda,
    settings: AirConditioningWithoutExternalPower,
    expected: bool,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/settings/ac-without-external-power"
    responses.post(url=url)

    future = myskoda.set_ac_without_external_power(VIN, settings)

    topic = (
        f"{USER_ID}/{VIN}/operation-request/"
        "air-conditioning/set-air-conditioning-without-external-power"
    )
    fake_mqtt_client_wrapper.set_messages(
        [
            create_aiomqtt_message(
                topic=topic, operation="set-air-conditioning-without-external-power"
            )
        ]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"airConditioningWithoutExternalPowerEnabled": expected},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (AirConditioningAtUnlock(air_conditioning_at_unlock_enabled=True), True),
        (AirConditioningAtUnlock(air_conditioning_at_unlock_enabled=False), False),
    ],
)
async def test_set_ac_at_unlock(
    responses: aioresponses,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    myskoda: MySkoda,
    settings: AirConditioningAtUnlock,
    expected: bool,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/settings/ac-at-unlock"
    responses.post(url=url)

    future = myskoda.set_ac_at_unlock(VIN, settings)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/set-air-conditioning-at-unlock"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="set-air-conditioning-at-unlock")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"airConditioningAtUnlockEnabled": expected},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (WindowHeating(window_heating_enabled=True), True),
        (WindowHeating(window_heating_enabled=False), False),
    ],
)
async def test_set_windows_heating(
    responses: aioresponses,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    myskoda: MySkoda,
    settings: WindowHeating,
    expected: bool,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/settings/windows-heating"
    responses.post(url=url)

    future = myskoda.set_windows_heating(VIN, settings)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/windows-heating"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="windows-heating")]
    )

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"windowHeatingEnabled": expected},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (SeatHeating(front_left=True), True),
        (SeatHeating(front_right=True), True),
        (SeatHeating(front_left=False), False),
    ],
)
async def test_set_seats_heating(
    responses: aioresponses,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    myskoda: MySkoda,
    settings: SeatHeating,
    expected: bool,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/settings/seats-heating"
    responses.post(url=url)

    future = myskoda.set_seats_heating(VIN, settings)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/set-air-conditioning-seats-heating"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="set-air-conditioning-seats-heating")]
    )

    json_data: dict[str, object] = {}
    if settings is not None:
        if settings.front_left is not None:
            json_data["frontLeft"] = expected
        if settings.front_right is not None:
            json_data["frontRight"] = expected

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=json_data,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("timer_id", "enabled"), [(1, True), (2, False)])
async def test_set_departure_timer(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    timer_id: int,
    enabled: bool,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v1/vehicle-automatization/{VIN}/departure/timers"
    responses.post(url=url)

    departure_info_json = FIXTURES_DIR.joinpath("other/departure-timers.json").read_text()
    departure_info = DepartureInfo.from_json(departure_info_json)

    selected_timer = (
        next((timer for timer in departure_info.timers if timer.id == timer_id), None)
        if departure_info.timers
        else None
    )
    assert selected_timer is not None

    with patch("aiohttp.ClientSession._request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = AsyncMock(status=200)
        selected_timer.enabled = enabled
        future = myskoda.set_departure_timer(VIN, selected_timer)

        topic = f"{USER_ID}/{VIN}/operation-request/departure/update-departure-timers"
        fake_mqtt_client_wrapper.set_messages(
            [create_aiomqtt_message(topic=topic, operation="update-departure-timers")]
        )

        await future

        # Extract and assert the captured request body
        assert mock_request.called
        request_args, request_kwargs = mock_request.call_args
        body = request_kwargs.get("data") or request_kwargs.get("json")
        assert body is not None
        # check only the timer as deviceDateTime can't be verified
        assert body["timers"][0] == selected_timer.to_dict()


@pytest.mark.asyncio
@pytest.mark.parametrize(("timer_id", "enabled"), [(1, True), (2, False)])
async def test_set_ac_timer(
    responses: aioresponses,
    myskoda: MySkoda,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    timer_id: int,
    enabled: bool,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/timers"
    responses.post(url=url)

    ac_info_json = FIXTURES_DIR.joinpath("other/air-conditioning-idle.json").read_text()
    ac_info = AirConditioning.from_json(ac_info_json)

    selected_timer = (
        next((timer for timer in ac_info.timers if timer.id == timer_id), None)
        if ac_info.timers
        else None
    )
    assert selected_timer is not None

    selected_timer.enabled = enabled
    future = myskoda.set_ac_timer(VIN, selected_timer)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/set-air-conditioning-timers"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="set-air-conditioning-timers")]
    )

    json_data = {"timers": [selected_timer.to_dict(by_alias=True)]}

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=json_data,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("timer_id", "enabled", "spin"), [(1, True, "1234"), (2, False, "4321")])
async def test_set_auxiliary_heating_timer(  # noqa: PLR0913
    responses: aioresponses,
    fake_mqtt_client_wrapper: FakeMqttClientWrapper,
    myskoda: MySkoda,
    timer_id: int,
    enabled: bool,
    spin: str,
) -> None:
    url = f"{BASE_URL_SKODA}/api/v2/air-conditioning/{VIN}/auxiliary-heating/timers"
    responses.post(url=url)

    aux_info_json = FIXTURES_DIR.joinpath("other/auxiliary-heating-idle.json").read_text()
    aux_info = AuxiliaryHeating.from_json(aux_info_json)

    selected_timer = (
        next((timer for timer in aux_info.timers if timer.id == timer_id), None)
        if aux_info.timers
        else None
    )
    assert selected_timer is not None

    selected_timer.enabled = enabled
    future = myskoda.set_auxiliary_heating_timer(VIN, selected_timer, spin)

    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/set-air-conditioning-timers"
    fake_mqtt_client_wrapper.set_messages(
        [create_aiomqtt_message(topic=topic, operation="set-air-conditioning-timers")]
    )

    json_data = {"spin": spin, "timers": [selected_timer.to_dict(by_alias=True)]}

    await future
    responses.assert_called_with(
        url=url,
        method="POST",
        headers={"authorization": f"Bearer {ACCESS_TOKEN}"},
        json=json_data,
    )

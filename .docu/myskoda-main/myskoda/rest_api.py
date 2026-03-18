"""Contains API representation for the MySkoda REST API."""

import asyncio
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote

from aiohttp import ClientResponseError, ClientSession

from myskoda.anonymize import (
    anonymize_air_conditioning,
    anonymize_auxiliary_heating,
    anonymize_charging,
    anonymize_chargingprofiles,
    anonymize_departure_timers,
    anonymize_driving_range,
    anonymize_garage,
    anonymize_health,
    anonymize_info,
    anonymize_maintenance,
    anonymize_parking_position,
    anonymize_positions,
    anonymize_single_trip_statistics,
    anonymize_status,
    anonymize_trip_statistics,
    anonymize_url,
    anonymize_user,
    anonymize_vehicle_connection_status,
)

from .auth.authorization import Authorization
from .const import BASE_URL_SKODA, REQUEST_TIMEOUT_IN_SECONDS
from .models.air_conditioning import (
    AirConditioning,
    AirConditioningAtUnlock,
    AirConditioningTimer,
    AirConditioningWithoutExternalPower,
    SeatHeating,
    WindowHeating,
)
from .models.auxiliary_heating import AuxiliaryConfig, AuxiliaryHeating, AuxiliaryHeatingTimer
from .models.charging import ChargeMode, Charging
from .models.charging_history import ChargingHistory
from .models.chargingprofiles import ChargingProfiles
from .models.common import Vin
from .models.departure import DepartureInfo, DepartureTimer
from .models.driving_range import DrivingRange
from .models.garage import Garage
from .models.health import Health
from .models.info import Info
from .models.maintenance import Maintenance, MaintenanceReport
from .models.position import ParkingPositionV3, Position, Positions, PositionType
from .models.spin import Spin
from .models.status import Status
from .models.trip_statistics import SingleTrips, TripStatistics
from .models.user import User
from .models.vehicle_connection_status import VehicleConnectionStatus
from .utils import to_iso8601

_LOGGER = logging.getLogger(__name__)


@dataclass
class GetEndpointResult[T]:
    url: str
    raw: str
    result: T


class RestApi:
    """API hub class that can perform all calls to the MySkoda API."""

    session: ClientSession
    authorization: Authorization

    def __init__(self, session: ClientSession, authorization: Authorization) -> None:
        self.session = session
        self.authorization = authorization

    def process_json(
        self,
        data: str,
        anonymize: bool,
        anonymization_fn: Callable[[dict], dict],
    ) -> str:
        """Process the raw json returned by the API with some preprocessor logic."""
        if not anonymize:
            return data
        parsed = json.loads(data)
        anonymized = anonymization_fn(parsed)
        return json.dumps(anonymized)

    async def _make_request(self, url: str, method: str, json: dict | None = None) -> str:
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_IN_SECONDS):
                async with self.session.request(
                    method=method,
                    url=f"{BASE_URL_SKODA}/api{url}",
                    headers=await self._headers(),
                    json=json,
                ) as response:
                    await response.text()  # Ensure response is fully read
                    response.raise_for_status()
                    return await response.text()
        except TimeoutError:  # pragma: no cover
            _LOGGER.exception("Timeout while sending %s request to %s", method, url)
            raise
        except ClientResponseError as err:  # pragma: no cover
            _LOGGER.exception("Invalid status for %s request to %s: %d", method, url, err.status)
            raise

    async def _make_get_request[T](self, url: str) -> str:
        return await self._make_request(url=url, method="GET")

    async def _make_post_request(self, url: str, json: dict | None = None) -> str:
        return await self._make_request(url=url, method="POST", json=json)

    async def _make_put_request(self, url: str, json: dict | None = None) -> str:
        return await self._make_request(url=url, method="PUT", json=json)

    async def verify_spin(self, spin: str, anonymize: bool = False) -> GetEndpointResult[Spin]:
        """Verify SPIN."""
        url = "/v1/spin/verify"
        json_data = {"currentSpin": spin}
        raw = self.process_json(
            data=await self._make_post_request(url, json_data),
            anonymize=anonymize,
            anonymization_fn=anonymize_info,
        )
        result = self._deserialize(raw, Spin.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_info(self, vin: str, anonymize: bool = False) -> GetEndpointResult[Info]:
        """Retrieve information related to basic information for the specified vehicle."""
        url = f"/v2/garage/vehicles/{vin}?connectivityGenerations=MOD1&connectivityGenerations=MOD2&connectivityGenerations=MOD3&connectivityGenerations=MOD4"  # noqa: E501
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_info,
        )
        result = self._deserialize(raw, Info.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_charging(self, vin: str, anonymize: bool = False) -> GetEndpointResult[Charging]:
        """Retrieve information related to charging for the specified vehicle."""
        url = f"/v1/charging/{vin}"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_charging,
        )
        result = self._deserialize(raw, Charging.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_charging_profiles(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[ChargingProfiles]:
        """Retrieve information related to chargingprofiles for the specified vehicle."""
        url = f"/v1/charging/{vin}/profiles"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_chargingprofiles,
        )
        result = self._deserialize(raw, ChargingProfiles.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_charging_history(
        self,
        vin: str,
        cursor: datetime | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
    ) -> GetEndpointResult[ChargingHistory]:
        """Retrieve charging history information for the specified vehicle."""
        url = f"/v1/charging/{vin}/history?userTimezone=UTC&limit={limit}"
        url = self._apply_date_filter(url, cursor=cursor, start=start, end=end)

        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=False,
            anonymization_fn=anonymize_info,
        )
        result = self._deserialize(raw, ChargingHistory.from_json)
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_status(self, vin: str, anonymize: bool = False) -> GetEndpointResult[Status]:
        """Retrieve the current status for the specified vehicle."""
        url = f"/v2/vehicle-status/{vin}"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_status,
        )
        result = self._deserialize(raw, Status.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_air_conditioning(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[AirConditioning]:
        """Retrieve the current air conditioning status for the specified vehicle."""
        url = f"/v2/air-conditioning/{vin}"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_air_conditioning,
        )
        result = self._deserialize(raw, AirConditioning.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_auxiliary_heating(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[AuxiliaryHeating]:
        """Retrieve the current auxiliary heating status for the specified vehicle."""
        url = f"/v2/air-conditioning/{vin}/auxiliary-heating"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_auxiliary_heating,
        )
        result = self._deserialize(raw, AuxiliaryHeating.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_positions(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[Positions]:
        """Retrieve the current position for the specified vehicle."""
        url = f"/v1/maps/positions?vin={vin}"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_positions,
        )
        result = self._deserialize(raw, Positions.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_parking_position(
        self, vin: Vin, anonymize: bool = False
    ) -> GetEndpointResult[ParkingPositionV3]:
        """Retrieve the last known parking position for the specified vehicle."""
        url = f"/v3/maps/positions/vehicles/{vin}/parking"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_parking_position,
        )
        result = self._deserialize(raw, ParkingPositionV3.from_json)
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_driving_range(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[DrivingRange]:
        """Retrieve estimated driving range for combustion vehicles."""
        url = f"/v2/vehicle-status/{vin}/driving-range"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_driving_range,
        )
        result = self._deserialize(raw, DrivingRange.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_trip_statistics(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[TripStatistics]:
        """Retrieve statistics about past trips."""
        url = f"/v1/trip-statistics/{vin}?offsetType=week&offset=0&timezone=Europe%2FBerlin"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_trip_statistics,
        )
        result = self._deserialize(raw, TripStatistics.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_single_trip_statistics(
        self,
        vin: str,
        start: datetime | None = None,
        end: datetime | None = None,
        anonymize: bool = False,
    ) -> GetEndpointResult[SingleTrips]:
        """Retrieve detailed statistics about past trips.

        If you want to filter by date, provide both start and end date.
        """
        url = f"/v1/trip-statistics/{vin}/single-trips?timezone=Europe%2FBerlin"
        url = self._apply_date_filter(url, cursor=None, start=start, end=end)
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_single_trip_statistics,
        )
        result = self._deserialize(raw, SingleTrips.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_maintenance(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[Maintenance]:
        """Retrieve maintenance report, settings and history."""
        url = f"/v3/vehicle-maintenance/vehicles/{vin}"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_maintenance,
        )
        result = self._deserialize(raw, Maintenance.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_maintenance_report(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[MaintenanceReport]:
        """Retrieve just the maintenance report."""
        url = f"/v3/vehicle-maintenance/vehicles/{vin}/report"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_maintenance,
        )
        result = self._deserialize(raw, MaintenanceReport.from_json)
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_health(self, vin: str, anonymize: bool = False) -> GetEndpointResult[Health]:
        """Retrieve health information for the specified vehicle."""
        url = f"/v1/vehicle-health-report/warning-lights/{vin}"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_health,
        )
        result = self._deserialize(raw, Health.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_user(self, anonymize: bool = False) -> GetEndpointResult[User]:
        """Retrieve user information about logged in user."""
        url = "/v1/users"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_user,
        )
        result = self._deserialize(raw, User.from_json)
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_garage(self, anonymize: bool = False) -> GetEndpointResult[Garage]:
        """Fetch the garage (list of vehicles with limited info)."""
        url = "/v2/garage?connectivityGenerations=MOD1&connectivityGenerations=MOD2&connectivityGenerations=MOD3&connectivityGenerations=MOD4"  # noqa: E501
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_garage,
        )
        result = self._deserialize(raw, Garage.from_json)
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_departure_timers(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[DepartureInfo]:
        """Retrieve departure timers for the vehicle."""
        # Get the current local time with timezone
        now = datetime.now().astimezone()
        # Format the datetime string with timezone
        formatted_time = (
            now.strftime("%Y-%m-%dT%H:%M:%S.%f")
            + now.strftime("%z")[:3]
            + ":"
            + now.strftime("%z")[3:]
        )

        url = (
            f"/v1/vehicle-automatization/{vin}/departure/timers"
            f"?deviceDateTime={quote(formatted_time, safe='')}"
        )
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_departure_timers,
        )
        result = self._deserialize(raw, DepartureInfo.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def get_vehicle_connection_status(
        self, vin: str, anonymize: bool = False
    ) -> GetEndpointResult[VehicleConnectionStatus]:
        """Retrieve vehicle connection status."""
        url = f"/v2/connection-status/{vin}/readiness"
        raw = self.process_json(
            data=await self._make_get_request(url),
            anonymize=anonymize,
            anonymization_fn=anonymize_vehicle_connection_status,
        )
        result = self._deserialize(raw, VehicleConnectionStatus.from_json)
        url = anonymize_url(url) if anonymize else url
        return GetEndpointResult(url=url, raw=raw, result=result)

    async def _headers(self) -> dict[str, str]:
        return {"authorization": f"Bearer {await self.authorization.get_access_token()}"}

    async def stop_air_conditioning(self, vin: str) -> None:
        """Stop the air conditioning."""
        _LOGGER.debug("Stopping air conditioning for vehicle %s", vin)
        await self._make_post_request(url=f"/v2/air-conditioning/{vin}/stop")

    async def start_air_conditioning(self, vin: str, temperature: float) -> None:
        """Start the air conditioning."""
        round_temp = round(temperature * 2) / 2
        _LOGGER.debug(
            "Starting air conditioning for vehicle %s with temperature %.1f",
            vin,
            round_temp,
        )
        json_data = {
            "heaterSource": "ELECTRIC",
            "targetTemperature": {
                "temperatureValue": round_temp,
                "unitInCar": "CELSIUS",
            },
        }
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/start",
            json=json_data,
        )

    async def stop_ventilation(self, vin: str) -> None:
        """Start the ventilation."""
        _LOGGER.debug("Stopping ventilation for vehicle %s", vin)
        await self._make_post_request(url=f"/v2/air-conditioning/{vin}/active-ventilation/stop")

    async def start_ventilation(self, vin: str) -> None:
        """Start the ventilation."""
        _LOGGER.debug("Starting ventilation for vehicle %s", vin)
        await self._make_post_request(url=f"/v2/air-conditioning/{vin}/active-ventilation/start")

    async def stop_auxiliary_heating(self, vin: str) -> None:
        """Stop the auxiliary heating."""
        _LOGGER.debug("Stopping auxiliary heating for vehicle %s", vin)
        await self._make_post_request(url=f"/v2/air-conditioning/{vin}/auxiliary-heating/stop")

    async def start_auxiliary_heating(
        self, vin: str, spin: str, config: AuxiliaryConfig | None = None
    ) -> None:
        """Start the auxiliary heating."""
        _LOGGER.debug("Starting auxiliary heating for vehicle %s", vin)

        json_data: dict[str, object] = {"spin": spin}
        if config is not None:
            json_data = json_data | config.to_dict(omit_none=True, by_alias=True)

        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/auxiliary-heating/start",
            json=json_data,
        )

    async def set_ac_without_external_power(
        self, vin: str, settings: AirConditioningWithoutExternalPower
    ) -> None:
        """Enable or disable AC without external power."""
        _LOGGER.debug(
            "Setting AC without external power for vehicle %s to %r",
            vin,
            settings.air_conditioning_without_external_power_enabled,
        )
        json_data = settings.to_dict()
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/settings/ac-without-external-power",
            json=json_data,
        )

    async def set_ac_at_unlock(self, vin: str, settings: AirConditioningAtUnlock) -> None:
        """Enable or disable AC at unlock."""
        _LOGGER.debug(
            "Setting AC at at unlock for vehicle %s to %r",
            vin,
            settings.air_conditioning_at_unlock_enabled,
        )
        json_data = settings.to_dict()
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/settings/ac-at-unlock",
            json=json_data,
        )

    async def set_windows_heating(self, vin: str, settings: WindowHeating) -> None:
        """Enable or disable windows heating with AC."""
        _LOGGER.debug(
            "Setting windows heating with AC for vehicle %s to %r",
            vin,
            settings.window_heating_enabled,
        )
        json_data = settings.to_dict()
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/settings/windows-heating",
            json=json_data,
        )

    async def set_seats_heating(self, vin: str, settings: SeatHeating) -> None:
        """Enable or disable seats heating with AC."""
        json_data = settings.to_dict(omit_none=True, by_alias=True)
        _LOGGER.debug("Setting seats heating with AC for vehicle %s: %s", vin, json_data)
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/settings/seats-heating",
            json=json_data,
        )

    async def set_target_temperature(self, vin: str, temperature: float) -> None:
        """Set the air conditioning's target temperature in °C."""
        round_temp = round(temperature * 2) / 2
        _LOGGER.debug("Setting target temperature for vehicle %s to %.1f", vin, round_temp)
        json_data = {"temperatureValue": round_temp, "unitInCar": "CELSIUS"}
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/settings/target-temperature",
            json=json_data,
        )

    async def start_window_heating(self, vin: str) -> None:
        """Start heating both the front and rear window."""
        _LOGGER.debug("Starting window heating for vehicle %s", vin)
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/start-window-heating",
        )

    async def stop_window_heating(self, vin: str) -> None:
        """Stop heating both the front and rear window."""
        _LOGGER.debug("Stopping window heating for vehicle %s", vin)
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/stop-window-heating",
        )

    async def set_charge_limit(self, vin: str, limit: int) -> None:
        """Set the maximum charge limit in percent."""
        _LOGGER.debug("Setting charge limit for vehicle %s to %d", vin, limit)
        json_data = {"targetSOCInPercent": limit}
        await self._make_put_request(
            url=f"/v1/charging/{vin}/set-charge-limit",
            json=json_data,
        )

    async def set_minimum_charge_limit(self, vin: str, limit: int) -> None:
        """Set minimum battery SoC in percent for departure timer."""
        _LOGGER.debug(
            "Setting minimum SoC for departure timers for vehicle %s to %r",
            vin,
            limit,
        )

        json_data = {"minimumBatteryStateOfChargeInPercent": limit}
        await self._make_post_request(
            url=f"/v1/vehicle-automatization/{vin}/departure/timers/settings",
            json=json_data,
        )

    # TODO @dvx76: Maybe refactor for FBT001
    async def set_battery_care_mode(self, vin: str, enabled: bool) -> None:
        """Enable or disable the battery care mode."""
        _LOGGER.debug("Setting battery care mode for vehicle %s to %r", vin, enabled)
        json_data = {"chargingCareMode": "ACTIVATED" if enabled else "DEACTIVATED"}
        await self._make_put_request(
            url=f"/v1/charging/{vin}/set-care-mode",
            json=json_data,
        )

    # TODO @dvx76: Maybe refactor for FBT001
    async def set_auto_unlock_plug(self, vin: str, enabled: bool) -> None:
        """Enable or disable auto unlock plug when charged."""
        _LOGGER.debug("Setting auto unlock plug for vehicle %s to %r", vin, enabled)
        json_data = {"autoUnlockPlug": "PERMANENT" if enabled else "OFF"}
        await self._make_put_request(
            url=f"/v1/charging/{vin}/set-auto-unlock-plug",
            json=json_data,
        )

    # TODO @dvx76: Maybe refactor for FBT001
    async def set_reduced_current_limit(self, vin: str, reduced: bool) -> None:
        """Enable reducing the current limit by which the car is charged."""
        _LOGGER.debug("Setting reduced charging for vehicle %s to %r", vin, reduced)
        json_data = {"chargingCurrent": "REDUCED" if reduced else "MAXIMUM"}
        await self._make_put_request(
            url=f"/v1/charging/{vin}/set-charging-current",
            json=json_data,
        )

    async def start_charging(self, vin: str) -> None:
        """Start charging the car."""
        _LOGGER.debug("Starting charging for vehicle %s", vin)
        await self._make_post_request(
            url=f"/v1/charging/{vin}/start",
        )

    async def stop_charging(self, vin: str) -> None:
        """Stop charging the car."""
        _LOGGER.debug("Stopping charging of vehicle %s", vin)
        await self._make_post_request(
            url=f"/v1/charging/{vin}/stop",
        )

    async def wakeup(self, vin: str) -> None:
        """Wake the vehicle up. Can be called maximum three times a day."""
        _LOGGER.debug("Waking up vehicle %s", vin)
        await self._make_post_request(
            url=f"/v1/vehicle-wakeup/{vin}?applyRequestLimiter=true",
        )

    async def set_charge_mode(self, vin: str, mode: ChargeMode) -> None:
        """Wake the vehicle up. Can be called maximum three times a day."""
        _LOGGER.debug("Changing charging mode of vehicle %s to %s", vin, mode)
        json_data = {"chargeMode": mode.value}
        await self._make_post_request(
            url=f"/v1/charging/{vin}/set-charge-mode",
            json=json_data,
        )

    async def lock(self, vin: str, spin: str) -> None:
        """Lock the vehicle."""
        _LOGGER.debug("Locking vehicle %s", vin)
        json_data = {"currentSpin": spin}
        await self._make_post_request(
            url=f"/v1/vehicle-access/{vin}/lock",
            json=json_data,
        )

    async def unlock(self, vin: str, spin: str) -> None:
        """Unlock the vehicle."""
        _LOGGER.debug("Unlocking vehicle %s", vin)
        json_data = {"currentSpin": spin}
        await self._make_post_request(
            url=f"/v1/vehicle-access/{vin}/unlock",
            json=json_data,
        )

    # TODO @dvx76: Maybe refactor for FBT001
    async def honk_flash(
        self,
        vin: str,
        positions: list[Position],
    ) -> None:
        """Emit Honk and flash."""
        position = next(pos for pos in positions if pos.type == PositionType.VEHICLE)
        # TODO @webspider: Make this a proper class
        json_data = {
            "mode": "HONK_AND_FLASH",
            "vehiclePosition": {
                "latitude": position.gps_coordinates.latitude,
                "longitude": position.gps_coordinates.longitude,
            },
        }
        await self._make_post_request(
            url=f"/v1/vehicle-access/{vin}/honk-and-flash", json=json_data
        )

    async def flash(
        self,
        vin: str,
        positions: list[Position],
    ) -> None:
        """Emit flash."""
        position = next(pos for pos in positions if pos.type == PositionType.VEHICLE)
        # TODO @webspider: Make this a proper class
        json_data = {
            "mode": "FLASH",
            "vehiclePosition": {
                "latitude": position.gps_coordinates.latitude,
                "longitude": position.gps_coordinates.longitude,
            },
        }
        await self._make_post_request(
            url=f"/v1/vehicle-access/{vin}/honk-and-flash", json=json_data
        )

    async def set_departure_timer(self, vin: str, timer: DepartureTimer) -> None:
        """Set departure timer."""
        _LOGGER.debug(
            "Setting departure timer #%i for vehicle %s to %r", timer.id, vin, timer.enabled
        )

        now = datetime.now(UTC)
        datetime_str = now.isoformat()

        json_data = {"deviceDateTime": datetime_str, "timers": [timer.to_dict()]}
        await self._make_post_request(
            url=f"/v1/vehicle-automatization/{vin}/departure/timers",
            json=json_data,
        )

    async def set_ac_timer(self, vin: str, timer: AirConditioningTimer) -> None:
        """Set air-conditioning timer."""
        _LOGGER.debug(
            "Setting air-conditioning timer #%i for vehicle %s to %r", timer.id, vin, timer.enabled
        )

        json_data = {"timers": [timer.to_dict(by_alias=True)]}
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/timers",
            json=json_data,
        )

    async def set_auxiliary_heating_timer(
        self, vin: str, timer: AuxiliaryHeatingTimer, spin: str
    ) -> None:
        """Set auxiliary heating timer."""
        _LOGGER.debug(
            "Setting auxiliary heating timer #%i for vehicle %s to %r", timer.id, vin, timer.enabled
        )

        json_data = {"spin": spin, "timers": [timer.to_dict(by_alias=True)]}
        await self._make_post_request(
            url=f"/v2/air-conditioning/{vin}/auxiliary-heating/timers",
            json=json_data,
        )

    def _deserialize[T](self, text: str, deserialize: Callable[[str], T]) -> T:  # pragma: no cover
        try:
            data = deserialize(text)
        except Exception:
            _LOGGER.exception("Failed to deserialize data: %s", text)
            raise
        else:
            return data

    def _apply_date_filter(
        self,
        url: str,
        cursor: datetime | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> str:
        """Apply date filter to URL."""
        if cursor:
            url += f"&cursor={to_iso8601(cursor)}"
        elif start or end:
            if start:
                url += f"&from={to_iso8601(start)}"
            if end:
                url += f"&to={to_iso8601(end)}"
        return url

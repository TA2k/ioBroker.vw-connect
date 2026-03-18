"""Main entry point for the MySkoda library.

This class provides all methods to operate on the API and MQTT broker.

Example:
    async with aiohttp.ClientSession() as client:
        myskoda = MySkoda(session)
        await myskoda.connect("username", "password")
        for vin in await myskoda.list_vehicle_vins():
            print(vin)

All get_ methods will always fetch new data from the API and return that.

All refresh_ methods are debounced or otherwise rate limited. They (eventually) update local
attributes and don't return anything. Instead they trigger callbacks which clients can register
for using the subscribe_updates method.

MQTT event callbacks can also be subscribed for using the subscribe_events method.

"""

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from ssl import SSLContext
from traceback import format_exc
from types import SimpleNamespace
from typing import Any

from aiohttp import ClientSession, TraceConfig, TraceRequestEndParams

from myskoda.anonymize import anonymize_url
from myskoda.models.fixtures import (
    Endpoint,
    Fixture,
    FixtureReportGet,
    FixtureReportType,
    FixtureVehicle,
    create_fixture_vehicle,
)

from .__version__ import __version__ as version
from .auth.authorization import Authorization
from .const import (
    BASE_URL_SKODA,
    CACHE_USER_ENDPOINT_IN_HOURS,
    CACHE_VEHICLE_HEALTH_IN_HOURS,
    CLIENT_ID,
    MQTT_OPERATION_TIMEOUT,
    OPERATION_REFRESH_DELAY_SECONDS,
    REDIRECT_URI,
)
from .models.air_conditioning import (
    AirConditioning,
    AirConditioningAtUnlock,
    AirConditioningTimer,
    AirConditioningWithoutExternalPower,
    SeatHeating,
    WindowHeating,
)
from .models.auxiliary_heating import (
    AuxiliaryConfig,
    AuxiliaryHeating,
    AuxiliaryHeatingTimer,
)
from .models.charging import ChargeMode, Charging, ChargingStatus
from .models.charging_history import ChargingHistory, ChargingSession
from .models.chargingprofiles import ChargingProfiles
from .models.common import Vin
from .models.departure import DepartureInfo, DepartureTimer
from .models.driving_range import DrivingRange, EngineType
from .models.event import (
    BaseEvent,
    OperationEvent,
    OperationName,
    OperationStatus,
    ServiceEventAccess,
    ServiceEventAirConditioning,
    ServiceEventChangeSoc,
    ServiceEventChangeSocData,
    ServiceEventCharging,
    ServiceEventDeparture,
    ServiceEventOdometer,
)
from .models.health import Health
from .models.info import CapabilityId, Info
from .models.maintenance import Maintenance, MaintenanceReport
from .models.position import ParkingPositionV3, Positions
from .models.spin import Spin
from .models.status import Status
from .models.trip_statistics import SingleTrips, TripStatistics
from .models.user import User
from .models.vehicle_connection_status import VehicleConnectionStatus
from .mqtt import MySkodaMqttClient
from .rest_api import GetEndpointResult, RestApi
from .utils import async_debounce
from .vehicle import Vehicle

_LOGGER = logging.getLogger(__name__)

background_tasks = set()


class MqttDisabledError(Exception):
    """MQTT was not enabled."""


class UnsupportedEndpointError(Exception):
    """Endpoint not implemented."""


class UnknownVinError(Exception):  # pragma: no cover
    """Requested Vin not found."""

    def __init__(self, vin: str) -> None:
        super().__init__(f"Vehicle with VIN {vin} not found")


async def trace_response(
    _session: ClientSession,
    _trace_config_ctx: SimpleNamespace,
    params: TraceRequestEndParams,
) -> None:
    """Log response details. Used in aiohttp.TraceConfig."""
    resp_text = await params.response.text()
    _LOGGER.debug(
        "Trace: %s %s - response: %s (%s bytes) %s",
        params.method,
        str(params.url)[:60],
        params.response.status,
        params.response.content_length,
        resp_text[:5000],
    )


TRACE_CONFIG = TraceConfig()
TRACE_CONFIG.on_request_end.append(trace_response)


class MySkodaAuthorization(Authorization):
    client_id: str = CLIENT_ID  #  pyright: ignore[reportIncompatibleMethodOverride]
    redirect_uri: str = REDIRECT_URI  #  pyright: ignore[reportIncompatibleMethodOverride]
    base_url: str = BASE_URL_SKODA  #  pyright: ignore[reportIncompatibleMethodOverride]


class MySkoda:
    session: ClientSession
    rest_api: RestApi
    mqtt: MySkodaMqttClient | None = None
    authorization: MySkodaAuthorization
    ssl_context: SSLContext | None = None
    user: User | None = None
    _vehicles: dict[Vin, Vehicle]
    _callbacks: dict[Vin, list[Callable[[], Coroutine[Any, Any, None]]]]

    def __init__(
        self,
        session: ClientSession,
        ssl_context: SSLContext | None = None,
        mqtt_enabled: bool = True,
    ) -> None:
        self._callbacks = defaultdict(list)
        self._vehicles = {}
        self.session = session
        self.authorization = MySkodaAuthorization(session)
        self.rest_api = RestApi(self.session, self.authorization)
        self.ssl_context = ssl_context
        if mqtt_enabled:
            self.mqtt = self._create_mqtt_client()

    async def enable_mqtt(self) -> None:
        """If MQTT was not enabled when initializing MySkoda, enable it manually and connect."""
        if self.mqtt is not None:
            return
        self.mqtt = self._create_mqtt_client()
        self.user = await self.get_user()
        vehicles = await self.list_vehicle_vins()
        await self.mqtt.connect(self.user.id, vehicles)

    async def connect(self, email: str, password: str) -> None:
        """Authenticate on the rest api and connect to the MQTT broker."""
        await self.authorization.authorize(email, password)
        _LOGGER.debug("IDK Authorization was successful.")

        if self.mqtt:
            user = await self.get_user()
            vehicles = await self.list_vehicle_vins()
            await self.mqtt.connect(user.id, vehicles)
        _LOGGER.info("MySkoda connection ready.")

    async def connect_with_refresh_token(self, refresh_token: str) -> None:
        """Authenticate using an existing OpenID refresh token and connect MQTT."""
        await self.authorization.authorize_refresh_token(refresh_token)
        _LOGGER.debug("IDK Authorization via refresh token was successful.")

        if self.mqtt:
            user = await self.get_user()
            vehicles = await self.list_vehicle_vins()
            await self.mqtt.connect(user.id, vehicles)
        _LOGGER.info("MySkoda connection ready.")

    async def disconnect(self) -> None:
        """Disconnect from the MQTT broker."""
        if self.mqtt:
            await self.mqtt.disconnect()

    def subscribe_events(self, callback: Callable[[BaseEvent], Coroutine[Any, Any, None]]) -> None:
        """Listen for events emitted by MySkoda's MQTT broker."""
        if self.mqtt is None:
            raise MqttDisabledError
        self.mqtt.subscribe(callback=callback)

    def subscribe(self, callback: Callable[[BaseEvent], Coroutine[Any, Any, None]]) -> None:
        """See subscribe_events. For backwards compatibility."""
        _LOGGER.warning(
            "The subscribe() method is deprecated and will be removed, use subscribe_events"
        )
        self.subscribe_events(callback=callback)

    def subscribe_updates(
        self, vin: Vin, callback: Callable[[], Coroutine[Any, Any, None]]
    ) -> None:
        """Subscribe a callback function to be called when Vehicle data is updated."""
        self._callbacks[vin].append(callback)

    async def verify_spin(self, spin: str, anonymize: bool = False) -> Spin:
        """Verify S-PIN."""
        return (await self.rest_api.verify_spin(spin, anonymize=anonymize)).result

    async def list_vehicle_vins(self) -> list[str]:
        """List all vehicles by their vins."""
        garage = (await self.rest_api.get_garage()).result
        if garage.vehicles is None:
            return []
        return [vehicle.vin for vehicle in garage.vehicles]

    def vehicle(self, vin: Vin) -> Vehicle:
        """Return the currently cached vehicle."""
        if vin in self._vehicles:
            return self._vehicles[vin]
        raise UnknownVinError(vin)

    async def get_vehicle(
        self, vin: Vin, excluded_capabilities: list[CapabilityId] | None = None
    ) -> Vehicle:
        """Load and return a full vehicle based on its capabilities."""
        capabilities = [
            CapabilityId.AIR_CONDITIONING,
            CapabilityId.AUXILIARY_HEATING,
            CapabilityId.CHARGING,
            CapabilityId.PARKING_POSITION,
            CapabilityId.STATE,
            CapabilityId.TRIP_STATISTICS,
            CapabilityId.VEHICLE_HEALTH_INSPECTION,
            CapabilityId.DEPARTURE_TIMERS,
            CapabilityId.READINESS,
        ]

        if excluded_capabilities:
            capabilities = [c for c in capabilities if c not in excluded_capabilities]

        return await self.get_partial_vehicle(vin, capabilities)

    async def get_partial_vehicle(self, vin: Vin, capabilities: list[CapabilityId]) -> Vehicle:
        """Load and return a partial vehicle, based on list of capabilities."""
        info = await self.get_info(vin)
        maintenance = await self.get_maintenance(vin)

        if vin in self._vehicles:
            self._vehicles[vin].info = info
            self._vehicles[vin].maintenance = maintenance
        else:
            self._vehicles[vin] = Vehicle(info=info, maintenance=maintenance)

        for capa in capabilities:
            if info.is_capability_available(capa):
                await self._request_capability_data(vin, capa)

        return self.vehicle(vin)

    async def get_auth_token(self) -> str:
        """Retrieve the main access token for the IDK session."""
        return await self.rest_api.authorization.get_access_token()

    async def get_refresh_token(self) -> str:
        """Retrieve the refresh token for the IDK session."""
        return await self.rest_api.authorization.get_refresh_token()

    async def get_user(self, anonymize: bool = False) -> User:
        """Retrieve user information about logged in user."""
        return (await self.rest_api.get_user(anonymize=anonymize)).result

    async def get_info(self, vin: Vin, anonymize: bool = False) -> Info:
        """Retrieve the basic vehicle information for the specified vehicle."""
        return (await self.rest_api.get_info(vin, anonymize=anonymize)).result

    async def get_charging(self, vin: Vin, anonymize: bool = False) -> Charging:
        """Retrieve information related to charging for the specified vehicle."""
        return (await self.rest_api.get_charging(vin, anonymize=anonymize)).result

    async def get_charging_profiles(self, vin: Vin, anonymize: bool = False) -> ChargingProfiles:
        """Retrieve information related to charging profiles for the specified vehicle."""
        return (await self.rest_api.get_charging_profiles(vin, anonymize=anonymize)).result

    async def get_charging_history(
        self,
        vin: Vin,
        cursor: datetime | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
    ) -> ChargingHistory:
        """Retrieve the charging history of the specified vehicle."""
        return (await self.rest_api.get_charging_history(vin, cursor, start, end, limit)).result

    async def get_all_charging_sessions(
        self, vin: Vin, start: datetime | None = None, end: datetime | None = None
    ) -> list[ChargingSession]:
        """Retrieve all sessions for a timeperiod."""

        def extract_sessions(history: ChargingHistory) -> list[ChargingSession]:
            if history.periods:
                return [session for period in history.periods for session in period.sessions]
            return []

        request_limit: int = 50
        charging_history = await self.rest_api.get_charging_history(
            vin, start, end, limit=request_limit
        )
        sessions = extract_sessions(charging_history.result)
        cursor = charging_history.result.next_cursor

        total_sessions = sessions.copy()

        while (len(sessions) == request_limit) and cursor:
            charging_history = await self.rest_api.get_charging_history(
                vin, cursor, limit=request_limit
            )
            sessions = extract_sessions(charging_history.result)
            total_sessions.extend(sessions)
            cursor = charging_history.result.next_cursor

        return total_sessions

    async def get_status(self, vin: Vin, anonymize: bool = False) -> Status:
        """Retrieve the current status for the specified vehicle."""
        return (await self.rest_api.get_status(vin, anonymize=anonymize)).result

    async def get_air_conditioning(self, vin: Vin, anonymize: bool = False) -> AirConditioning:
        """Retrieve the current air conditioning status for the specified vehicle."""
        return (await self.rest_api.get_air_conditioning(vin, anonymize=anonymize)).result

    async def get_auxiliary_heating(self, vin: Vin, anonymize: bool = False) -> AuxiliaryHeating:
        """Retrieve the current auxiliary heating status for the specified vehicle."""
        return (await self.rest_api.get_auxiliary_heating(vin, anonymize=anonymize)).result

    async def get_positions(self, vin: Vin, anonymize: bool = False) -> Positions:
        """Retrieve the current position for the specified vehicle."""
        return (await self.rest_api.get_positions(vin, anonymize=anonymize)).result

    async def get_parking_position(self, vin: Vin, anonymize: bool = False) -> ParkingPositionV3:
        """Retrieve last known parking positions for the vehicle."""
        return (await self.rest_api.get_parking_position(vin, anonymize=anonymize)).result

    async def get_driving_range(self, vin: Vin, anonymize: bool = False) -> DrivingRange:
        """Retrieve estimated driving range for combustion vehicles."""
        return (await self.rest_api.get_driving_range(vin, anonymize=anonymize)).result

    async def get_single_trip_statistics(
        self,
        vin: Vin,
        start: datetime | None = None,
        end: datetime | None = None,
        anonymize: bool = False,
    ) -> SingleTrips:
        """Retrieve detailed statistics about past trips.

        If you want to filter by date, provide both start and end date.
        """
        return (
            await self.rest_api.get_single_trip_statistics(
                vin, start=start, end=end, anonymize=anonymize
            )
        ).result

    async def get_trip_statistics(self, vin: Vin, anonymize: bool = False) -> TripStatistics:
        """Retrieve statistics about past trips."""
        return (await self.rest_api.get_trip_statistics(vin, anonymize=anonymize)).result

    async def get_maintenance(self, vin: Vin, anonymize: bool = False) -> Maintenance:
        """Retrieve maintenance report, settings and history."""
        return (await self.rest_api.get_maintenance(vin, anonymize=anonymize)).result

    async def get_maintenance_report(self, vin: Vin, anonymize: bool = False) -> MaintenanceReport:
        """Retrieve maintenance report only."""
        return (await self.rest_api.get_maintenance_report(vin, anonymize=anonymize)).result

    async def get_health(self, vin: Vin, anonymize: bool = False) -> Health:
        """Retrieve health information for the specified vehicle."""
        return (await self.rest_api.get_health(vin, anonymize=anonymize)).result

    async def get_departure_timers(self, vin: Vin, anonymize: bool = False) -> DepartureInfo:
        """Retrieve departure timers for the specified vehicle."""
        return (await self.rest_api.get_departure_timers(vin, anonymize=anonymize)).result

    async def get_connection_status(
        self, vin: Vin, anonymize: bool = False
    ) -> VehicleConnectionStatus:
        """Retrieve vehicle connection status for the specified vehicle."""
        return (await self.rest_api.get_vehicle_connection_status(vin, anonymize=anonymize)).result

    async def start_charging(self, vin: Vin) -> None:
        """Start charging the car."""
        future = self._wait_for_operation(OperationName.START_CHARGING)
        await self.rest_api.start_charging(vin)
        await future

    async def stop_charging(self, vin: Vin) -> None:
        """Stop the car from charging."""
        future = self._wait_for_operation(OperationName.STOP_CHARGING)
        await self.rest_api.stop_charging(vin)
        await future

    async def set_charge_mode(self, vin: Vin, mode: ChargeMode) -> None:
        """Set the charge mode."""
        future = self._wait_for_operation(OperationName.UPDATE_CHARGE_MODE)
        await self.rest_api.set_charge_mode(vin, mode=mode)
        await future

    async def honk_flash(self, vin: Vin) -> None:
        """Honk and flash."""
        future = self._wait_for_operation(OperationName.START_HONK)
        await self.rest_api.honk_flash(vin, (await self.get_positions(vin)).positions)
        await future

    async def flash(self, vin: Vin) -> None:
        """Flash lights."""
        future = self._wait_for_operation(OperationName.START_FLASH)
        await self.rest_api.flash(vin, (await self.get_positions(vin)).positions)
        await future

    async def wakeup(self, vin: Vin) -> None:
        """Wake the vehicle up. Can be called maximum three times a day."""
        future = self._wait_for_operation(OperationName.WAKEUP)
        await self.rest_api.wakeup(vin)
        await future

    async def set_reduced_current_limit(self, vin: Vin, reduced: bool) -> None:
        """Enable reducing the current limit by which the car is charged."""
        future = self._wait_for_operation(OperationName.UPDATE_CHARGING_CURRENT)
        await self.rest_api.set_reduced_current_limit(vin, reduced=reduced)
        await future

    async def set_battery_care_mode(self, vin: Vin, enabled: bool) -> None:
        """Enable or disable the battery care mode."""
        future = self._wait_for_operation(OperationName.UPDATE_CARE_MODE)
        await self.rest_api.set_battery_care_mode(vin, enabled)
        await future

    async def set_auto_unlock_plug(self, vin: Vin, enabled: bool) -> None:
        """Enable or disable auto unlock plug when charged."""
        future = self._wait_for_operation(OperationName.UPDATE_AUTO_UNLOCK_PLUG)
        await self.rest_api.set_auto_unlock_plug(vin, enabled)
        await future

    async def set_charge_limit(self, vin: Vin, limit: int) -> None:
        """Set the maximum charge limit in percent."""
        future = self._wait_for_operation(OperationName.UPDATE_CHARGE_LIMIT)
        await self.rest_api.set_charge_limit(vin, limit)
        await future

    async def set_minimum_charge_limit(self, vin: Vin, limit: int) -> None:
        """Set minimum battery SoC in percent for departure timer."""
        future = self._wait_for_operation(OperationName.UPDATE_MINIMAL_SOC)
        await self.rest_api.set_minimum_charge_limit(vin, limit)
        await future

    async def stop_window_heating(self, vin: Vin) -> None:
        """Stop heating both the front and rear window."""
        future = self._wait_for_operation(OperationName.STOP_WINDOW_HEATING)
        await self.rest_api.stop_window_heating(vin)
        await future

    async def start_window_heating(self, vin: Vin) -> None:
        """Start heating both the front and rear window."""
        future = self._wait_for_operation(OperationName.START_WINDOW_HEATING)
        await self.rest_api.start_window_heating(vin)
        await future

    async def set_ac_without_external_power(
        self, vin: Vin, settings: AirConditioningWithoutExternalPower
    ) -> None:
        """Enable or disable AC without external power."""
        future = self._wait_for_operation(OperationName.SET_AIR_CONDITIONING_WITHOUT_EXTERNAL_POWER)
        await self.rest_api.set_ac_without_external_power(vin, settings)
        await future

    async def set_ac_at_unlock(self, vin: Vin, settings: AirConditioningAtUnlock) -> None:
        """Enable or disable AC at unlock."""
        future = self._wait_for_operation(OperationName.SET_AIR_CONDITIONING_AT_UNLOCK)
        await self.rest_api.set_ac_at_unlock(vin, settings)
        await future

    async def set_windows_heating(self, vin: Vin, settings: WindowHeating) -> None:
        """Enable or disable windows heating with AC."""
        future = self._wait_for_operation(OperationName.WINDOWS_HEATING)
        await self.rest_api.set_windows_heating(vin, settings)
        await future

    async def set_seats_heating(self, vin: Vin, settings: SeatHeating) -> None:
        """Enable or disable seats heating with AC."""
        future = self._wait_for_operation(OperationName.SET_AIR_CONDITIONING_SEATS_HEATING)
        await self.rest_api.set_seats_heating(vin, settings)
        await future

    async def set_target_temperature(self, vin: Vin, temperature: float) -> None:
        """Set the air conditioning's target temperature in °C."""
        future = self._wait_for_operation(OperationName.SET_AIR_CONDITIONING_TARGET_TEMPERATURE)
        await self.rest_api.set_target_temperature(vin, temperature)
        await future

    async def start_air_conditioning(self, vin: Vin, temperature: float) -> None:
        """Start the air conditioning with the provided target temperature in °C."""
        future = self._wait_for_operation(OperationName.START_AIR_CONDITIONING)
        await self.rest_api.start_air_conditioning(vin, temperature)
        await future

    async def stop_air_conditioning(self, vin: Vin) -> None:
        """Stop the air conditioning."""
        future = self._wait_for_operation(OperationName.STOP_AIR_CONDITIONING)
        await self.rest_api.stop_air_conditioning(vin)
        await future

    async def start_ventilation(self, vin: Vin) -> None:
        """Start the ventilation."""
        future = self._wait_for_operation(OperationName.START_ACTIVE_VENTILATION)
        await self.rest_api.start_ventilation(vin)
        await future

    async def stop_ventilation(self, vin: Vin) -> None:
        """Start the ventilation."""
        future = self._wait_for_operation(OperationName.STOP_ACTIVE_VENTILATION)
        await self.rest_api.stop_ventilation(vin)
        await future

    async def start_auxiliary_heating(
        self, vin: Vin, spin: str, config: AuxiliaryConfig | None = None
    ) -> None:
        """Start the auxiliary heating with the provided configuration."""
        future = self._wait_for_operation(OperationName.START_AUXILIARY_HEATING)
        await self.rest_api.start_auxiliary_heating(vin, spin, config=config)
        await future

    async def stop_auxiliary_heating(self, vin: Vin) -> None:
        """Stop the auxiliary heating."""
        future = self._wait_for_operation(OperationName.STOP_AUXILIARY_HEATING)
        await self.rest_api.stop_auxiliary_heating(vin)
        await future

    async def set_ac_timer(self, vin: Vin, timer: AirConditioningTimer) -> None:
        """Send provided air-conditioning timer to the vehicle."""
        future = self._wait_for_operation(OperationName.SET_AIR_CONDITIONING_TIMERS)
        await self.rest_api.set_ac_timer(vin, timer)
        await future

    async def set_auxiliary_heating_timer(
        self, vin: Vin, timer: AuxiliaryHeatingTimer, spin: str
    ) -> None:
        """Send provided auxiliary heating timer to the vehicle."""
        future = self._wait_for_operation(OperationName.SET_AIR_CONDITIONING_TIMERS)
        await self.rest_api.set_auxiliary_heating_timer(vin, timer, spin)
        await future

    async def lock(self, vin: Vin, spin: str) -> None:
        """Lock the car."""
        future = self._wait_for_operation(OperationName.LOCK)
        await self.rest_api.lock(vin, spin)
        await future

    async def unlock(self, vin: Vin, spin: str) -> None:
        """Unlock the car."""
        future = self._wait_for_operation(OperationName.UNLOCK)
        await self.rest_api.unlock(vin, spin)
        await future

    async def set_departure_timer(self, vin: Vin, timer: DepartureTimer) -> None:
        """Send provided departure timer to the vehicle."""
        future = self._wait_for_operation(OperationName.UPDATE_DEPARTURE_TIMERS)
        await self.rest_api.set_departure_timer(vin, timer)
        await future

    async def refresh_user(self) -> None:
        """Refresh user data for the provided Vin."""
        if self.user and self.user.timestamp:
            cache_expiry_time = self.user.timestamp + timedelta(hours=CACHE_USER_ENDPOINT_IN_HOURS)

            if datetime.now(UTC) > cache_expiry_time:
                _LOGGER.debug("Refreshing user - cache expired at %s", self.user.timestamp)
                self.user = await self.get_user()
            else:
                _LOGGER.debug("Skipping user refresh - cache is still valid.")
        else:
            self.user = await self.get_user()

    @async_debounce(immediate=True)
    async def refresh_vehicle(self, vin: Vin, notify: bool = True) -> None:
        """Refresh all vehicle data for the provided Vin.

        Get health only when missing and every 24h.
        This avoids triggering battery protection, such as in Citigoe and Karoq.
        https://github.com/skodaconnect/homeassistant-myskoda/issues/468
        """
        excluded_capabilities = []
        if (vehicle := self._vehicles.get(vin)) and vehicle.health and vehicle.health.timestamp:
            cache_expiry = vehicle.health.timestamp + timedelta(hours=CACHE_VEHICLE_HEALTH_IN_HOURS)

            if datetime.now(UTC) > cache_expiry:
                _LOGGER.debug("Refreshing health - cache expired at %s", cache_expiry)
            else:
                _LOGGER.debug("Skipping health refresh - cache is still valid.")
                excluded_capabilities.append(CapabilityId.VEHICLE_HEALTH_INSPECTION)

        self._vehicles[vin] = await self.get_vehicle(vin, excluded_capabilities)

        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_info(self, vin: Vin, notify: bool = True) -> None:
        """Refresh info data for the provided Vin."""
        self._vehicles[vin].info = await self.get_info(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_charging(self, vin: Vin, notify: bool = True) -> None:
        """Refresh charging data for the provided Vin."""
        self._vehicles[vin].charging = await self.get_charging(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_status(self, vin: Vin, notify: bool = True) -> None:
        """Refresh status data for the provided Vin."""
        self._vehicles[vin].status = await self.get_status(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_air_conditioning(self, vin: Vin, notify: bool = True) -> None:
        """Refresh air_conditioning data for the provided Vin."""
        self._vehicles[vin].air_conditioning = await self.get_air_conditioning(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_auxiliary_heating(self, vin: Vin, notify: bool = True) -> None:
        """Refresh auxiliary_heating data for the provided Vin."""
        self._vehicles[vin].auxiliary_heating = await self.get_auxiliary_heating(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_positions(self, vin: Vin, notify: bool = True) -> None:
        """Refresh positions data for the provided Vin."""
        self._vehicles[vin].positions = await self.get_positions(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_driving_range(self, vin: Vin, notify: bool = True) -> None:
        """Refresh driving_range data for the provided Vin."""
        self._vehicles[vin].driving_range = await self.get_driving_range(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_trip_statistics(self, vin: Vin, notify: bool = True) -> None:
        """Refresh trip_statistics data for the provided Vin."""
        self._vehicles[vin].trip_statistics = await self.get_trip_statistics(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_single_trip_statistics(self, vin: Vin, notify: bool = True) -> None:
        """Refresh single_trip_statistics data for the provided Vin."""
        self._vehicles[vin].single_trip_statistics = await self.get_single_trip_statistics(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_maintenance(self, vin: Vin, notify: bool = True) -> None:
        """Refresh maintenance data for the provided Vin."""
        self._vehicles[vin].maintenance = await self.get_maintenance(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_maintenance_report(self, vin: Vin, notify: bool = True) -> None:
        """Refresh only the maintenance report for the provided Vin."""
        self._vehicles[vin].maintenance.maintenance_report = await self.get_maintenance_report(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_health(self, vin: Vin, notify: bool = True) -> None:
        """Refresh health data for the provided Vin."""
        self._vehicles[vin].health = await self.get_health(vin)
        if notify:
            self._notify_callbacks(vin)

    @async_debounce(immediate=True)
    async def refresh_departure_info(self, vin: Vin, notify: bool = True) -> None:
        """Refresh departure_info data for the provided Vin."""
        self._vehicles[vin].departure_info = await self.get_departure_timers(vin)
        if notify:
            self._notify_callbacks(vin)

    async def generate_fixture_report(
        self, vin: Vin, vehicle: FixtureVehicle, endpoint: Endpoint
    ) -> FixtureReportGet:
        """Generate a fixture report for the specified endpoint and vehicle."""
        try:
            result = await self.get_endpoint(vin, endpoint, anonymize=True)
        except Exception:  # noqa: BLE001
            return FixtureReportGet(
                type=FixtureReportType.GET,
                vehicle_id=vehicle.id,
                success=False,
                endpoint=endpoint,
                error=anonymize_url(format_exc()),
            )
        else:
            return FixtureReportGet(
                type=FixtureReportType.GET,
                vehicle_id=vehicle.id,
                raw=result.raw,
                success=True,
                url=result.url,
                endpoint=endpoint,
                result=result.result.to_dict(),
            )

    async def get_endpoint(
        self, vin: Vin, endpoint: Endpoint, anonymize: bool = False
    ) -> GetEndpointResult[Any]:
        """Invoke a get endpoint by endpoint enum."""
        # Mapping of endpoints to corresponding methods
        endpoint_method_map = {
            Endpoint.INFO: self.rest_api.get_info,
            Endpoint.STATUS: self.rest_api.get_status,
            Endpoint.AIR_CONDITIONING: self.rest_api.get_air_conditioning,
            Endpoint.AUXILIARY_HEATING: self.rest_api.get_auxiliary_heating,
            Endpoint.POSITIONS: self.rest_api.get_positions,
            Endpoint.HEALTH: self.rest_api.get_health,
            Endpoint.CHARGING: self.rest_api.get_charging,
            Endpoint.CHARGING_PROFILES: self.rest_api.get_charging_profiles,
            Endpoint.MAINTENANCE: self.rest_api.get_maintenance,
            Endpoint.DRIVING_RANGE: self.rest_api.get_driving_range,
            Endpoint.TRIP_STATISTICS: self.rest_api.get_trip_statistics,
            Endpoint.DEPARTURE_INFO: self.rest_api.get_departure_timers,
            Endpoint.VEHICLE_CONNECTION_STATUS: self.rest_api.get_vehicle_connection_status,
        }

        # Look up the method, or raise an error if unsupported
        method = endpoint_method_map.get(endpoint)
        if not method:
            error_message = f"Unsupported endpoint: {endpoint}"
            raise UnsupportedEndpointError(error_message)

        # Call the method and return the result
        return await method(vin, anonymize=anonymize)

    async def generate_get_fixture(
        self, name: str, description: str, vins: list[str], endpoint: Endpoint
    ) -> Fixture:  # pragma: no cover
        """Generate a fixture for a get request."""
        vehicles = [
            (vin, create_fixture_vehicle(i, await self.get_info(vin))) for i, vin in enumerate(vins)
        ]

        endpoints = []
        if endpoint != Endpoint.ALL:
            endpoints = [endpoint]
        else:
            endpoints = filter(lambda ep: ep != Endpoint.ALL, Endpoint)

        reports = [
            await self.generate_fixture_report(vin, vehicle, endpoint)
            for (vin, vehicle) in vehicles
            for endpoint in endpoints
        ]

        return Fixture(
            name=name,
            description=description,
            generation_time=datetime.now(tz=UTC),
            vehicles=[vehicle for (_, vehicle) in vehicles],
            reports=reports,
            library_version=version,
        )

    async def _request_capability_data(self, vin: Vin, capa: CapabilityId) -> None:
        """Request specific capability data from MySkoda API."""
        capa_request_map = {
            CapabilityId.AIR_CONDITIONING: self._request_air_conditioning,
            CapabilityId.AUXILIARY_HEATING: self._request_auxiliary_heating,
            CapabilityId.CHARGING: self._request_charging,
            CapabilityId.PARKING_POSITION: self._request_positions,
            CapabilityId.STATE: self._request_state,
            CapabilityId.TRIP_STATISTICS: self._request_trip_statistics,
            CapabilityId.VEHICLE_HEALTH_INSPECTION: self._request_health,
            CapabilityId.DEPARTURE_TIMERS: self._request_departure_info,
            CapabilityId.READINESS: self._request_connection_status,
        }

        try:
            request_fn = capa_request_map.get(capa)
            if request_fn:
                await request_fn(vin)
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Requesting %s failed: %s, continue", capa, err)

    async def _request_air_conditioning(self, vin: Vin) -> None:
        """Update state with air conditioning data."""
        self._vehicles[vin].air_conditioning = await self.get_air_conditioning(vin)

    async def _request_auxiliary_heating(self, vin: Vin) -> None:
        """Update state with auxiliary heating data."""
        self._vehicles[vin].auxiliary_heating = await self.get_auxiliary_heating(vin)

    async def _request_charging(self, vin: Vin) -> None:
        """Update state with charging data."""
        self._vehicles[vin].charging = await self.get_charging(vin)

    async def _request_positions(self, vin: Vin) -> None:
        """Update state with parking position data."""
        self._vehicles[vin].positions = await self.get_positions(vin)

    async def _request_state(self, vin: Vin) -> None:
        """Update state with state and driving range data."""
        self._vehicles[vin].status = await self.get_status(vin)
        self._vehicles[vin].driving_range = await self.get_driving_range(vin)

    async def _request_trip_statistics(self, vin: Vin) -> None:
        """Update state with trip statistics data."""
        self._vehicles[vin].trip_statistics = await self.get_trip_statistics(vin)
        self._vehicles[vin].single_trip_statistics = await self.get_single_trip_statistics(vin)

    async def _request_health(self, vin: Vin) -> None:
        """Update state with vehicle health inspection data."""
        self._vehicles[vin].health = await self.get_health(vin)

    async def _request_departure_info(self, vin: Vin) -> None:
        """Update state with departure timer data."""
        self._vehicles[vin].departure_info = await self.get_departure_timers(vin)

    async def _request_connection_status(self, vin: Vin) -> None:
        """Update state with connection status data."""
        self._vehicles[vin].connection_status = await self.get_connection_status(vin)

    async def _wait_for_operation(self, operation: OperationName) -> None:
        if self.mqtt is None:
            return
        try:
            async with asyncio.timeout(MQTT_OPERATION_TIMEOUT):
                await self.mqtt.wait_for_operation(operation)
        except TimeoutError:
            _LOGGER.warning("Timeout occurred while waiting for %s. Aborted.", operation)

    def _notify_callbacks(self, vin: Vin) -> None:
        """Execute registered callback functions for the vin."""
        for callback in self._callbacks.get(vin, []):
            result = callback()
            if result is not None:
                task = asyncio.create_task(result)
                background_tasks.add(task)
                task.add_done_callback(background_tasks.discard)

    def _create_mqtt_client(self) -> MySkodaMqttClient:
        mqtt = MySkodaMqttClient(authorization=self.authorization, ssl_context=self.ssl_context)
        mqtt.subscribe(self._on_mqtt_event)
        return mqtt

    async def _on_mqtt_event(self, event: BaseEvent) -> None:
        """Handle MQTT events.

        Update self._vehicles with data received in event and notify callbacks.
        """
        if event.vin not in self._vehicles:
            _LOGGER.debug("Received event for unknown VIN %s", event)
            return

        if isinstance(event, OperationEvent):
            await self._process_operation_event(event)
        elif isinstance(event, ServiceEventChangeSoc):
            await self._process_charging_event(event)
        elif isinstance(event, ServiceEventCharging):
            await self.refresh_charging(event.vin)
        elif isinstance(event, ServiceEventAccess):
            await self.refresh_vehicle(event.vin)
        elif isinstance(event, ServiceEventAirConditioning):
            await self.refresh_air_conditioning(event.vin)
        elif isinstance(event, ServiceEventDeparture):
            await self.refresh_positions(event.vin)
        elif isinstance(event, ServiceEventOdometer):
            await self.refresh_maintenance_report(event.vin)

    async def _process_operation_event(self, event: OperationEvent) -> None:
        """Refresh the appropriate vehicle data based on the operation details."""
        _LOGGER.debug("Processing operation event: %s", event)
        if event.status == OperationStatus.ERROR:
            _LOGGER.warning(
                "Error received from car in operation %s, reason: %s.",
                event.status,
                event.error_code,
            )
            return
        if event.status == OperationStatus.IN_PROGRESS:
            return
        # The API backend doesn't seem to update right away after an operation completes so delay
        # a little bit before refreshing data. Magic numbers are bad but there is no way for us
        # to know when the backend has updated data...
        await asyncio.sleep(OPERATION_REFRESH_DELAY_SECONDS)
        if event.operation in [
            OperationName.STOP_AIR_CONDITIONING,
            OperationName.START_AIR_CONDITIONING,
            OperationName.SET_AIR_CONDITIONING_TARGET_TEMPERATURE,
            OperationName.START_WINDOW_HEATING,
            OperationName.STOP_WINDOW_HEATING,
            OperationName.SET_AIR_CONDITIONING_TIMERS,
        ]:
            await self.refresh_air_conditioning(event.vin)
        elif event.operation in [
            OperationName.START_AUXILIARY_HEATING,
            OperationName.STOP_AUXILIARY_HEATING,
        ]:
            await self.refresh_auxiliary_heating(event.vin)
        elif event.operation in [
            OperationName.UPDATE_CHARGE_LIMIT,
            OperationName.UPDATE_CARE_MODE,
            OperationName.UPDATE_CHARGING_CURRENT,
            OperationName.START_CHARGING,
            OperationName.STOP_CHARGING,
            OperationName.UPDATE_AUTO_UNLOCK_PLUG,
        ]:
            await self.refresh_charging(event.vin)
        elif event.operation in [
            OperationName.LOCK,
            OperationName.UNLOCK,
        ]:
            await self.refresh_status(event.vin)
        elif event.operation == OperationName.UPDATE_DEPARTURE_TIMERS:
            await self.refresh_departure_info(event.vin)

    async def _process_charging_event(self, event: ServiceEventChangeSoc) -> None:
        """Update self._vehicles with data from the event.

        Start by fully refreshing Vehicle.charging and Vehicle.driving_range as the endpoints
        may return updated data which is not included in the event. At the same time, the event
        may have more recent data so still apply data extracted from the event on top...
        """
        _LOGGER.debug("Processing charging event: %s", event)
        await self.refresh_charging(event.vin, notify=False)
        await self.refresh_driving_range(event.vin, notify=False)

        vehicle = self._vehicles[event.vin]
        if vehicle.charging and (status := vehicle.charging.status):
            self._process_charging_event_update_charging(status, event.data)

        if driving_range := vehicle.driving_range:
            self._process_charging_event_update_driving_range(driving_range, event.data)

        self._notify_callbacks(event.vin)

    @staticmethod
    def _process_charging_event_update_charging(
        charging_status: ChargingStatus, event_data: ServiceEventChangeSocData
    ) -> None:
        """Update charging_status with the event_data."""
        if event_data.charged_range:
            charging_status.battery.remaining_cruising_range_in_meters = (
                event_data.charged_range * 1000
            )
        if event_data.soc:
            charging_status.battery.state_of_charge_in_percent = event_data.soc
        if event_data.time_to_finish:
            charging_status.remaining_time_to_fully_charged_in_minutes = event_data.time_to_finish
        if event_data.state:
            charging_status.state = event_data.state

    @staticmethod
    def _process_charging_event_update_driving_range(
        driving_range: DrivingRange, event_data: ServiceEventChangeSocData
    ) -> None:
        """Update driving_range with the event_data."""
        per = driving_range.primary_engine_range
        ser = False

        if driving_range.secondary_engine_range:
            ser = driving_range.secondary_engine_range

        if event_data.soc:
            if per.engine_type == EngineType.ELECTRIC:
                per.current_soc_in_percent = event_data.soc
            elif ser and ser.engine_type == EngineType.ELECTRIC:
                ser.current_soc_in_percent = event_data.soc

        if event_data.charged_range:
            range_in_km = int(event_data.charged_range / 1000)
            if per.engine_type == EngineType.ELECTRIC:
                per.remaining_range_in_km = range_in_km
            elif ser and ser.engine_type == EngineType.ELECTRIC:
                ser.remaining_range_in_km = range_in_km

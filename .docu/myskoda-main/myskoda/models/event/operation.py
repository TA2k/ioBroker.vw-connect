"""Models for operation events, returned by the MQTT broker.

Operation Event example:
{
    "version": 1,
    "traceId": "800a74737b5a4328862d958c35b71b74",
    "operation": "start-window-heating",
    "status": "ERROR",
    "errorCode": "timeout",
    "requestId": "5a16b265-85e7-4502-bd24-c92091c3df31",
}
"""

from dataclasses import dataclass, field
from enum import StrEnum

from mashumaro import field_options

from .base import BaseEvent, EventType


class OperationStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED_SUCCESS = "COMPLETED_SUCCESS"
    COMPLETED_WARNING = "COMPLETED_WARNING"
    ERROR = "ERROR"


class OperationName(StrEnum):
    APPLY_BACKUP = "apply-backup"
    LOCK = "lock"
    SET_AIR_CONDITIONING_AT_UNLOCK = "set-air-conditioning-at-unlock"
    SET_AIR_CONDITIONING_SEATS_HEATING = "set-air-conditioning-seats-heating"
    SET_AIR_CONDITIONING_TARGET_TEMPERATURE = "set-air-conditioning-target-temperature"
    SET_AIR_CONDITIONING_TIMERS = "set-air-conditioning-timers"
    SET_AIR_CONDITIONING_WITHOUT_EXTERNAL_POWER = "set-air-conditioning-without-external-power"
    SET_CLIMATE_PLANS = "set-climate-plans"
    START_ACTIVE_VENTILATION = "start-active-ventilation"
    START_AIR_CONDITIONING = "start-air-conditioning"
    START_AUXILIARY_HEATING = "start-auxiliary-heating"
    START_CHARGING = "start-charging"
    START_FLASH = "start-flash"
    START_HONK = "start-honk"
    START_WINDOW_HEATING = "start-window-heating"
    START_STOP_CHARGING = "start-stop-charging"
    STOP_ACTIVE_VENTILATION = "stop-active-ventilation"
    STOP_AIR_CONDITIONING = "stop-air-conditioning"
    STOP_AUXILIARY_HEATING = "stop-auxiliary-heating"
    STOP_CHARGING = "stop-charging"
    STOP_WINDOW_HEATING = "stop-window-heating"
    UNLOCK = "unlock"
    UPDATE_AUTO_UNLOCK_PLUG = "update-auto-unlock-plug"
    UPDATE_BATTERY_SUPPORT = "update-battery-support"
    UPDATE_CARE_MODE = "update-care-mode"
    UPDATE_CHARGE_LIMIT = "update-charge-limit"
    UPDATE_CHARGE_MODE = "update-charge-mode"
    UPDATE_CHARGING_CURRENT = "update-charging-current"
    UPDATE_CHARGING_PROFILES = "update-charging-profiles"
    UPDATE_DEPARTURE_TIMERS = "update-departure-timers"
    UPDATE_MINIMAL_SOC = "update-minimal-soc"
    UPDATE_TARGET_TEMPERATURE = "update-target-temperature"
    WAKEUP = "wakeup"
    WINDOWS_HEATING = "windows-heating"


@dataclass(frozen=True)
class OperationEvent(BaseEvent):
    """Base model for all Operation Events."""

    event_type = EventType.OPERATION
    request_id: str = field(metadata=field_options(alias="requestId"))
    operation: OperationName
    status: OperationStatus
    error_code: str | None = field(default=None, metadata=field_options(alias="errorCode"))


# TODO @dvx76: so also have a subclass per operation name here??

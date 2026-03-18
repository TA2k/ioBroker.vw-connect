"""Models for responses of api/v2/air-conditioning endpoint."""

from dataclasses import dataclass, field
from datetime import datetime, time
from enum import StrEnum
from typing import Any

from mashumaro import field_options
from mashumaro.config import (
    TO_DICT_ADD_BY_ALIAS_FLAG,
    TO_DICT_ADD_OMIT_NONE_FLAG,
    BaseConfig,
)
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .common import BaseResponse, ChargerLockedState, ConnectionState, OnOffState, Side, Weekday


class TemperatureUnit(StrEnum):
    CELSIUS = "CELSIUS"


class TimerMode(StrEnum):
    ONE_OFF = "ONE_OFF"
    RECURRING = "RECURRING"


class AirConditioningState(StrEnum):
    COOLING = "COOLING"
    HEATING = "HEATING"
    HEATING_AUXILIARY = "HEATING_AUXILIARY"
    OFF = "OFF"
    ON = "ON"
    VENTILATION = "VENTILATION"
    INVALID = "INVALID"


# Probably other states than AUTOMATIC are available, to be discovered
class HeaterSource(StrEnum):
    AUTOMATIC = "AUTOMATIC"
    ELECTRIC = "ELECTRIC"


@dataclass
class AirConditioningTimer(DataClassORJSONMixin):
    enabled: bool
    id: int
    time: time
    type: TimerMode
    selected_days: list[Weekday] = field(metadata=field_options(alias="selectedDays"))

    class Config(BaseConfig):
        """Configuration for serialization and deserialization.."""

        code_generation_options = [  # noqa: RUF012
            TO_DICT_ADD_BY_ALIAS_FLAG
        ]

    def __post_serialize__(self, d: dict[Any, Any]) -> dict[Any, Any]:
        """Post-process the data before serialization."""
        if self.time:
            d["time"] = self.time.strftime("%H:%M")  # Format to hh:mm
        return d


@dataclass
class SeatHeating(DataClassORJSONMixin):
    front_left: bool | None = field(default=None, metadata=field_options(alias="frontLeft"))
    front_right: bool | None = field(default=None, metadata=field_options(alias="frontRight"))

    class Config(BaseConfig):
        """Configuration for serialization and deserialization.."""

        code_generation_options = [  # noqa: RUF012
            TO_DICT_ADD_BY_ALIAS_FLAG,
            TO_DICT_ADD_OMIT_NONE_FLAG,
        ]


@dataclass
class TargetTemperature(DataClassORJSONMixin):
    temperature_value: float = field(metadata=field_options(alias="temperatureValue"))
    unit_in_car: TemperatureUnit = field(
        default=TemperatureUnit.CELSIUS, metadata=field_options(alias="unitInCar")
    )

    class Config(BaseConfig):
        """Configuration for serialization and deserialization.."""

        code_generation_options = [TO_DICT_ADD_BY_ALIAS_FLAG]  # noqa: RUF012


@dataclass
class OutsideTemperature(TargetTemperature):
    car_captured_timestamp: datetime | None = field(
        default=None, metadata=field_options(alias="carCapturedTimestamp")
    )


@dataclass
class WindowHeatingState(DataClassORJSONMixin):
    front: OnOffState
    rear: OnOffState
    unspecified: Any


@dataclass
class AirConditioningAtUnlock(DataClassORJSONMixin):
    """AirConditioningAtUnlock setting."""

    air_conditioning_at_unlock_enabled: bool = field(
        metadata=field_options(alias="airConditioningAtUnlockEnabled")
    )

    class Config(BaseConfig):
        """Configuration for serialization and deserialization.."""

        serialize_by_alias = True


@dataclass
class AirConditioningWithoutExternalPower(DataClassORJSONMixin):
    """AirConditioningWithoutExternalPower setting."""

    air_conditioning_without_external_power_enabled: bool = field(
        metadata=field_options(alias="airConditioningWithoutExternalPowerEnabled")
    )

    class Config(BaseConfig):
        """Configuration for serialization and deserialization.."""

        serialize_by_alias = True


@dataclass
class WindowHeating(DataClassORJSONMixin):
    """WindowHeating setting."""

    window_heating_enabled: bool = field(metadata=field_options(alias="windowHeatingEnabled"))

    class Config(BaseConfig):
        """Configuration for serialization and deserialization.."""

        serialize_by_alias = True


@dataclass
class AirConditioning(BaseResponse):
    """Information related to air conditioning."""

    timers: list[AirConditioningTimer]
    errors: list[Any]
    state: AirConditioningState
    steering_wheel_position: Side | None = field(
        default=None, metadata=field_options(alias="steeringWheelPosition")
    )
    window_heating_state: WindowHeatingState | None = field(
        default=None, metadata=field_options(alias="windowHeatingState")
    )
    car_captured_timestamp: datetime | None = field(
        default=None, metadata=field_options(alias="carCapturedTimestamp")
    )
    air_conditioning_at_unlock: bool | None = field(
        default=None, metadata=field_options(alias="airConditioningAtUnlock")
    )
    charger_connection_state: ConnectionState | None = field(
        default=None, metadata=field_options(alias="chargerConnectionState")
    )
    charger_lock_state: ChargerLockedState | None = field(
        default=None, metadata=field_options(alias="chargerLockState")
    )
    estimated_date_time_to_reach_target_temperature: datetime | None = field(
        default=None, metadata=field_options(alias="estimatedDateTimeToReachTargetTemperature")
    )
    heater_source: HeaterSource | None = field(
        default=None, metadata=field_options(alias="heaterSource")
    )
    seat_heating_activated: SeatHeating | None = field(
        default=None, metadata=field_options(alias="seatHeatingActivated")
    )
    target_temperature: TargetTemperature | None = field(
        default=None, metadata=field_options(alias="targetTemperature")
    )
    window_heating_enabled: bool | None = field(
        default=None, metadata=field_options(alias="windowHeatingEnabled")
    )
    air_conditioning_without_external_power: bool | None = field(
        default=None, metadata=field_options(alias="airConditioningWithoutExternalPower")
    )
    outside_temperature: OutsideTemperature | None = field(
        default=None, metadata=field_options(alias="outsideTemperature")
    )

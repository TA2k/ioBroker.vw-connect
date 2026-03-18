"""Models for responses of api/v2/auxiliary_heating endpoint."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from mashumaro import field_options
from mashumaro.config import TO_DICT_ADD_BY_ALIAS_FLAG, TO_DICT_ADD_OMIT_NONE_FLAG, BaseConfig
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .air_conditioning import (
    AirConditioningTimer,
    HeaterSource,
    OutsideTemperature,
    TargetTemperature,
)
from .common import BaseResponse


class AuxiliaryState(StrEnum):
    HEATING_AUXILIARY = "HEATING_AUXILIARY"
    INVALID = "INVALID"
    OFF = "OFF"
    PREHEATING = "PREHEATING"
    UNSUPPORTED = "UNSUPPORTED"
    VENTILATION = "VENTILATION"


class AuxiliaryStartMode(StrEnum):
    HEATING = "HEATING"
    VENTILATION = "VENTILATION"
    INVALID = "INVALID"


@dataclass
class AuxiliaryConfig(DataClassORJSONMixin):
    """Configuration needed for starting auxiliary heater."""

    target_temperature: TargetTemperature | None = field(
        default=None, metadata=field_options(alias="targetTemperature")
    )
    duration_in_seconds: int | None = field(
        default=None, metadata=field_options(alias="durationInSeconds")
    )
    heater_source: HeaterSource | None = field(
        default=None, metadata=field_options(alias="heaterSource")
    )
    start_mode: AuxiliaryStartMode | None = field(
        default=None, metadata=field_options(alias="startMode")
    )

    class Config(BaseConfig):
        """Configuration for serialization and deserialization.."""

        code_generation_options = [  # noqa: RUF012
            TO_DICT_ADD_BY_ALIAS_FLAG,
            TO_DICT_ADD_OMIT_NONE_FLAG,
        ]

    def __pre_serialize__(self) -> "AuxiliaryConfig":
        """Round target temperature before serialization to 0.5."""
        if self.target_temperature is not None:
            self.target_temperature.temperature_value = (
                round(self.target_temperature.temperature_value * 2) / 2
            )
        return self


@dataclass
class AuxiliaryHeatingTimer(AirConditioningTimer):
    """Timer for auxiliary heating."""


@dataclass
class AuxiliaryHeating(BaseResponse):
    """Information related to auxiliary heating."""

    timers: list[AuxiliaryHeatingTimer]
    errors: list[Any]
    state: AuxiliaryState | None = field(default=None, metadata=field_options(alias="state"))
    start_mode: AuxiliaryStartMode | None = field(
        default=None, metadata=field_options(alias="startMode")
    )
    duration_in_seconds: int | None = field(
        default=None, metadata=field_options(alias="durationInSeconds")
    )
    target_temperature: TargetTemperature | None = field(
        default=None, metadata=field_options(alias="targetTemperature")
    )
    car_captured_timestamp: datetime | None = field(
        default=None, metadata=field_options(alias="carCapturedTimestamp")
    )
    estimated_date_time_to_reach_target_temperature: datetime | None = field(
        default=None, metadata=field_options(alias="estimatedDateTimeToReachTargetTemperature")
    )
    outside_temperature: OutsideTemperature | None = field(
        default=None, metadata=field_options(alias="outsideTemperature")
    )

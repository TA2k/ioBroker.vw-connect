"""Models for responses of api/v2/vehicle-status/{vin}/driving-range endpoint."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .common import BaseResponse


class EngineType(StrEnum):
    DIESEL = "diesel"
    ELECTRIC = "electric"
    GASOLINE = "gasoline"
    HYBRID = "hybrid"
    CNG = "cng"
    UNKNOWN = "unknown"


@dataclass
class EngineRange(DataClassORJSONMixin):
    engine_type: EngineType = field(metadata=field_options(alias="engineType"))
    current_fuel_level_in_percent: int | None = field(
        default=None, metadata=field_options(alias="currentFuelLevelInPercent")
    )
    current_soc_in_percent: int | None = field(
        default=None, metadata=field_options(alias="currentSoCInPercent")
    )
    remaining_range_in_km: int | None = field(
        default=None, metadata=field_options(alias="remainingRangeInKm")
    )


@dataclass
class DrivingRange(BaseResponse):
    car_captured_timestamp: datetime = field(metadata=field_options(alias="carCapturedTimestamp"))
    car_type: EngineType = field(metadata=field_options(alias="carType"))
    primary_engine_range: EngineRange = field(metadata=field_options(alias="primaryEngineRange"))
    secondary_engine_range: EngineRange | None = field(
        default=None, metadata=field_options(alias="secondaryEngineRange")
    )
    total_range_in_km: int | None = field(
        default=None, metadata=field_options(alias="totalRangeInKm")
    )
    ad_blue_range: int | None = field(default=None, metadata=field_options(alias="adBlueRange"))

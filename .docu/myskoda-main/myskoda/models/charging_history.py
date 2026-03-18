"""Models for responses of api/v1/charging/{vin}/history."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .common import BaseResponse


class ChargingCurrentType(StrEnum):
    AC = "AC"
    DC = "DC"


@dataclass
class ChargingSession(DataClassORJSONMixin):
    start_at: datetime = field(metadata=field_options(alias="startAt"))
    charged_in_kwh: float = field(metadata=field_options(alias="chargedInKWh"))
    duration_in_minutes: int = field(metadata=field_options(alias="durationInMinutes"))
    current_type: ChargingCurrentType = field(metadata=field_options(alias="currentType"))


@dataclass
class ChargingPeriod(DataClassORJSONMixin):
    total_charged_in_kwh: float = field(
        default=0.0, metadata=field_options(alias="totalChargedInKWh")
    )
    sessions: list[ChargingSession] = field(default_factory=list)


@dataclass
class ChargingHistory(BaseResponse):
    next_cursor: datetime | None = field(default=None, metadata=field_options(alias="nextCursor"))
    periods: list[ChargingPeriod] = field(default_factory=list)

"""Models for responses of api/v1/vehicle-health-report/warning-lights endpoint."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .common import BaseResponse


class WarningLightCategory(StrEnum):
    ASSISTANCE = "ASSISTANCE"
    COMFORT = "COMFORT"
    BRAKE = "BRAKE"
    ELECTRIC_ENGINE = "ELECTRIC_ENGINE"
    ENGINE = "ENGINE"
    LIGHTING = "LIGHTING"
    TIRE = "TIRE"
    OTHER = "OTHER"


@dataclass
class DefectDetails(DataClassORJSONMixin):
    text: str
    priority: str
    icon: str | None = None


@dataclass
class WarningLight(DataClassORJSONMixin):
    category: WarningLightCategory
    defects: list[DefectDetails]


@dataclass
class Health(BaseResponse):
    """Information about the car's health (currently only mileage)."""

    warning_lights: list[WarningLight] = field(metadata=field_options(alias="warningLights"))
    mileage_in_km: int | None = field(default=None, metadata=field_options(alias="mileageInKm"))
    captured_at: datetime | None = field(default=None, metadata=field_options(alias="capturedAt"))

"""Models for responses of api/v2/garage/vehicles/{vin}."""

import logging
from dataclasses import dataclass, field
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .common import BaseResponse
from .info import CompositeRender, Render, VehicleState

_LOGGER = logging.getLogger(__name__)


class GarageErrorType(StrEnum):
    """Known errors in the Garage."""

    NO_MOD1_4_VEHICLES = "NO_MOD1_4_VEHICLES"
    UNKNOWN = "UNKNOWN"
    MISSING_RENDER = "MISSING_RENDER"


@dataclass
class GarageError(DataClassORJSONMixin):
    """Errors occurring in the Garage."""

    description: str
    type: GarageErrorType


@dataclass
class GarageEntry(DataClassORJSONMixin):
    """One vehicle in the list of vehicles."""

    vin: str
    name: str
    state: VehicleState
    title: str
    priority: int
    device_platform: str = field(metadata=field_options(alias="devicePlatform"))
    system_model_id: str = field(metadata=field_options(alias="systemModelId"))
    renders: list[Render]
    composite_renders: list[CompositeRender] = field(
        metadata=field_options(alias="compositeRenders")
    )


@dataclass
class Garage(BaseResponse):
    """Contents of the users Garage."""

    vehicles: list[GarageEntry] | None = field(default=None)
    errors: list[GarageError] | None = field(default=None)

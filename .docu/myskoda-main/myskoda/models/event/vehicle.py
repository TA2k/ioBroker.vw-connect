"""Models related to vehicle events from the MQTT broker.

Vehicle Event example:
{
    "version": 1,
    "traceId": "800a74737b5a4328862d958c35b71b74",
    "producer": "SKODA_MHUB",
    "name": "vehicle-awake",
    "timestamp": "2025-05-11T07:35:18Z",
    "data": {
        "userId": "b8bc126c-ee36-402b-8723-2c1c3dff8dec",
        "vin": "TMOCKAA0AA000000",
    },
}
"""

from dataclasses import dataclass, field
from enum import StrEnum

from mashumaro import field_options
from mashumaro.types import Discriminator

from myskoda.models.vehicle_ignition_status import (
    IgnitionStatus,
    UnexpectedIgnitionStatusError,
)

from .base import BaseEvent, BaseEventData, EventType


class VehicleEventTopic(StrEnum):
    VEHICLE_CONNECTION_STATUS_UPDATE = "VEHICLE_CONNECTION_STATUS_UPDATE"
    VEHICLE_IGNITION_STATUS = "VEHICLE_IGNITION_STATUS"


class VehicleEventName(StrEnum):
    """List of known vehicle EventNames."""

    VEHICLE_AWAKE = "vehicle-awake"
    VEHICLE_CONNECTION_ONLINE = "vehicle-connection-online"
    VEHICLE_CONNECTION_OFFLINE = "vehicle-connection-offline"
    VEHICLE_WARNING_BATTEYLEVEL = "vehicle-warning-batterylevel"
    VEHICLE_IGNITION_STATUS_CHANGED = "vehicle-ignition-status-changed"


def _deserialize_ignition_status(value: str) -> IgnitionStatus:
    match value:
        case "ON":
            return IgnitionStatus.ON
        case "OFF":
            return IgnitionStatus.OFF
        case _:
            raise UnexpectedIgnitionStatusError


@dataclass(frozen=True)
class VehicleEventData(BaseEventData):
    """Base model for data in all Vehicle Events."""


@dataclass(frozen=True)
class VehicleEvent(BaseEvent):
    """Base model for all Vehicle Events.

    Vehicle Events are unsolicited events emitted by the MQTT bus towards the client.
    Vehicle Events have a 'name' field which can be used as a discriminator.
    """

    class Config(BaseEvent.Config):  # noqa: D106
        discriminator = Discriminator(field="name", include_subtypes=True)

    event_type = EventType.VEHICLE_EVENT
    producer: str
    name: VehicleEventName
    data: VehicleEventData


@dataclass(frozen=True)
class VehicleEventVehicleIgnitionStatusData(VehicleEventData):
    """Ignition data inside vehicle service event vehicle-ignition-status."""

    ignition_status: IgnitionStatus | None = field(
        default=None,
        metadata=field_options(alias="ignitionStatus", deserialize=_deserialize_ignition_status),
    )


@dataclass(frozen=True)
class VehicleEventAwake(VehicleEvent):
    name = VehicleEventName.VEHICLE_AWAKE


@dataclass(frozen=True)
class VehicleEventConnectionOnline(VehicleEvent):
    name = VehicleEventName.VEHICLE_CONNECTION_ONLINE


@dataclass(frozen=True)
class VehicleEventConnectionOffline(VehicleEvent):
    name = VehicleEventName.VEHICLE_CONNECTION_OFFLINE


@dataclass(frozen=True)
class VehicleEventIgnitionStatusChanged(VehicleEvent):
    name = VehicleEventName.VEHICLE_IGNITION_STATUS_CHANGED
    data: VehicleEventVehicleIgnitionStatusData


@dataclass(frozen=True)
class VehicleEventWarningBatterylevel(VehicleEvent):
    name = VehicleEventName.VEHICLE_WARNING_BATTEYLEVEL

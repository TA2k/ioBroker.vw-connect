"""Models related to service events from the MQTT broker.

Service Event example:
{
    "version": 1,
    "traceId": "4a13b906-e13d-4ea5-a377-6cb70f790337",
    "producer": "SKODA_MHUB",
    "name": "change-soc",
    "timestamp": "2025-05-11T07:35:18Z",
    "data": {
        "mode": "manual",
        "state": "charging",
        "soc": "79",
        "chargedRange": "355",
        "timeToFinish": "130",
        "userId": "b8bc126c-ee36-402b-8723-2c1c3dff8dec",
        "vin": "TMOCKAA0AA000000",
    },
}
"""

from dataclasses import dataclass, field
from enum import StrEnum

from mashumaro import field_options
from mashumaro.types import Discriminator

from myskoda.models.charging import ChargeMode, ChargingState

from .base import BaseEvent, BaseEventData, EventType


class UnexpectedChargeModeError(Exception):
    pass


class UnexpectedChargingStateError(Exception):
    pass


class ServiceEventName(StrEnum):
    """List of known Service Event Names."""

    CHANGE_ACCESS = "change-access"
    CHANGE_CHARGE_MODE = "change-charge-mode"
    CHANGE_LIGHTS = "change-lights"
    CHANGE_ODOMETER = "change-odometer"
    CHANGE_REMAINING_TIME = "change-remaining-time"
    CHANGE_SOC = "change-soc"
    CHARGING_COMPLETED = "charging-completed"
    CHARGING_ERROR = "charging-error"
    CHARGING_STATUS_CHANGED = "charging-status-changed"
    CLIMATISATION_COMPLETED = "climatisation-completed"
    DEPARTURE_READY = "departure-ready"
    DEPARTURE_STATUS_CHANGED = "departure-status-changed"
    DEPARTURE_ERROR_PLUG = "departure-error-plug"


class ServiceEventError(StrEnum):
    STOPPED_DEVICE = "STOPPED_DEVICE"
    CLIMA = "CLIMA"
    STOPPED_POWER = "STOPPED_POWER"


def _deserialize_time_to_finish(value: int | str) -> int | None:
    if value == "null":
        return None
    return int(value)


@dataclass(frozen=True)
class ServiceEventData(BaseEventData):
    """Base model for data in all Service Events."""


@dataclass(frozen=True)
class ServiceEventErrorData(ServiceEventData):
    """Model for service event data with an error."""

    error_code: ServiceEventError = field(metadata=field_options(alias="errorCode"))


@dataclass(frozen=True)
class ServiceEvent(BaseEvent):
    """Base model for all Service Events.

    Service Events are unsolicited events emitted by the MQTT bus towards the client.
    Service Events have a 'name' field which can be used as a discriminator.
    """

    class Config(BaseEvent.Config):  # noqa: D106
        discriminator = Discriminator(field="name", include_subtypes=True)

    event_type = EventType.SERVICE_EVENT
    producer: str
    name: ServiceEventName
    data: ServiceEventData


# ChargeMode and ChargingState use different values in API responses and MQTT events.
# This allows using the same Enum for both.
ChargeMode.HOME_STORAGE_CHARGING._add_value_alias_("homeStorageCharging")  # type: ignore[reportAttributeAccessIssue]
ChargeMode.IMMEDIATE_DISCHARGING._add_value_alias_("immediateDischarging")  # type: ignore[reportAttributeAccessIssue]
ChargeMode.ONLY_OWN_CURRENT._add_value_alias_("onlyOwnCurrent")  # type: ignore[reportAttributeAccessIssue]
ChargeMode.PREFERRED_CHARGING_TIMES._add_value_alias_("preferredChargingTimes")  # type: ignore[reportAttributeAccessIssue]
ChargeMode.TIMER_CHARGING_WITH_CLIMATISATION._add_value_alias_("timerChargingWithClimatisation")  # type: ignore[reportAttributeAccessIssue]
ChargingState.READY_FOR_CHARGING._add_value_alias_("chargePurposeReachedAndNotConservationCharging")  # type: ignore[reportAttributeAccessIssue]
ChargingState.READY_FOR_CHARGING._add_value_alias_("readyForCharging")  # type: ignore[reportAttributeAccessIssue]
ChargingState.CONNECT_CABLE._add_value_alias_("notReadyForCharging")  # type: ignore[reportAttributeAccessIssue]
ChargingState.CONSERVING._add_value_alias_("chargePurposeReachedAndConservation")  # type: ignore[reportAttributeAccessIssue]


@dataclass(frozen=True)
class ServiceEventChangeSocData(ServiceEventData):
    """Charging data inside charging service event change-soc.

    TODO: Remove the None defaults where they aren't really needed...
    """

    mode: ChargeMode | None = None
    state: ChargingState | None = None
    soc: int | None = field(default=None)
    charged_range: int | None = field(default=None, metadata=field_options(alias="chargedRange"))
    time_to_finish: int | None = field(
        default=None,
        metadata=field_options(alias="timeToFinish", deserialize=_deserialize_time_to_finish),
    )


class ServiceEventAirConditioning(ServiceEvent):
    """Group events under topic 'service-event/air-conditioning'."""


@dataclass(frozen=True)
class ServiceEventClimatisationCompleted(ServiceEventAirConditioning):
    name = ServiceEventName.CLIMATISATION_COMPLETED


class ServiceEventCharging(ServiceEvent):
    """Group events under topic 'service-event/charging'."""


@dataclass(frozen=True)
class ServiceEventChangeChargeMode(ServiceEventCharging):
    name = ServiceEventName.CHANGE_CHARGE_MODE


@dataclass(frozen=True)
class ServiceEventChangeRemainingTime(ServiceEventCharging):
    name = ServiceEventName.CHANGE_REMAINING_TIME


@dataclass(frozen=True)
class ServiceEventChangeSoc(ServiceEventCharging):
    data: ServiceEventChangeSocData
    name = ServiceEventName.CHANGE_SOC


@dataclass(frozen=True)
class ServiceEventChargingCompleted(ServiceEventCharging):
    data: ServiceEventChangeSocData
    name = ServiceEventName.CHARGING_COMPLETED


@dataclass(frozen=True)
class ServiceEventChargingError(ServiceEventCharging):
    data: ServiceEventErrorData
    name = ServiceEventName.CHARGING_ERROR


@dataclass(frozen=True)
class ServiceEventChargingStatusChanged(ServiceEventCharging):
    name = ServiceEventName.CHARGING_STATUS_CHANGED


class ServiceEventAccess(ServiceEvent):
    """Group events under topic 'service-event/vehicle-status/access'."""


@dataclass(frozen=True)
class ServiceEventChangeAccess(ServiceEventAccess):
    name = ServiceEventName.CHANGE_ACCESS


class ServiceEventLights(ServiceEvent):
    """Group events under topic 'service-event/vehicle-status/lights'."""


@dataclass(frozen=True)
class ServiceEventChangeLights(ServiceEventLights):
    name = ServiceEventName.CHANGE_LIGHTS


class ServiceEventOdometer(ServiceEvent):
    """Group events under topic 'service-event/vehicle-status/odometer'."""


@dataclass(frozen=True)
class ServiceEventChangeOdometer(ServiceEventOdometer):
    name = ServiceEventName.CHANGE_ODOMETER


class ServiceEventDeparture(ServiceEvent):
    """Group events under topic 'service-event/departure'."""


@dataclass(frozen=True)
class ServiceEventDepartureReady(ServiceEventDeparture):
    name = ServiceEventName.DEPARTURE_READY


@dataclass(frozen=True)
class ServiceEventDepartureStatusChanged(ServiceEventDeparture):
    name = ServiceEventName.DEPARTURE_STATUS_CHANGED


@dataclass(frozen=True)
class ServiceEventDepartureErrorPlug(ServiceEventDeparture):
    data: ServiceEventErrorData
    name = ServiceEventName.DEPARTURE_ERROR_PLUG

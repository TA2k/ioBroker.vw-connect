"""Events emitted by MySkoda."""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from mashumaro import field_options
from mashumaro.config import BaseConfig
from mashumaro.mixins.orjson import DataClassORJSONMixin
from mashumaro.types import Discriminator


class EventType(StrEnum):
    """The different 'types' of events.

    The type is determine by a part of the MQTT topic.
    """

    ACCOUNT_EVENT = "account-event"
    OPERATION = "operation-request"
    SERVICE_EVENT = "service-event"
    VEHICLE_EVENT = "vehicle-event"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class BaseEventData(DataClassORJSONMixin):
    """Base model for data in all Events."""

    user_id: str = field(metadata=field_options(alias="userId"))
    vin: str


@dataclass(frozen=True, kw_only=True)
class BaseEvent(DataClassORJSONMixin):
    """Base model for all Events.

    Raw events from the MQTT broker don't include vin or event_type.
    """

    class Config(BaseConfig):  # noqa: D106
        discriminator = Discriminator(field="event_type", include_subtypes=True)

    vin: str = ""
    event_type: EventType = EventType.UNKNOWN
    version: int
    trace_id: str = field(metadata=field_options(alias="traceId"))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_mqtt_message(cls, topic: str, payload: str) -> "BaseEvent":
        """Return a parsed event object.

        'topic' is the original MQTT topic on which the event was received
        'payload' is the original payload as a binary string
        """
        # Depending on the event the event_topic can be one or two levels of the mqtt topic
        _user_id, vin, event_type, _event_topic = topic.split("/", maxsplit=3)
        deserialized_payload = json.loads(payload)
        deserialized_payload["vin"] = vin
        deserialized_payload["event_type"] = event_type
        return cls.from_dict(deserialized_payload)

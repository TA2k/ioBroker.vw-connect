"""Models related to service events from the MQTT broker."""

from dataclasses import dataclass
from enum import StrEnum

from .base import BaseEvent, EventType


class AccountEventTopic(StrEnum):
    ACCOUNT_PRIVACY = "ACCOUNT_PRIVACY"


@dataclass(frozen=True)
class AccountEvent(BaseEvent):
    """Base model for all Account Events.

    TODO: We need examples of account events!
    """

    event_type = EventType.ACCOUNT_EVENT

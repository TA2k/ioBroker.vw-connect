"""Common models used in multiple responses."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

type Vin = str


class CaseInsensitiveStrEnum(StrEnum):
    @classmethod
    def _missing_(cls, value: object) -> StrEnum | None:
        """Ignore the case of the value.

        Some endpoints will return values sometimes as uppercase and sometimes as lowercase...
        """
        if not isinstance(value, str):
            raise TypeError
        value = value.lower()
        for member in cls:
            if member.lower() == value:
                return member
        return None


class OnOffState(StrEnum):
    ON = "ON"
    OFF = "OFF"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


class EnabledState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    NOT_ALLOWED = "NOT_ALLOWED"


class ActiveState(StrEnum):
    ACTIVATED = "ACTIVATED"
    DEACTIVATED = "DEACTIVATED"


class OpenState(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class ReliableLockState(StrEnum):
    LOCKED = "LOCKED"
    UNLOCKED = "UNLOCKED"
    UNKNOWN = "UNKNOWN"


class DoorLockedState(StrEnum):
    LOCKED = "YES"
    OPENED = "OPENED"
    TRUNK_OPENED = "TRUNK_OPENED"
    UNLOCKED = "NO"
    UNKNOWN = "UNKNOWN"


class ChargerLockedState(StrEnum):
    LOCKED = "LOCKED"
    UNLOCKED = "UNLOCKED"
    INVALID = "INVALID"


class ConnectionState(StrEnum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"


class Side(StrEnum):
    LEFT = "LEFT"
    RIGHT = "RIGHT"


@dataclass
class Coordinates(DataClassORJSONMixin):
    """GPS Coordinates."""

    latitude: float
    longitude: float


@dataclass
class Address(DataClassORJSONMixin):
    """A representation of a house-address."""

    country_code: str = field(metadata=field_options(alias="countryCode"))
    zip_code: str | None = field(default=None, metadata=field_options(alias="zipCode"))
    house_number: str | None = field(default=None, metadata=field_options(alias="houseNumber"))
    street: str | None = field(default=None)
    city: str | None = field(default=None)
    country: str | None = field(default=None)


class Weekday(StrEnum):
    MONDAY = "MONDAY"
    TUESDAY = "TUESDAY"
    WEDNESDAY = "WEDNESDAY"
    THURSDAY = "THURSDAY"
    FRIDAY = "FRIDAY"
    SATURDAY = "SATURDAY"
    SUNDAY = "SUNDAY"


@dataclass
class BaseResponse(DataClassORJSONMixin):
    """Base class for all API response models.

    All responses have the current timestamp injected.
    """

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC), kw_only=True)

"""MySkoda Vehicle connection status."""

from dataclasses import dataclass, field

from mashumaro import field_options

from .common import BaseResponse


@dataclass
class VehicleConnectionStatus(BaseResponse):
    unreachable: bool
    in_motion: bool = field(metadata=field_options(alias="inMotion"))
    battery_protection_limit_on: bool = field(
        metadata=field_options(alias="batteryProtectionLimitOn")
    )
    ignition_on: bool | None = field(default=None, metadata=field_options(alias="ignitionOn"))


class UnexpectedVehicleConnectionStatusError(Exception):
    pass

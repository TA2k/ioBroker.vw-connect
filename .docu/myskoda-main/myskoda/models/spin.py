"""Models for responses of api/v1/spin/verify."""

from dataclasses import dataclass, field
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .common import BaseResponse


class VerificationStatus(StrEnum):
    """List of known statuses for SPIN."""

    CORRECT_SPIN = "CORRECT_SPIN"
    INCORRECT_SPIN = "INCORRECT_SPIN"


@dataclass
class SpinStatus(DataClassORJSONMixin):
    state: str
    remaining_tries: int = field(metadata=field_options(alias="remainingTries"))
    locked_waiting_time_in_seconds: int = field(
        metadata=field_options(alias="lockedWaitingTimeInSeconds")
    )


@dataclass
class Spin(BaseResponse):
    verification_status: VerificationStatus = field(
        metadata=field_options(alias="verificationStatus")
    )
    spin_status: SpinStatus | None = field(default=None, metadata=field_options(alias="spinStatus"))

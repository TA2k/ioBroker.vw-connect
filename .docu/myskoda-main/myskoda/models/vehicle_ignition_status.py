"""MySkoda Vehicle ignition statuses."""

from enum import StrEnum


class IgnitionStatus(StrEnum):
    ON = "ON"
    OFF = "OFF"


class UnexpectedIgnitionStatusError(Exception):
    pass

"""Models for responses of api/v1/charging/vin/profiles endpoint."""

from dataclasses import dataclass, field
from datetime import datetime, time

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .air_conditioning import TimerMode
from .charging import MaxChargeCurrent, PlugUnlockMode
from .common import BaseResponse, Coordinates, Weekday


@dataclass
class ChargingTimes(DataClassORJSONMixin):
    """Times a charging profile can be active."""

    id: int
    enabled: bool
    start_time: time = field(metadata=field_options(alias="startTime"))
    end_time: time = field(metadata=field_options(alias="endTime"))


@dataclass
class MinBatterySOC(DataClassORJSONMixin):
    """Settings for minimal battery SOC."""

    minimum_battery_state_of_charge_in_percent: int = field(
        metadata=field_options(alias="minimumBatteryStateOfChargeInPercent")
    )


@dataclass
class ProfileSettings(DataClassORJSONMixin):
    """Settings for a Charging location/Profile."""

    max_charging_current: MaxChargeCurrent = field(
        metadata=field_options(alias="maxChargingCurrent")
    )
    min_battery_state_of_charge: MinBatterySOC = field(
        metadata=field_options(alias="minBatteryStateOfCharge")
    )
    target_state_of_charge_in_percent: int = field(
        metadata=field_options(alias="targetStateOfChargeInPercent")
    )
    auto_unlock_plug_when_charged: PlugUnlockMode = field(
        metadata=field_options(alias="autoUnlockPlugWhenCharged")
    )


@dataclass
class ChargingTimers(DataClassORJSONMixin):
    """Timers for a Charging location."""

    id: int
    enabled: bool
    time: time
    type: TimerMode
    recurring_on: list[Weekday] = field(metadata=field_options(alias="recurringOn"))


@dataclass
class ChargingProfile(DataClassORJSONMixin):
    """Charging profile definition."""

    id: int
    name: str
    settings: ProfileSettings
    preferred_charging_times: list[ChargingTimes] = field(
        metadata=field_options(alias="preferredChargingTimes")
    )
    timers: list[ChargingTimers]
    location: Coordinates | None = field(default=None)


@dataclass
class CurrentProfile(DataClassORJSONMixin):
    """Information on the currently active charging profile."""

    id: int
    name: str
    target_state_of_charge_in_percent: int = field(
        metadata=field_options(alias="targetStateOfChargeInPercent")
    )
    next_charging_time: time | None = field(
        default=None, metadata=field_options(alias="nextChargingTime")
    )


@dataclass
class ChargingProfiles(BaseResponse):
    """Information related to location bound charging settings for an EV."""

    charging_profiles: list[ChargingProfile] = field(
        metadata=field_options(alias="chargingProfiles")
    )
    current_vehicle_position_profile: CurrentProfile | None = field(
        default=None, metadata=field_options(alias="currentVehiclePositionProfile")
    )
    car_captured_timestamp: datetime | None = field(
        default=None, metadata=field_options(alias="carCapturedTimestamp")
    )

"""Models for responses of api/v1/charging endpoint."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .common import ActiveState, BaseResponse, CaseInsensitiveStrEnum, EnabledState


class ChargingErrorType(StrEnum):
    CARE_MODE_IS_NOT_AVAILABLE = "CARE_MODE_IS_NOT_AVAILABLE"
    AUTO_UNLOCK_IS_NOT_AVAILABLE = "AUTO_UNLOCK_IS_NOT_AVAILABLE"
    MAX_CHARGE_CURRENT_IS_NOT_AVAILABLE = "MAX_CHARGE_CURRENT_IS_NOT_AVAILABLE"
    CHARGE_LIMIT_IS_NOT_AVAILABLE = "CHARGE_LIMIT_IS_NOT_AVAILABLE"
    STATUS_OF_CHARGING_NOT_AVAILABLE = "STATUS_OF_CHARGING_NOT_AVAILABLE"
    STATUS_OF_CONNECTION_NOT_AVAILABLE = "STATUS_OF_CONNECTION_NOT_AVAILABLE"


@dataclass
class ChargingError(DataClassORJSONMixin):
    type: ChargingErrorType
    description: str


class ChargeMode(CaseInsensitiveStrEnum):
    HOME_STORAGE_CHARGING = "HOME_STORAGE_CHARGING"
    IMMEDIATE_DISCHARGING = "IMMEDIATE_DISCHARGING"
    ONLY_OWN_CURRENT = "ONLY_OWN_CURRENT"
    PREFERRED_CHARGING_TIMES = "PREFERRED_CHARGING_TIMES"
    TIMER_CHARGING_WITH_CLIMATISATION = "TIMER_CHARGING_WITH_CLIMATISATION"
    TIMER = "TIMER"
    MANUAL = "MANUAL"
    OTHER = "OTHER"
    OFF = "OFF"


class MaxChargeCurrent(StrEnum):
    MAXIMUM = "MAXIMUM"
    REDUCED = "REDUCED"


class ChargingState(CaseInsensitiveStrEnum):
    READY_FOR_CHARGING = "READY_FOR_CHARGING"
    CONNECT_CABLE = "CONNECT_CABLE"
    CONSERVING = "CONSERVING"
    CHARGING = "CHARGING"
    CHARGING_INTERRUPTED = "CHARGING_INTERRUPTED"
    ERROR = "ERROR"


class ChargeType(StrEnum):
    AC = "AC"
    DC = "DC"
    OFF = "OFF"


class PlugUnlockMode(StrEnum):
    PERMANENT = "PERMANENT"
    ON = "ON"
    OFF = "OFF"


@dataclass
class Settings(DataClassORJSONMixin):
    available_charge_modes: list[ChargeMode] = field(
        metadata=field_options(alias="availableChargeModes")
    )
    max_charge_current_ac: MaxChargeCurrent | None = field(
        default=None, metadata=field_options(alias="maxChargeCurrentAc")
    )
    auto_unlock_plug_when_charged: PlugUnlockMode | None = field(
        default=None, metadata=field_options(alias="autoUnlockPlugWhenCharged")
    )
    battery_support: EnabledState | None = field(
        default=None, metadata=field_options(alias="batterySupport")
    )
    charging_care_mode: ActiveState | None = field(
        default=None, metadata=field_options(alias="chargingCareMode")
    )
    preferred_charge_mode: ChargeMode | None = field(
        default=None, metadata=field_options(alias="preferredChargeMode")
    )
    target_state_of_charge_in_percent: int | None = field(
        default=None, metadata=field_options(alias="targetStateOfChargeInPercent")
    )


@dataclass
class Battery(DataClassORJSONMixin):
    state_of_charge_in_percent: int | None = field(
        default=None, metadata=field_options(alias="stateOfChargeInPercent")
    )
    remaining_cruising_range_in_meters: int | None = field(
        default=None, metadata=field_options(alias="remainingCruisingRangeInMeters")
    )


@dataclass
class ChargingStatus(DataClassORJSONMixin):
    battery: Battery
    state: ChargingState | None = field(default=None)
    charge_power_in_kw: float | None = field(
        default=None, metadata=field_options(alias="chargePowerInKw")
    )
    charging_rate_in_kilometers_per_hour: float | None = field(
        default=None, metadata=field_options(alias="chargingRateInKilometersPerHour")
    )
    charge_type: ChargeType | None = field(default=None, metadata=field_options(alias="chargeType"))
    errors: list[ChargingError] | None = field(default=None)
    remaining_time_to_fully_charged_in_minutes: int | None = field(
        default=None, metadata=field_options(alias="remainingTimeToFullyChargedInMinutes")
    )


@dataclass
class Charging(BaseResponse):
    """Information related to charging an EV."""

    errors: list[ChargingError]
    settings: Settings
    is_vehicle_in_saved_location: bool = field(
        metadata=field_options(alias="isVehicleInSavedLocation")
    )
    car_captured_timestamp: datetime | None = field(
        default=None, metadata=field_options(alias="carCapturedTimestamp")
    )
    status: ChargingStatus | None = field(default=None)

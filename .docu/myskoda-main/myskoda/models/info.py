"""Models for responses of api/v2/garage/vehicles/{vin}."""

import logging
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin
from mashumaro.mixins.yaml import DataClassYAMLMixin

from .common import BaseResponse

_LOGGER = logging.getLogger(__name__)


class CapabilityId(StrEnum):
    """List of known Capabilities."""

    ACCESS = "ACCESS"
    ACCIDENT_DAMAGE_MANAGEMENT = "ACCIDENT_DAMAGE_MANAGEMENT"
    ACTIVE_VENTILATION = "ACTIVE_VENTILATION"
    AIR_CONDITIONING = "AIR_CONDITIONING"
    AIR_CONDITIONING_HEATING_SOURCE_AUXILIARY = "AIR_CONDITIONING_HEATING_SOURCE_AUXILIARY"
    AIR_CONDITIONING_HEATING_SOURCE_ELECTRIC = "AIR_CONDITIONING_HEATING_SOURCE_ELECTRIC"
    AIR_CONDITIONING_SAVE_AND_ACTIVATE = "AIR_CONDITIONING_SAVE_AND_ACTIVATE"
    AIR_CONDITIONING_SMART_SETTINGS = "AIR_CONDITIONING_SMART_SETTINGS"
    AIR_CONDITIONING_TIMERS = "AIR_CONDITIONING_TIMERS"
    AUTOMATION = "AUTOMATION"
    AUXILIARY_HEATING = "AUXILIARY_HEATING"
    AUXILIARY_HEATING_BASIC = "AUXILIARY_HEATING_BASIC"
    AUXILIARY_HEATING_TEMPERATURE_SETTING = "AUXILIARY_HEATING_TEMPERATURE_SETTING"
    AUXILIARY_HEATING_TIMERS = "AUXILIARY_HEATING_TIMERS"
    BATTERY_CHARGING_CARE = "BATTERY_CHARGING_CARE"
    BATTERY_SUPPORT = "BATTERY_SUPPORT"
    CAR_FEEDBACK = "CAR_FEEDBACK"
    CARE_AND_INSURANCE = "CARE_AND_INSURANCE"
    CHARGE_MODE_SELECTION = "CHARGE_MODE_SELECTION"
    CHARGING = "CHARGING"
    CHARGING_MEB = "CHARGING_MEB"
    CHARGING_MQB = "CHARGING_MQB"
    CHARGING_PROFILES = "CHARGING_PROFILES"
    CHARGING_PROFILES_CREATE = "CHARGING_PROFILES_CREATE"
    CHARGING_STATIONS = "CHARGING_STATIONS"
    CUBIC = "CUBIC"
    DEALER_APPOINTMENT = "DEALER_APPOINTMENT"
    DEPARTURE_TIMERS = "DEPARTURE_TIMERS"
    DESTINATIONS = "DESTINATIONS"
    DESTINATION_IMPORT = "DESTINATION_IMPORT"
    DESTINATION_IMPORT_UPGRADABLE = "DESTINATION_IMPORT_UPGRADABLE"
    DIGICERT = "DIGICERT"
    DRIVING_SCORE = "DRIVING_SCORE"
    E_PRIVACY = "E_PRIVACY"
    EMERGENCY_CALLING = "EMERGENCY_CALLING"
    EV_ROUTE_PLANNING = "EV_ROUTE_PLANNING"
    EV_SERVICE_BOOKING = "EV_SERVICE_BOOKING"
    EXTENDED_CHARGING_SETTINGS = "EXTENDED_CHARGING_SETTINGS"
    FLEET_SUPPORTED = "FLEET_SUPPORTED"
    FUEL_STATUS = "FUEL_STATUS"
    GEO_FENCE = "GEO_FENCE"
    GUEST_USER_MANAGEMENT = "GUEST_USER_MANAGEMENT"
    HONK_AND_FLASH = "HONK_AND_FLASH"
    ICE_VEHICLE_RTS = "ICE_VEHICLE_RTS"
    LAURA_INITIAL_PROMPTS_BEV = "LAURA_INITIAL_PROMPTS_BEV"
    LOYALTY_PROGRAM = "LOYALTY_PROGRAM"
    LOYALTY_PROGRAM_WORLDWIDE = "LOYALTY_PROGRAM_WORLDWIDE"
    MAP_UPDATE = "MAP_UPDATE"
    MEASUREMENTS = "MEASUREMENTS"
    MISUSE_PROTECTION = "MISUSE_PROTECTION"
    NEWS = "NEWS"
    ONLINE_REMOTE_UPDATE = "ONLINE_REMOTE_UPDATE"
    ONLINE_SPEECH_GPS = "ONLINE_SPEECH_GPS"
    OUTSIDE_TEMPERATURE = "OUTSIDE_TEMPERATURE"
    PARKING_INFORMATION = "PARKING_INFORMATION"
    PARKING_POSITION = "PARKING_POSITION"
    PAY_TO_FUEL = "PAY_TO_FUEL"
    PAY_TO_PARK = "PAY_TO_PARK"
    PLUG_AND_CHARGE = "PLUG_AND_CHARGE"
    POI_SEARCH = "POI_SEARCH"
    POWERPASS_TARIFFS = "POWERPASS_TARIFFS"
    PREDICTIVE_WAKE_UP = "PREDICTIVE_WAKE_UP"
    READINESS = "READINESS"
    ROADSIDE_ASSISTANT = "ROADSIDE_ASSISTANT"
    ROUTE_IMPORT = "ROUTE_IMPORT"
    ROUTE_PLANNING_5_CHARGERS = "ROUTE_PLANNING_5_CHARGERS"
    ROUTE_PLANNING_10_CHARGERS = "ROUTE_PLANNING_10_CHARGERS"
    ROUTING = "ROUTING"
    SERVICE_PARTNER = "SERVICE_PARTNER"
    SPEED_ALERT = "SPEED_ALERT"
    STATE = "STATE"
    SUBSCRIPTIONS = "SUBSCRIPTIONS"
    THEFT_WARNING = "THEFT_WARNING"
    TRAFFIC_INFORMATION = "TRAFFIC_INFORMATION"
    TRIP_STATISTICS = "TRIP_STATISTICS"
    TRIP_STATISTICS_MEB = "TRIP_STATISTICS_MEB"
    UNAVAILABILITY_STATUSES = "UNAVAILABILITY_STATUSES"
    VEHICLE_HEALTH_INSPECTION = "VEHICLE_HEALTH_INSPECTION"
    VEHICLE_HEALTH_WARNINGS = "VEHICLE_HEALTH_WARNINGS"
    VEHICLE_HEALTH_WARNINGS_WITH_WAKE_UP = "VEHICLE_HEALTH_WARNINGS_WITH_WAKE_UP"
    VEHICLE_SERVICES_BACKUPS = "VEHICLE_SERVICES_BACKUPS"
    VEHICLE_WAKE_UP = "VEHICLE_WAKE_UP"
    VEHICLE_WAKE_UP_TRIGGER = "VEHICLE_WAKE_UP_TRIGGER"
    WARNING_LIGHTS = "WARNING_LIGHTS"
    WEB_RADIO = "WEB_RADIO"
    WINDOW_HEATING = "WINDOW_HEATING"


class CapabilityStatus(StrEnum):
    """List of known statuses for Capabilities."""

    DEACTIVATED_BY_ACTIVE_VEHICLE_USER = "DEACTIVATED_BY_ACTIVE_VEHICLE_USER"
    DEACTIVATED = "DEACTIVATED"
    DISABLED_BY_USER = "DISABLED_BY_USER"
    FRONTEND_SWITCHED_OFF = "FRONTEND_SWITCHED_OFF"
    INITIALLY_DISABLED = "INITIALLY_DISABLED"
    INSUFFICIENT_BATTERY_LEVEL = "INSUFFICIENT_BATTERY_LEVEL"
    INSUFFICIENT_RIGHTS = "INSUFFICIENT_RIGHTS"
    INSUFFICIENT_SPIN = "INSUFFICIENT_SPIN"
    LICENSE_EXPIRED = "LICENSE_EXPIRED"
    LICENSE_MISSING = "LICENSE_MISSING"
    LOCATION_DATA_DISABLED = "LOCATION_DATA_DISABLED"
    VEHICLE_DISABLED = "VEHICLE_DISABLED"


class ErrorType(StrEnum):
    """Known errors."""

    MISSING_RENDER = "MISSING_RENDER"
    UNAVAILABLE_SERVICE_PLATFORM_CAPABILITIES = "UNAVAILABLE_SERVICE_PLATFORM_CAPABILITIES"
    UNAVAILABLE_SOFTWARE_VERSION = "UNAVAILABLE_SOFTWARE_VERSION"


@dataclass
class Error(DataClassORJSONMixin):
    """Main model for emitted errors."""

    description: str
    type: ErrorType


@dataclass
class Capability(DataClassORJSONMixin, DataClassYAMLMixin):
    """Shows the status of a capability. Empty status indicates no error."""

    id: CapabilityId
    statuses: list[CapabilityStatus]

    def is_available(self) -> bool:
        """Check whether the capability can currently be used.

        It looks like every status is an indication that the capability is not available.
        """
        return not self.statuses


def drop_unknown_capabilities(value: list[dict]) -> list[Capability]:
    """Drop any unknown capabilities and log a message."""
    unknown_capabilities = [c for c in value if c["id"] not in CapabilityId]
    if unknown_capabilities:
        _LOGGER.info("Dropping unknown capabilities: %s", unknown_capabilities)
    return [Capability.from_dict(c) for c in value if c["id"] in CapabilityId]


@dataclass
class Capabilities(DataClassORJSONMixin):
    """Main Model for Capabilities.

    Capabilities are Skoda software features known by the library.
    """

    capabilities: list[Capability] = field(
        metadata=field_options(deserialize=drop_unknown_capabilities)
    )
    errors: list[Error] | None = field(default=None)


@dataclass
class Battery(DataClassORJSONMixin):
    """Battery features."""

    capacity: int = field(metadata=field_options(alias="capacityInKWh"))


class BodyType(StrEnum):
    """Known car body types."""

    SUV = "SUV"
    SUV_COUPE = "SUV Coupe"
    COMBI = "Combi"
    LIFTBACK = "Liftback"
    HATCHBACK = "Hatchback"
    CROSSOVER = "Crossover"
    SPACEBACK = "Spaceback"


class VehicleState(StrEnum):
    """Main software state of the vehicle."""

    ACTIVATED = "ACTIVATED"
    GUEST_USER = "GUEST_USER"
    NOT_ACTIVATED = "NOT_ACTIVATED"
    RESET_SPIN = "RESET_SPIN"


@dataclass
class Engine(DataClassORJSONMixin):
    """Engine features."""

    power: int = field(metadata=field_options(alias="powerInKW"))
    type: str | None = field(default=None)
    capacity_in_liters: float | None = field(
        default=None, metadata=field_options(alias="capacityInLiters")
    )


@dataclass
class Gearbox(DataClassORJSONMixin):
    """Gearbox features."""

    type: str


@dataclass
class Specification(DataClassORJSONMixin):
    """Car specification. Model for the physical features of the car."""

    body: BodyType
    engine: Engine
    model: str
    title: str
    manufacturing_date: date = field(metadata=field_options(alias="manufacturingDate"))
    model_year: str = field(metadata=field_options(alias="modelYear"))
    system_code: str = field(metadata=field_options(alias="systemCode"))
    system_model_id: str = field(metadata=field_options(alias="systemModelId"))
    battery: Battery | None = field(default=None)
    max_charging_power: int | None = field(
        default=None, metadata=field_options(alias="maxChargingPowerInKW")
    )
    trim_level: str | None = field(default=None, metadata=field_options(alias="trimLevel"))


@dataclass
class ServicePartner(DataClassORJSONMixin):
    """ServicePartner is a fancy name for car dealer."""

    id: str = field(metadata=field_options(alias="servicePartnerId"))


class ViewType(StrEnum):
    UNMODIFIED_EXTERIOR_SIDE = "UNMODIFIED_EXTERIOR_SIDE"
    UNMODIFIED_EXTERIOR_FRONT = "UNMODIFIED_EXTERIOR_FRONT"
    HOME = "HOME"
    CHARGING_LIGHT = "CHARGING_LIGHT"
    CHARGING_DARK = "CHARGING_DARK"
    PLUGGED_IN_DARK = "PLUGGED_IN_DARK"
    PLUGGED_IN_LIGHT = "PLUGGED_IN_LIGHT"


class RenderType(StrEnum):
    REAL = "REAL"


@dataclass
class Render(DataClassORJSONMixin):
    url: str
    type: RenderType
    order: int
    view_point: str = field(metadata=field_options(alias="viewPoint"))


@dataclass
class CompositeRender(DataClassORJSONMixin):
    layers: list[Render]
    view_type: ViewType = field(metadata=field_options(alias="viewType"))


@dataclass
class Info(BaseResponse):
    """Basic vehicle information."""

    state: VehicleState
    specification: Specification
    vin: str
    name: str
    capabilities: Capabilities
    renders: list[Render]
    device_platform: str = field(metadata=field_options(alias="devicePlatform"))
    workshop_mode_enabled: bool = field(metadata=field_options(alias="workshopModeEnabled"))
    composite_renders: list[CompositeRender] = field(
        metadata=field_options(alias="compositeRenders")
    )
    service_partner: ServicePartner | None = field(
        default=None, metadata=field_options(alias="servicePartner")
    )
    software_version: str | None = field(
        default=None, metadata=field_options(alias="softwareVersion")
    )
    license_plate: str | None = field(default=None, metadata=field_options(alias="licensePlate"))
    errors: list[Error] | None = field(default=None)

    def has_capability(self, cap: CapabilityId) -> bool:
        """Check for a capability.

        Checks whether a vehicle generally has a capability.
        Does not check whether it's actually available.
        """
        return any(capability.id == cap for capability in self.capabilities.capabilities)

    def is_capability_available(self, cap: CapabilityId) -> bool:
        """Check for capability availability.

        Checks whether the vehicle has the capability and whether it is currently
        available. A capability can be unavailable for example if it's deactivated
        by the currently active user.
        """
        return any(
            capability.id == cap and capability.is_available()
            for capability in self.capabilities.capabilities
        )

    def get_model_name(self) -> str:
        """Return the name of the vehicle's model."""
        model = self.specification.model
        engine = self.specification.engine
        model_year = self.specification.model_year
        system_model_id = self.specification.system_model_id
        return f"{model} {engine} {model_year} ({system_model_id})"

"""Models for responses of api/v2/vehicle-status/{vin}."""

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from .common import BaseResponse


class VehicleType(StrEnum):
    FUEL = "FUEL"
    HYBRID = "HYBRID"
    ELECTRIC = "ELECTRIC"
    GAS = "GAS"


@dataclass
class StatisticsEntry(DataClassORJSONMixin):
    date: date
    average_fuel_consumption: float | None = field(
        default=None, metadata=field_options(alias="averageFuelConsumption")
    )
    average_gas_consumption: float | None = field(
        default=None, metadata=field_options(alias="averageGasConsumption")
    )
    average_speed_in_kmph: int | None = field(
        default=None, metadata=field_options(alias="averageSpeedInKmph")
    )
    average_electric_consumption: float | None = field(
        default=None, metadata=field_options(alias="averageElectricConsumption")
    )
    average_recuperation: float | None = field(
        default=None, metadata=field_options(alias="averageRecuperation")
    )
    average_aux_consumption: float | None = field(
        default=None, metadata=field_options(alias="averageAuxConsumption")
    )
    mileage_in_km: int | None = field(default=None, metadata=field_options(alias="mileageInKm"))
    travel_time_in_min: int | None = field(
        default=None, metadata=field_options(alias="travelTimeInMin")
    )
    trip_ids: list[int] | None = field(default=None, metadata=field_options(alias="tripIds"))


@dataclass
class TripStatistics(BaseResponse):
    vehicle_type: VehicleType = field(metadata=field_options(alias="vehicleType"))
    detailed_statistics: list[StatisticsEntry] = field(
        metadata=field_options(alias="detailedStatistics")
    )
    overall_average_electric_consumption: float | None = field(
        default=None, metadata=field_options(alias="overallAverageElectricConsumption")
    )
    overall_average_fuel_consumption: float | None = field(
        default=None, metadata=field_options(alias="overallAverageFuelConsumption")
    )
    overall_average_gas_consumption: float | None = field(
        default=None, metadata=field_options(alias="overallAverageGasConsumption")
    )
    overall_average_mileage_in_km: int | None = field(
        default=None, metadata=field_options(alias="overallAverageMileageInKm")
    )
    overall_average_speed_in_kmph: int | None = field(
        default=None, metadata=field_options(alias="overallAverageSpeedInKmph")
    )
    overall_average_travel_time_in_min: int | None = field(
        default=None, metadata=field_options(alias="overallAverageTravelTimeInMin")
    )
    overall_mileage_in_km: int | None = field(
        default=None, metadata=field_options(alias="overallMileageInKm")
    )
    overall_travel_time_in_min: int | None = field(
        default=None, metadata=field_options(alias="overallTravelTimeInMin")
    )


@dataclass
class FuelCost(DataClassORJSONMixin):
    cost: float | None = field(default=None, metadata=field_options(alias="cost"))
    cost_currency: str | None = field(default=None, metadata=field_options(alias="costCurrency"))
    price_per_unit: float | None = field(default=None, metadata=field_options(alias="pricePerUnit"))


@dataclass
class OverallCost(DataClassORJSONMixin):
    total_cost: float | None = field(default=None, metadata=field_options(alias="totalCost"))
    total_cost_currency: str | None = field(
        default=None, metadata=field_options(alias="totalCostCurrency")
    )
    fuel_cost: FuelCost | None = field(default=None, metadata=field_options(alias="fuelCost"))


@dataclass
class Trip(DataClassORJSONMixin):
    id: str | None = field(default=None, metadata=field_options(alias="id"))
    end_time: str | None = field(default=None, metadata=field_options(alias="endTime"))
    start_mileage_in_km: int | None = field(
        default=None, metadata=field_options(alias="startMileageInKm")
    )
    end_mileage_in_km: int | None = field(
        default=None, metadata=field_options(alias="endMileageInKm")
    )
    mileage_in_km: int | None = field(default=None, metadata=field_options(alias="mileageInKm"))
    travel_time_in_min: int | None = field(
        default=None, metadata=field_options(alias="travelTimeInMin")
    )
    average_speed_in_kmph: int | None = field(
        default=None, metadata=field_options(alias="averageSpeedInKmph")
    )
    average_fuel_consumption: float | None = field(
        default=None, metadata=field_options(alias="averageFuelConsumption")
    )
    cost: OverallCost | None = field(default=None, metadata=field_options(alias="cost"))


@dataclass
class DailyTrip(DataClassORJSONMixin):
    date: str
    overall_mileage: int | None = field(
        default=None, metadata=field_options(alias="overallMileage")
    )
    overall_cost: OverallCost | None = field(
        default=None, metadata=field_options(alias="overallCost")
    )
    trips: list[Trip] | None = field(default=None, metadata=field_options(alias="trips"))


@dataclass
class SingleTrips(BaseResponse):
    daily_trips: list[DailyTrip] = field(metadata=field_options(alias="dailyTrips"))
    vehicle_type: VehicleType | None = field(
        default=None, metadata=field_options(alias="vehicleType")
    )


# Fetching data

After initializing ([see basic example](#basic-example)), it is possible to fetch data directly from the `MySkoda` object.
Simply call and await the getter for whatever data is needed.

## Info

This endpoint contains static information about the vehicle, such as the engine type, the model and model year, settings and other things that seldomly change.

```python
from myskoda.models.info import Info

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
info = await myskoda.get_info(vin)
print(f"Vehicle is a {info.get_model_name()}.")
```

## Charging

Charging related information such as current battery soc and so on. 

```python
from myskoda.models.charging import Charging

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
charging: Charging = await myskoda.get_charging(vin)
soc = charging.status.battery.state_of_charge_in_percent
print(f"Vehicle is {soc}% charged.")
```

## Status

All temporary status information for a vehicle, such as whether it is locked or opened, the lights are on and therelike.

```python
from myskoda.models.status import Status
from myskoda.models.common import DoorLockedState

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
status: Status = await myskoda.get_status(vin)
if status.overall.doors_locked == DoorLockedState.UNLOCKED:
    print("Vehicle is not locked.")
```

## Air Conditioning

Provides information about air conditioning and window heating.

```python
from myskoda.models.air_conditioning import AirConditioning, AirConditioningState

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
air_conditioning: AirConditioning = await myskoda.get_air_conditioning(vin)
print(air_conditioning.state == AirConditioningState.ON)
```

## Positions

List of positions related to the car.

Each `Position` has a type which further describes it.
The vehicle's current position has type `PositionType.VEHICLE`.

```python
from myskoda.models.positions import PositionType

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
positions: Positions = await myskoda.get_positions(vin)
pos = next(pos for pos in self._positions().positions if pos.type == PositionType.VEHICLE)
print(f"lat: {pos.gps_coordinates.latitude}, lng: {pos.gps_coordinates.longitude}")
```

## Driving Range

Information about the vehicle's driving range, such as the range in km until the car needs to be fueled or charged.

```python
from myskoda.models.driving_range import DrivingRange

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
driving_range: DrivingRange = await myskoda.get_driving_range(vin)
print(f"Range: {driving_range.total_range_in_km}km")
```

## Trip Statistics

Information about past trips, as statistical overview.

```python
from myskoda.models.trip_statistics import TripStatistics

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
trip_statistics: TripStatistics = await myskoda.get_trip_statistics(vin)
for entry in tripstatistics.detailed_statistics:
    print(f"{entry.date}: {entry.milage_in_km}km")
```

## Single Trip Statistics

Information about recent individual trips grouped by day.

```python
from myskoda.models.trip_statistics import SingleTrips

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
single_trips: SingleTrips = await myskoda.get_single_trip_statistics(vin)
if single_trips.daily_trips and single_trips.daily_trips[0].trips:
    last_trip = single_trips.daily_trips[0].trips[0]
    print(f"Last trip mileage: {last_trip.mileage_in_km}km")
```

## Maintenance

Maintenance information about the car, such as the total mileage or next scheduled maintenance.

```python
from myskoda.models.maintenance import Maintenance

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
maintenance: Maintenance = await myskoda.get_maintenance(vin)
print(f"Inspection due in {maintenance.maintenance_report.inspection_due_in_days} days")
```

## Health

This endpoint returns information about the healths status and problems with the vehicle,
such as the active warning light indicators and total mileage.

```python
from myskoda.models.health import Health

vin = "TMBJB9NY6RF999999" # See `MySkoda.list_vehicle_vins()`.
health: Health = await myskoda.get_health(vin)
print(f"Mileage: {health.mileage_in_km}km")
```

## User

Information about the logged-in user account.

```python
from myskoda.models.user import User

user: User = await myskoda.get_user()
print(f"User id: {user.id}")
```

## Listing Vehicles

Information about the logged-in user account.

```python
from myskoda.models.user import User

user: User = await myskoda.get_user()
print(f"User id: {user.id}")
```
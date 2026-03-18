
# Refreshing data

New in `v1.0.0`.

The `get_*()` methods (see [fetching data](fetching_data.md)) will always fetch new data from the Skoda API and return it.

MySkoda also provides `refresh_*()` methods. These methods:
- Are automatically debounced every 10 seconds. This means the first call will execute immediatally but subsequent calls within 10 seconds will only execute once after those 10 seconds.
- Do not return anything. Instead they will trigger a callback after the request data has been refreshing.
- Callbacks can be registered with the `subscribe_updates()` method.

## Subscribing callbacks

Update callback functions are registered for a specific vehicle VIN and are called with no arguments. The updated vehicle data can be obtained with the `vehicle()` method.

```python
VIN = "YOUR_VIN"

async def on_myskoda_update():
    latest = myskoda.vehicle(VIN)
    print(f"Latest data for {VIN}: {latest})

myskoda = MySkoda(session)
myskoda.subscribe_updates(VIN, on_myskoda_update)
```

## Requesting data refresh

The `get_*()` methods have a matching `refresh_*()` method, taking only the vehicle VIN as an argument.

```python
VIN = "YOUR_VIN"

myskoda = MySkoda(session)

# Refresh all vehicle data
myskoda.refresh_vehicle(VIN)

# Refresh only charging data
myskoda.refresh_charging(VIN)
```

## Update callbacks and MQTT events

MQTT events can be subscribed to separately (see [Events](events.md)). Some events will cause MySkoda to automatically update its local vehicle data. This will also result in any subscribe *update* callbacks to be called.

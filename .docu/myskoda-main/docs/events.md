# Events

After initializing ([see basic example](#basic-example)), it is possible to subscribe to events for a specific vehicle by providing a callback function.

Internally, MySkoda will always connect to all MQTT topics that it can subscribe to, after loading a list of all vehicle identification numbers.

## Subscribing to Events

**NOTE**: in `v1.0.0` the `subscribe()` method has been renamed to `subscribe_events()`.

```python
from myskoda.event import Event

def on_event(event: Event):
    pass

myskoda.subscribe_event(on_event)
```

The suggested approach is to check the event's `event_type` field to see what it contains. If you're using mypy or pyright, this will also narrow down the event's type and allow you to access specific fields:

```python
from myskoda.event import Event, EventType, ServiceEventTopic

def on_event(event: Event):
    if event.event_type == EventType.SERVICE_EVENT:
        print("Received service event.")
        if event.topic == ServiceEventTopic.CHARGING:
            print(f"Battery is {event.event.data.soc}% charged.")
```

There is four types of events:

* `EventType.SERVICE_EVENT`: Sent proactively by the vehicle, when something changed.
* `EventType.OPERATION`: Sent by Skoda's server as response to an operation executed on the vehicle. It will track the operation's status.
* `EventType.ACCOUNT_EVENT`
* `EventType.VEHICLE_EVENT`: Sent proactively by the vehicle, when something changed.

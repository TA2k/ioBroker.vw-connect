# Primer

MySkoda relies on two ways to connect to the Skoda servers:

* **MQTT** (For realtime information and for checking whether operations were performed by the car.)
* **HTTP Api** (For retrieving detailed information and initiating operations.)

## Performing Operations

Every operation is executed the following way:

1. An HTTP request to the MySkoda servers is executed, initiating the desired operation (e.g. starting window heating)
2. The HTTP request will immediately return status 200, no matter whether it is successful or not.
3. An MQTT message with an `OperationRequest` is is published. It will be status `IN_PROGRESS`.
4. At some point, the vehicle will pick up the operation and perform it.
5. An MQTT message with an `OperationRequest` and status `COMPLETED_SUCCESS` will be published.
6. The operation is completed.

## Subscribing to Events

The vehicle will proactively send `ServiceEvent` messages to the MQTT broker. These events are very generic and most of them contain no meaningful data or information about what exactly happened.

When a message with `ServiceEvent` is received, detailed information can be gathered from the Rest API.
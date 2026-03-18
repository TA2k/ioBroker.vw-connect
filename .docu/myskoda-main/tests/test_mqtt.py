"""Unit tests for MQTT."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import ANY

import aiomqtt
import pytest

from myskoda.anonymize import USER_ID, VIN
from myskoda.models.charging import ChargeMode, ChargingState
from myskoda.models.event import (
    BaseEvent,
    EventType,
    OperationEvent,
    OperationName,
    OperationStatus,
    ServiceEventChangeAccess,
    ServiceEventChangeLights,
    ServiceEventChangeOdometer,
    ServiceEventChangeSoc,
    ServiceEventChangeSocData,
    ServiceEventChargingCompleted,
    ServiceEventData,
    ServiceEventName,
    VehicleEventAwake,
    VehicleEventConnectionOffline,
    VehicleEventConnectionOnline,
    VehicleEventData,
    VehicleEventIgnitionStatusChanged,
    VehicleEventName,
    VehicleEventVehicleIgnitionStatusData,
    VehicleEventWarningBatterylevel,
)
from myskoda.models.vehicle_ignition_status import IgnitionStatus
from myskoda.mqtt import MySkodaMqttClient

from .conftest import FakeMqttClientWrapper

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
async def connected_mqtt_client(myskoda_mqtt_client: MySkodaMqttClient) -> MySkodaMqttClient:
    """Return a connected MySkodaMqttClient instance to use in tests."""
    await myskoda_mqtt_client.connect(user_id="1234", vehicle_vins=["TMOCKAA0AA000000"])
    return myskoda_mqtt_client


@pytest.mark.asyncio
async def test_wait_for_operation(
    connected_mqtt_client: MySkodaMqttClient, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    topic = f"{USER_ID}/{VIN}/operation-request/air-conditioning/start-stop-air-conditioning"
    future = connected_mqtt_client.wait_for_operation(OperationName.START_AIR_CONDITIONING)

    assert future.done() is False

    in_progress = json2mqtt(
        {
            "version": 1,
            "operation": "start-air-conditioning",
            "status": "IN_PROGRESS",
            "traceId": "f0b638f7bba08ec4acb5de64cdb97ba9",
            "requestId": "72f24950-b3db-4b7e-948f-7032f533773a",
        }
    )
    complete = json2mqtt(
        {
            "version": 1,
            "operation": "start-air-conditioning",
            "status": "COMPLETED_SUCCESS",
            "traceId": "10d37beb6b37e9a9e74460d402855f27",
            "requestId": "72f24950-b3db-4b7e-948f-7032f533773a",
        }
    )
    fake_mqtt_client_wrapper.set_messages(
        [
            aiomqtt.Message(
                topic=topic, payload=in_progress, qos=1, retain=False, mid=1, properties=None
            ),
            aiomqtt.Message(
                topic=topic, payload=complete, qos=1, retain=False, mid=1, properties=None
            ),
        ]
    )

    await future


def json2mqtt(data: dict) -> bytes:
    """Convert plain json to passable format for aiomqtt."""
    return json.dumps(data).encode()


@pytest.mark.asyncio
async def test_subscribe_event(
    connected_mqtt_client: MySkodaMqttClient, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> None:
    base_topic = f"{USER_ID}/{VIN}"
    trace_id = "7a59299d06535a6756d10e96e0c75ed3"
    request_id = "b9bc1258-2d0c-43c2-8d67-44d9f6c8cb9f"
    timestamp_str = "2024-10-17T08:49:59.538Z"
    timestamp = datetime.fromisoformat(timestamp_str)

    events: list[BaseEvent] = []
    future = asyncio.get_event_loop().create_future()

    messages = [
        aiomqtt.Message(
            topic=f"{base_topic}/operation-request/air-conditioning/start-stop-air-conditioning",
            payload=json2mqtt(
                {
                    "version": 1,
                    "operation": "stop-air-conditioning",
                    "status": "COMPLETED_SUCCESS",
                    "traceId": trace_id,
                    "requestId": request_id,
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/service-event/vehicle-status/lights",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "change-lights",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/service-event/vehicle-status/odometer",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "change-odometer",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/service-event/vehicle-status/access",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "change-access",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/service-event/charging",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "change-soc",
                    "data": {
                        "mode": "manual",
                        "state": "charging",
                        "soc": "91",
                        "chargedRange": "307",
                        "timeToFinish": "40",
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/service-event/charging",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "charging-completed",
                    "data": {
                        "mode": "manual",
                        "state": "chargePurposeReachedAndConservation",
                        "soc": "100",
                        "chargedRange": "500",
                        "timeToFinish": "0",
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/service-event/charging",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "charging-completed",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/vehicle-event/vehicle-connection-status-update",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "vehicle-connection-online",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/vehicle-event/vehicle-connection-status-update",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "vehicle-connection-offline",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/vehicle-event/vehicle-connection-status-update",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "vehicle-awake",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/vehicle-event/vehicle-connection-status-update",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "vehicle-warning-batterylevel",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/vehicle-event/vehicle-ignition-status",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "vehicle-ignition-status-changed",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                        "ignitionStatus": IgnitionStatus.ON,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
        aiomqtt.Message(
            topic=f"{base_topic}/vehicle-event/vehicle-ignition-status",
            payload=json2mqtt(
                {
                    "version": 1,
                    "traceId": trace_id,
                    "timestamp": timestamp_str,
                    "producer": "SKODA_MHUB",
                    "name": "vehicle-ignition-status-changed",
                    "data": {
                        "userId": USER_ID,
                        "vin": VIN,
                        "ignitionStatus": IgnitionStatus.OFF,
                    },
                }
            ),
            qos=1,
            retain=False,
            mid=1,
            properties=None,
        ),
    ]

    async def on_event(event: BaseEvent) -> None:
        events.append(event)
        if len(events) == len(messages):
            future.set_result(None)

    connected_mqtt_client.subscribe(on_event)

    # @dvx76: not sure why messages get received/send in reverse order ...
    fake_mqtt_client_wrapper.set_messages(list(reversed(messages)))

    await future

    assert events == [
        OperationEvent(
            vin=VIN,
            event_type=EventType.OPERATION,
            timestamp=ANY,
            version=1,
            operation=OperationName.STOP_AIR_CONDITIONING,
            trace_id=trace_id,
            request_id=request_id,
            status=OperationStatus.COMPLETED_SUCCESS,
            error_code=None,
        ),
        ServiceEventChangeLights(
            vin=VIN,
            event_type=EventType.SERVICE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=ServiceEventName.CHANGE_LIGHTS,
            data=ServiceEventData(user_id=USER_ID, vin=VIN),
        ),
        ServiceEventChangeOdometer(
            vin=VIN,
            event_type=EventType.SERVICE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=ServiceEventName.CHANGE_ODOMETER,
            data=ServiceEventData(user_id=USER_ID, vin=VIN),
        ),
        ServiceEventChangeAccess(
            vin=VIN,
            event_type=EventType.SERVICE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=ServiceEventName.CHANGE_ACCESS,
            data=ServiceEventData(user_id=USER_ID, vin=VIN),
        ),
        ServiceEventChangeSoc(
            vin=VIN,
            event_type=EventType.SERVICE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=ServiceEventName.CHANGE_SOC,
            data=ServiceEventChangeSocData(
                user_id=USER_ID,
                vin=VIN,
                charged_range=307,
                soc=91,
                state=ChargingState.CHARGING,
                mode=ChargeMode.MANUAL,
                time_to_finish=40,
            ),
        ),
        ServiceEventChargingCompleted(
            vin=VIN,
            event_type=EventType.SERVICE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=ServiceEventName.CHARGING_COMPLETED,
            data=ServiceEventChangeSocData(
                user_id=USER_ID,
                vin=VIN,
                charged_range=500,
                soc=100,
                state=ChargingState.CONSERVING,
                mode=ChargeMode.MANUAL,
                time_to_finish=0,
            ),
        ),
        ServiceEventChargingCompleted(
            vin=VIN,
            event_type=EventType.SERVICE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=ServiceEventName.CHARGING_COMPLETED,
            data=ServiceEventChangeSocData(
                user_id=USER_ID,
                vin=VIN,
                mode=None,
                state=None,
                soc=None,
                charged_range=None,
                time_to_finish=None,
            ),
        ),
        VehicleEventConnectionOnline(
            vin=VIN,
            event_type=EventType.VEHICLE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=VehicleEventName.VEHICLE_CONNECTION_ONLINE,
            data=VehicleEventData(user_id=USER_ID, vin=VIN),
        ),
        VehicleEventConnectionOffline(
            vin=VIN,
            event_type=EventType.VEHICLE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=VehicleEventName.VEHICLE_CONNECTION_OFFLINE,
            data=VehicleEventData(user_id=USER_ID, vin=VIN),
        ),
        VehicleEventAwake(
            vin=VIN,
            event_type=EventType.VEHICLE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=VehicleEventName.VEHICLE_AWAKE,
            data=VehicleEventData(user_id=USER_ID, vin=VIN),
        ),
        VehicleEventWarningBatterylevel(
            vin=VIN,
            event_type=EventType.VEHICLE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=VehicleEventName.VEHICLE_WARNING_BATTEYLEVEL,
            data=VehicleEventData(user_id=USER_ID, vin=VIN),
        ),
        VehicleEventIgnitionStatusChanged(
            vin=VIN,
            event_type=EventType.VEHICLE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=VehicleEventName.VEHICLE_IGNITION_STATUS_CHANGED,
            data=VehicleEventVehicleIgnitionStatusData(
                user_id=USER_ID, vin=VIN, ignition_status=IgnitionStatus.ON
            ),
        ),
        VehicleEventIgnitionStatusChanged(
            vin=VIN,
            event_type=EventType.VEHICLE_EVENT,
            version=1,
            trace_id=trace_id,
            timestamp=timestamp,
            producer="SKODA_MHUB",
            name=VehicleEventName.VEHICLE_IGNITION_STATUS_CHANGED,
            data=VehicleEventVehicleIgnitionStatusData(
                user_id=USER_ID, vin=VIN, ignition_status=IgnitionStatus.OFF
            ),
        ),
    ]

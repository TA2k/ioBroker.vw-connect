"""MQTT client module for the MySkoda server.

Inspired by https://github.com/YoSmart-Inc/yolink-api/tree/main
"""

import asyncio
import logging
import re
import ssl
import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from random import uniform
from types import TracebackType
from typing import Any, Protocol, Self, cast

import aiomqtt

from .auth.authorization import Authorization
from .const import (
    MQTT_ACCOUNT_EVENT_TOPICS,
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_FAST_RETRY,
    MQTT_KEEPALIVE,
    MQTT_MAX_RECONNECT_DELAY,
    MQTT_OPERATION_TOPICS,
    MQTT_RECONNECT_DELAY,
    MQTT_SERVICE_EVENT_TOPICS,
    MQTT_VEHICLE_EVENT_TOPICS,
)
from .models.event import BaseEvent, OperationEvent, OperationName, OperationStatus

_LOGGER = logging.getLogger(__name__)
TOPIC_RE = re.compile("^(.*?)/(.*?)/(.*?)/(.*?)$")
APP_UUID = uuid.uuid4()


def _create_ssl_context() -> ssl.SSLContext:
    """Create a SSL context for the MQTT connection."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    return context


_SSL_CONTEXT = _create_ssl_context()

background_tasks = set()


class OperationListener:
    """Used to track callbacks to execute for a given OperationName."""

    operation_name: OperationName
    future: asyncio.Future[OperationEvent]

    def __init__(
        self, operation_name: OperationName, future: asyncio.Future[OperationEvent]
    ) -> None:
        self.operation_name = operation_name
        self.future = future


class OperationFailedError(Exception):  # pragma: no cover
    def __init__(self, event: OperationEvent) -> None:
        op = event.operation
        error = event.error_code
        trace = event.trace_id
        super().__init__(f"Operation {op} with trace {trace} failed: {error}")


class AbstractMqttClientWrapper(Protocol):
    """Interface for an aiomqtt.Client wrapper.

    We're using an interface so we can pass in a fake wrapper in tests.
    We're wrapping (technically subclassing) so we can add a clean public update_username_password
    method.
    """

    async def __aenter__(self) -> Self: ...  # noqa: D105

    async def __aexit__(  # noqa: D105
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    @property
    def messages(self) -> AsyncIterator: ...  # noqa: D102

    async def subscribe(self, topic: str) -> None: ...  # noqa: D102

    def update_username_password(self, username: str, password: str) -> None: ...  # noqa: D102


class AioMqttClientWrapper(aiomqtt.Client):
    def update_username_password(self, username: str, password: str) -> None:
        """Update the username and password set in an aiomqtt.Client object.

        This isn't super clean since _client is a private member but it's just an instance of
        paho.mqtt.Client so unlikely to change.

        We want the ability to update the username/pw so that MySkodaMqttClient can instantiate
        this in its __init__ but defer setting the username/pw.
        """
        self._client.username_pw_set(username=username, password=password)


class MySkodaMqttClient:
    user_id: str | None
    vehicle_vins: list[str]
    _callbacks: list[Callable[[BaseEvent], Coroutine[Any, Any, None]]]
    _operation_listeners: list[OperationListener]

    def __init__(
        self,
        authorization: Authorization,
        mqtt_client: AbstractMqttClientWrapper | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.authorization = authorization
        self.vehicle_vins = []
        self.mqtt_client = mqtt_client
        if self.mqtt_client is None:
            # Pass in pre-created SSLContext (vs 'tls_params=aiomqtt.TLSParameters()') to avoid a
            # blocking call in paho.mqtt.client. See https://github.com/w1ll1am23/pyeconet/pull/43.
            self.mqtt_client = AioMqttClientWrapper(
                hostname=MQTT_BROKER_HOST,
                port=MQTT_BROKER_PORT,
                identifier="Id" + str(APP_UUID) + "#" + str(uuid.uuid4()),
                logger=_LOGGER,
                tls_context=ssl_context or _SSL_CONTEXT,
                keepalive=MQTT_KEEPALIVE,
                clean_session=True,
            )
        self._callbacks = []
        self._operation_listeners = []
        self._listener_task = None
        self._running = False
        self._subscribed = asyncio.Event()
        self._reconnect_delay = MQTT_RECONNECT_DELAY

    async def connect(self, user_id: str, vehicle_vins: list[str]) -> None:
        """Connect to the MQTT broker and listen for messages for the given user_id and VINs."""
        _LOGGER.info("Connecting to MQTT with %s/%s", user_id, vehicle_vins)
        self.user_id = user_id
        self.vehicle_vins = vehicle_vins
        self._listener_task = asyncio.create_task(self._connect_and_listen())
        await self._subscribed.wait()

    async def disconnect(self) -> None:
        """Cancel listener task and set self_running to False, causing the listen loop to end."""
        if self._listener_task is None:
            return
        self._listener_task.cancel()
        self._listener_task = None
        self._running = False

    def subscribe(self, callback: Callable[[BaseEvent], Coroutine[Any, Any, None]]) -> None:
        """Listen for events emitted by MySkoda's MQTT broker."""
        self._callbacks.append(callback)

    def wait_for_operation(self, operation_name: OperationName) -> asyncio.Future[OperationEvent]:
        """Wait until the next operation of the specified type completes."""
        _LOGGER.debug("Waiting for operation %s complete.", operation_name)
        future: asyncio.Future[OperationEvent] = asyncio.get_event_loop().create_future()

        self._operation_listeners.append(OperationListener(operation_name, future))

        return future

    async def _connect_and_listen(self) -> None:
        """Connect to the MQTT broker and listen for messages for the given user_id and VINs.

        Reconnect loop based on https://github.com/empicano/aiomqtt/blob/main/docs/reconnection.md.

        Re-fetch and update the authorization token on every try.
        """
        _LOGGER.debug("Starting _connect_and_listen")
        self._running = True
        retry_count = 0  # Track the number of retries
        self._reconnect_delay = MQTT_RECONNECT_DELAY  # Initial delay for backoff
        while self._running:
            try:
                assert self.mqtt_client is not None
                password = await self.authorization.get_access_token()
                self.mqtt_client.update_username_password(username="android-app", password=password)
                async with self.mqtt_client as client:
                    _LOGGER.info("Connected to MQTT")
                    _LOGGER.debug("using MQTT client %s", client)
                    for vin in self.vehicle_vins:
                        for topic in MQTT_OPERATION_TOPICS:
                            await client.subscribe(
                                f"{self.user_id}/{vin}/operation-request/{topic}"
                            )
                        for topic in MQTT_SERVICE_EVENT_TOPICS:
                            await client.subscribe(f"{self.user_id}/{vin}/service-event/{topic}")
                        for topic in MQTT_ACCOUNT_EVENT_TOPICS:
                            await client.subscribe(f"{self.user_id}/{vin}/account-event/{topic}")
                        for topic in MQTT_VEHICLE_EVENT_TOPICS:
                            await client.subscribe(f"{self.user_id}/{vin}/vehicle-event/{topic}")

                    self._subscribed.set()
                    self._reconnect_delay = MQTT_RECONNECT_DELAY
                    retry_count = 0  # Reset retry count on successful connection
                    async for message in client.messages:
                        self._on_message(message)
            except aiomqtt.MqttError as exc:
                retry_count += 1
                _LOGGER.info(
                    "Connection lost (%s); reconnecting in %ss", exc, self._reconnect_delay
                )
                await asyncio.sleep(self._reconnect_delay)
                if (
                    retry_count > MQTT_FAST_RETRY
                    and self._reconnect_delay < MQTT_MAX_RECONNECT_DELAY
                ):  # first x retries are not exponential
                    self._reconnect_delay *= 2
                    self._reconnect_delay += uniform(0, 1)  # noqa: S311
                    self._reconnect_delay = min(self._reconnect_delay, MQTT_MAX_RECONNECT_DELAY)
                    _LOGGER.debug("Increased reconnect backoff to %s", self._reconnect_delay)

    def _on_message(self, msg: aiomqtt.Message) -> None:
        """Deserialize received MQTT message and emit Event to subscribed callbacks."""
        # Cast the data from binary string, ignoring empty messages.
        payload = cast("str", msg.payload)
        if len(payload) == 0:
            return

        topic = str(msg.topic)

        _LOGGER.debug("Message received on topic %s: %s", topic, payload)

        try:
            self._emit(BaseEvent.from_mqtt_message(topic=topic, payload=payload))
        except Exception as exc:  # noqa: BLE001  pragma: no cover
            _LOGGER.warning("Exception parsing MQTT event: %s", exc)

    def _emit(self, event: BaseEvent) -> None:
        for callback in self._callbacks:
            result = callback(event)
            if result is not None:
                task = asyncio.create_task(result)
                background_tasks.add(task)
                task.add_done_callback(background_tasks.discard)

        if isinstance(event, OperationEvent):
            self._handle_operation(event)

    def _handle_operation(self, event: OperationEvent) -> None:
        if event.status == OperationStatus.IN_PROGRESS:
            _LOGGER.debug(
                "An operation '%s' is now in progress. Trace id: %s",
                event.operation,
                event.trace_id,
            )
            return

        _LOGGER.debug(
            "Operation '%s' for trace id '%s' completed.",
            event.operation,
            event.trace_id,
        )
        self._handle_operation_completed(event)

    def _handle_operation_completed(self, event: OperationEvent) -> None:
        listeners = self._operation_listeners
        self._operation_listeners = []
        for listener in listeners:
            if listener.operation_name != event.operation:
                self._operation_listeners.append(listener)
                continue

            if event.status == OperationStatus.ERROR:
                _LOGGER.error(
                    "Resolving listener for operation '%s' with error '%s'.",
                    event.operation,
                    event.error_code,
                )
                listener.future.set_exception(OperationFailedError(event))
            else:
                if event.status == OperationStatus.COMPLETED_WARNING:
                    _LOGGER.warning("Operation '%s' completed with warnings.", event.operation)

                _LOGGER.debug("Resolving listener for operation '%s'.", event.operation)
                listener.future.set_result(event)

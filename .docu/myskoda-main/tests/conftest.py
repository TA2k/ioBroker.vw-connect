"""Test helpers."""

import asyncio
import copy
import json
from collections.abc import AsyncIterator, Generator
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from socket import socket
from types import TracebackType
from typing import Any
from unittest.mock import AsyncMock

import aiomqtt
import pytest
from aiohttp import ClientSession
from aioresponses import aioresponses

from myskoda.anonymize import ACCESS_TOKEN
from myskoda.auth.authorization import Authorization
from myskoda.mqtt import MySkodaMqttClient
from myskoda.myskoda import MySkoda, MySkodaAuthorization
from myskoda.rest_api import RestApi

FIXTURES_DIR = Path(__file__).parent / "fixtures"
TRACE_ID = "7a59299d06535a6756d10e96e0c75ed3"
REQUEST_ID = "b9bc1258-2d0c-43c2-8d67-44d9f6c8cb9f"


class FakeAuthorization(Authorization):
    @property
    def client_id(self) -> str | None:
        return "1"

    @property
    def redirect_uri(self) -> str | None:
        return "https://fake/auth/redirect"

    @property
    def base_url(self) -> str | None:
        return "https://fake/auth"

    async def get_access_token(self) -> str:
        return "access_token"


class SimpleAsyncIterator:
    """A simple AsyncIterator which returns any type of items.

    Items can be set in __init__ or later added with the items property.
    """

    def __init__(self, items: list[Any]) -> None:
        self._new_items_available = asyncio.Event()
        self._items = []
        if items:
            self.items = items

    def __aiter__(self):  # noqa: ANN204
        return self

    @property
    def items(self) -> list[Any]:
        return self._items

    @items.setter
    def items(self, value: list[Any]) -> None:
        self._items = copy.deepcopy(value)  # copy to avoid popping of the passed value
        self._new_items_available.set()

    async def __anext__(self):  # noqa: ANN204
        """Block until (new) items are available."""
        await self._new_items_available.wait()
        next_item = self._items.pop()
        if not self._items:
            self._new_items_available.clear()
        return next_item


class FakeMqttClientWrapper(AbstractAsyncContextManager):
    """Fake aiomqtt.Client wrapper to use in tests.

    Can be initiatlized with a list of aiomqtt.Message's which will be available immediatally.
    Additional messages can be injected later using set_messages().
    """

    def __init__(self, messages: list[aiomqtt.Message]) -> None:
        self._aiter = SimpleAsyncIterator(messages)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        pass

    def set_messages(self, messages: list[aiomqtt.Message]) -> None:
        self._aiter.items = messages

    @property
    def messages(self) -> AsyncIterator:
        return self._aiter

    async def subscribe(self, topic: str) -> None:
        print(f"Fake subscribed to topic {topic}")

    def update_username_password(self, username: str, password: str) -> None:
        print(f"Fake updated username/password as {username}/{password}")


@pytest.fixture
async def fake_authorization() -> FakeAuthorization:
    """Return a fake Authorization instance."""
    async with ClientSession() as session:
        return FakeAuthorization(session)


@pytest.fixture
def fake_mqtt_client_wrapper() -> FakeMqttClientWrapper:
    """Return a fake AbstractMqttClientWrapper instance."""
    return FakeMqttClientWrapper(messages=[])


@pytest.fixture
async def myskoda_mqtt_client(
    fake_authorization: FakeAuthorization, fake_mqtt_client_wrapper: FakeMqttClientWrapper
) -> AsyncIterator[MySkodaMqttClient]:
    """Return a MySkodaMqttClient instance to use in tests."""
    mqtt_client = MySkodaMqttClient(
        authorization=fake_authorization, mqtt_client=fake_mqtt_client_wrapper
    )
    yield mqtt_client
    await mqtt_client.disconnect()


@pytest.fixture
def responses() -> Generator[aioresponses]:
    """Return aioresponses fixture."""
    with aioresponses() as mocked_responses:
        yield mocked_responses


@pytest.fixture
async def api() -> AsyncIterator[RestApi]:
    """Return rest api."""
    async with ClientSession() as session:
        authorization = MySkodaAuthorization(session)
        api = RestApi(session, authorization)
        api.authorization.get_access_token = AsyncMock()
        yield api


def random_port() -> int:
    with socket() as sock:
        sock.bind(("", 0))
        return sock.getsockname()[1]


def mock_default_routes(responses: aioresponses) -> None:
    responses.get(
        url="https://mysmob.api.connect.skoda-auto.cz/api/v1/users",
        body=(FIXTURES_DIR / "mqtt" / "user.json").read_text(),
    )
    responses.get(
        url="https://mysmob.api.connect.skoda-auto.cz/api/v2/garage?connectivityGenerations=MOD1&connectivityGenerations=MOD2&connectivityGenerations=MOD3&connectivityGenerations=MOD4",
        body=(FIXTURES_DIR / "mqtt" / "vehicles.json").read_text(),
    )


@pytest.fixture
async def myskoda(
    responses: aioresponses, myskoda_mqtt_client: MySkodaMqttClient
) -> AsyncIterator[MySkoda]:
    """Return rest api."""
    async with ClientSession() as session:
        mock_default_routes(responses)
        myskoda = MySkoda(session, mqtt_enabled=False)
        myskoda.mqtt = myskoda_mqtt_client
        myskoda.authorization.get_access_token = AsyncMock(return_value=ACCESS_TOKEN)
        myskoda.authorization.authorize = AsyncMock()
        await myskoda.connect("user@example.com", "password")
        yield myskoda
        await myskoda.disconnect()


def create_aiomqtt_message(topic: str, operation: str) -> aiomqtt.Message:
    payload = json.dumps(
        {
            "version": 1,
            "operation": operation,
            "status": "COMPLETED_SUCCESS",
            "traceId": TRACE_ID,
            "requestId": REQUEST_ID,
        }
    ).encode("utf-8")

    return aiomqtt.Message(
        topic=topic,
        payload=payload,
        qos=1,
        retain=False,
        mid=1,
        properties=None,
    )

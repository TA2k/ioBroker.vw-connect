"""CLI commands for dealing with MQTT."""

import asyncio
from typing import TYPE_CHECKING

import asyncclick as click
from asyncclick.core import Context
from termcolor import colored

from myskoda.cli.utils import mqtt_required
from myskoda.models.event import BaseEvent, OperationName
from myskoda.myskoda import MqttDisabledError

if TYPE_CHECKING:
    from myskoda import MySkoda


@click.command()
@click.argument("operation", type=click.Choice(OperationName))  # pyright: ignore [reportArgumentType]
@click.pass_context
@mqtt_required
async def wait_for_operation(ctx: Context, operation: OperationName) -> None:
    """Wait for the operation with the specified name to complete."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    if myskoda.mqtt is None:
        raise MqttDisabledError

    print(f"Waiting for an operation {colored(operation, 'green')} to start and complete...")

    await myskoda.mqtt.wait_for_operation(operation)
    print("Completed.")


@click.command()
@click.pass_context
@mqtt_required
async def subscribe(ctx: Context) -> None:
    """Connect to the MQTT broker and listen for messages."""
    myskoda: MySkoda = ctx.obj["myskoda"]

    async def on_event(event: BaseEvent) -> None:
        ctx.obj["print"](event.to_dict())

    myskoda.subscribe_events(on_event)
    await asyncio.Event().wait()

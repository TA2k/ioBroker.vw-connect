"""Commands for the CLI for operations that can be performed."""

import asyncio
from typing import TYPE_CHECKING

import asyncclick as click
from asyncclick.core import Context

from myskoda.cli.utils import mqtt_required

if TYPE_CHECKING:
    from myskoda import MySkoda

from myskoda.models.air_conditioning import (
    AirConditioningAtUnlock,
    AirConditioningWithoutExternalPower,
    HeaterSource,
    SeatHeating,
    TargetTemperature,
    WindowHeating,
)
from myskoda.models.auxiliary_heating import AuxiliaryConfig, AuxiliaryStartMode


@click.command()
@click.option("temperature", "--temperature", type=float, required=True)
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def start_air_conditioning(
    ctx: Context,
    temperature: float,
    timeout: float,  # noqa: ASYNC109
    vin: str,
) -> None:
    """Start the air conditioning with the provided target temperature in °C."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.start_air_conditioning(vin, temperature)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def stop_air_conditioning(ctx: Context, timeout: float, vin: str) -> None:  # noqa: ASYNC109
    """Stop the air conditioning."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.stop_air_conditioning(vin)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def start_ventilation(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
) -> None:
    """Start the ventilation."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.start_ventilation(vin)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def stop_ventilation(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
) -> None:
    """Stop the ventilation."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.stop_ventilation(vin)


@click.command()
@click.option("temperature", "--temperature", type=float, required=False)
@click.option("duration", "--duration", type=int, required=False)
@click.option(
    "mode", "--mode", type=click.Choice([e.value for e in AuxiliaryStartMode]), required=False
)
@click.option(
    "source", "--source", type=click.Choice([e.value for e in HeaterSource]), required=False
)
@click.option("spin", "--spin", type=str, required=True)
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def start_auxiliary_heating(  # noqa: PLR0913
    ctx: Context,
    spin: str,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    temperature: float | None = None,
    duration: int | None = None,
    mode: AuxiliaryStartMode | None = None,
    source: HeaterSource | None = None,
) -> None:
    """Start the auxiliary heating with the provided target temperature in °C."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    config = AuxiliaryConfig(
        target_temperature=TargetTemperature(temperature_value=temperature)
        if temperature is not None
        else None,
        duration_in_seconds=duration,
        start_mode=AuxiliaryStartMode(mode) if mode is not None else None,
        heater_source=HeaterSource(source) if source is not None else None,
    )
    async with asyncio.timeout(timeout):
        await myskoda.start_auxiliary_heating(vin, spin, config)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def stop_auxiliary_heating(ctx: Context, timeout: float, vin: str) -> None:  # noqa: ASYNC109
    """Stop the auxiliary heating."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.stop_auxiliary_heating(vin)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("temperature", "--temperature", type=float, required=True)
@click.pass_context
@mqtt_required
async def set_target_temperature(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    temperature: float,
) -> None:
    """Set the air conditioning's target temperature in °C."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_target_temperature(vin, temperature)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def start_window_heating(ctx: Context, timeout: float, vin: str) -> None:  # noqa: ASYNC109
    """Start heating both the front and rear window."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.start_window_heating(vin)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def stop_window_heating(ctx: Context, timeout: float, vin: str) -> None:  # noqa: ASYNC109
    """Stop heating both the front and rear window."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.stop_window_heating(vin)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("limit", "--limit", type=float, required=True)
@click.pass_context
@mqtt_required
async def set_charge_limit(ctx: Context, timeout: float, vin: str, limit: int) -> None:  # noqa: ASYNC109
    """Set the maximum charge limit in percent."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_charge_limit(vin, limit)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("limit", "--limit", type=float, required=True)
@click.pass_context
@mqtt_required
async def set_minimum_charge_limit(ctx: Context, timeout: float, vin: str, limit: int) -> None:  # noqa: ASYNC109
    """Set the minimum charge limit in percent."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_minimum_charge_limit(vin, limit)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("enabled", "--enabled", type=bool, required=True)
@click.pass_context
@mqtt_required
async def set_battery_care_mode(ctx: Context, timeout: float, vin: str, enabled: bool) -> None:  # noqa: ASYNC109
    """Enable or disable the battery care mode."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_battery_care_mode(vin, enabled)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("enabled", "--enabled", type=bool, required=True)
@click.pass_context
@mqtt_required
async def set_reduced_current_limit(ctx: Context, timeout: float, vin: str, enabled: bool) -> None:  # noqa: ASYNC109
    """Enable reducing the current limit by which the car is charged."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_reduced_current_limit(vin, enabled)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def wakeup(ctx: Context, timeout: float, vin: str) -> None:  # noqa: ASYNC109
    """Wake the vehicle up. Can be called maximum three times a day."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.wakeup(vin)


@click.command()
@click.option("spin", "--spin", type=str, required=True)
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def lock(
    ctx: Context,
    spin: str,
    timeout: float,  # noqa: ASYNC109
    vin: str,
) -> None:
    """Lock the car."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.lock(vin, spin)


@click.command()
@click.option("spin", "--spin", type=str, required=True)
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def unlock(
    ctx: Context,
    spin: str,
    timeout: float,  # noqa: ASYNC109
    vin: str,
) -> None:
    """Unlock the car."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.unlock(vin, spin)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def honk_flash(ctx: Context, timeout: float, vin: str) -> None:  # noqa: ASYNC109
    """Honk and/or flash."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.honk_flash(vin)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.pass_context
@mqtt_required
async def flash(ctx: Context, timeout: float, vin: str) -> None:  # noqa: ASYNC109
    """Flash."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.flash(vin)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("enabled", "--enabled", type=bool, required=True)
@click.pass_context
@mqtt_required
async def set_ac_without_external_power(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    enabled: bool,
) -> None:
    """Enable or disable AC without external power."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_ac_without_external_power(
            vin,
            AirConditioningWithoutExternalPower(
                air_conditioning_without_external_power_enabled=enabled
            ),
        )


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("enabled", "--enabled", type=bool, required=True)
@click.pass_context
@mqtt_required
async def set_ac_at_unlock(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    enabled: bool,
) -> None:
    """Enable or disable AC at unlock."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_ac_at_unlock(
            vin, AirConditioningAtUnlock(air_conditioning_at_unlock_enabled=enabled)
        )


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("enabled", "--enabled", type=bool, required=True)
@click.pass_context
@mqtt_required
async def set_windows_heating(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    enabled: bool,
) -> None:
    """Enable or disable windows heating with AC."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_windows_heating(vin, WindowHeating(window_heating_enabled=enabled))


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("front_left", "--frontLeft", type=bool, required=False)
@click.option("front_right", "--frontRight", type=bool, required=False)
@click.pass_context
@mqtt_required
async def set_seats_heating(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    front_left: bool | None = None,
    front_right: bool | None = None,
) -> None:
    """Enable or disable seats heating with AC."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    settings = SeatHeating(
        front_left=front_left,
        front_right=front_right,
    )
    async with asyncio.timeout(timeout):
        await myskoda.set_seats_heating(vin, settings)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("enabled", "--enabled", type=bool, required=True)
@click.pass_context
@mqtt_required
async def set_auto_unlock_plug(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    enabled: bool,
) -> None:
    """Enable or disable auto unlock plug when charged."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        await myskoda.set_auto_unlock_plug(vin, enabled)


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("timer", "--timer", type=click.Choice(["1", "2", "3"]), required=True)
@click.option("enabled", "--enabled", type=bool, required=True)
@click.pass_context
@mqtt_required
async def set_departure_timer(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    timer: str,
    enabled: bool,
) -> None:
    """Enable or disable selected departure timer."""
    timer_id = int(timer)
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        # Get all timers from vehicle first
        departure_info = await myskoda.get_departure_timers(vin)
        if departure_info is not None:
            selected_timer = (
                next((t for t in departure_info.timers if t.id == timer_id), None)
                if departure_info.timers
                else None
            )
            if selected_timer is not None:
                selected_timer.enabled = enabled
                await myskoda.set_departure_timer(vin, selected_timer)
            else:
                print(f"No timer found with ID {timer_id}.")
        else:
            print("No DepartureInfo found for the given VIN.")


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("timer", "--timer", type=click.Choice(["1", "2", "3"]), required=True)
@click.option("enabled", "--enabled", type=bool, required=True)
@click.pass_context
@mqtt_required
async def set_ac_timer(
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    timer: str,
    enabled: bool,
) -> None:
    """Enable or disable selected air-conditioning timer."""
    timer_id = int(timer)
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        # Get all timers from vehicle first
        air_conditioning = await myskoda.get_air_conditioning(vin)
        if air_conditioning is not None:
            selected_timer = (
                next((t for t in air_conditioning.timers if t.id == timer_id), None)
                if air_conditioning.timers
                else None
            )
            if selected_timer is not None:
                selected_timer.enabled = enabled
                await myskoda.set_ac_timer(vin, selected_timer)
            else:
                print(f"No timer found with ID {timer_id}.")
        else:
            print("No AirConditioning found for the given VIN.")


@click.command()
@click.option("timeout", "--timeout", type=float, default=300)
@click.argument("vin")
@click.option("timer", "--timer", type=click.Choice(["1", "2", "3"]), required=True)
@click.option("enabled", "--enabled", type=bool, required=True)
@click.option("spin", "--spin", type=str, required=True)
@click.pass_context
@mqtt_required
async def set_aux_timer(  # noqa: PLR0913
    ctx: Context,
    timeout: float,  # noqa: ASYNC109
    vin: str,
    timer: str,
    enabled: bool,
    spin: str,
) -> None:
    """Enable or disable selected auxiliary-heating timer."""
    timer_id = int(timer)
    myskoda: MySkoda = ctx.obj["myskoda"]
    async with asyncio.timeout(timeout):
        # Get all timers from vehicle first
        auxiliary_heating = await myskoda.get_auxiliary_heating(vin)
        if auxiliary_heating is not None:
            selected_timer = (
                next((t for t in auxiliary_heating.timers if t.id == timer_id), None)
                if auxiliary_heating.timers
                else None
            )
            if selected_timer is not None:
                selected_timer.enabled = enabled
                await myskoda.set_auxiliary_heating_timer(vin, selected_timer, spin)
            else:
                print(f"No timer found with ID {timer_id}.")
        else:
            print("No AuxiliaryHeating found for the given VIN.")

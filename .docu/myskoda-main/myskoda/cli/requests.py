"""Commands dealing with reading data from the Rest API."""

from datetime import datetime
from typing import TYPE_CHECKING, Any

import asyncclick as click
from asyncclick.core import Context

from myskoda.cli.utils import MethodArgument, handle_request, iso8601_datetime, simple_date

if TYPE_CHECKING:
    from myskoda.myskoda import MySkoda


@click.command()
@click.pass_context
async def list_vehicles(ctx: Context) -> None:
    """Print a list of all vehicle identification numbers associated with the account."""
    await handle_request(ctx, ctx.obj["myskoda"].list_vehicle_vins)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def info(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print info for the specified vin."""
    await handle_request(ctx, ctx.obj["myskoda"].get_info, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def status(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print current status for the specified vin."""
    await handle_request(ctx, ctx.obj["myskoda"].get_status, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def air_conditioning(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print current status about air conditioning."""
    await handle_request(ctx, ctx.obj["myskoda"].get_air_conditioning, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def auxiliary_heating(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print current status about auxiliary heating."""
    await handle_request(ctx, ctx.obj["myskoda"].get_auxiliary_heating, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def positions(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the vehicle's current position."""
    await handle_request(ctx, ctx.obj["myskoda"].get_positions, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def parking_position(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the vehicle's current position."""
    await handle_request(ctx, ctx.obj["myskoda"].get_parking_position, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def health(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the vehicle's mileage."""
    await handle_request(ctx, ctx.obj["myskoda"].get_health, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def charging(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the vehicle's current charging state."""
    await handle_request(ctx, ctx.obj["myskoda"].get_charging, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def charging_profiles(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the vehicle's charging profiles."""
    await handle_request(ctx, ctx.obj["myskoda"].get_charging_profiles, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("--start", "start", help="ISO8601 compatible start date", callback=iso8601_datetime)
@click.option("--end", "end", help="ISO8601 compatible end date", callback=iso8601_datetime)
@click.option(
    "--cursor",
    "cursor",
    help="ISO8601 compatible cursor date. When this is set, --start and --end are ignored",
    callback=iso8601_datetime,
)
@click.option(
    "--limit",
    "limit",
    help="Maximum amount of sessions in the result",
    type=click.IntRange(1, 99),
    default=50,
)
@click.pass_context
async def charging_history(  # noqa: PLR0913
    ctx: Context,
    vin: str,
    start: datetime | None = None,
    end: datetime | None = None,
    cursor: datetime | None = None,
    limit: int = 50,
) -> None:
    """Print the vehicle's charging history."""

    if cursor is None and (start is None or end is None):
        err_msg = "Either --cursor must be set, or both --start and --end must be provided."
        raise click.BadParameter(err_msg)

    kwargs: dict[str, Any] = {
        k: v
        for k, v in (
            ("vin", vin),
            ("start", start),
            ("end", end),
            ("cursor", cursor),
            ("limit", limit),
        )
        if v is not None
    }

    await handle_request(ctx, ctx.obj["myskoda"].get_charging_history, **kwargs)


@click.command()
@click.argument("vin")
@click.pass_context
async def all_charging_sessions(ctx: Context, vin: str) -> None:
    """Print all vehicles charging sessions."""
    await handle_request(ctx, ctx.obj["myskoda"].get_all_charging_sessions, vin)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def maintenance(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the vehicle's maintenance information."""
    await handle_request(ctx, ctx.obj["myskoda"].get_maintenance, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def maintenance_report(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the vehicle's maintenance report."""
    await handle_request(ctx, ctx.obj["myskoda"].get_maintenance_report, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def driving_range(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the vehicle's estimated driving range information."""
    await handle_request(ctx, ctx.obj["myskoda"].get_driving_range, vin, anonymize)


@click.command()
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def user(ctx: Context, anonymize: bool) -> None:
    """Print information about currently logged in user."""
    await handle_request(ctx, ctx.obj["myskoda"].get_user, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def trip_statistics(ctx: Context, vin: str, anonymize: bool) -> None:
    """Print the last trip statics."""
    await handle_request(ctx, ctx.obj["myskoda"].get_trip_statistics, vin, anonymize)


@click.command()
@click.argument("vin")
@click.option(
    "--start", "start", help="start date in format YYYY-MM-DD (inclusive)", callback=simple_date
)
@click.option(
    "--end", "end", help="end date in format YYYY-MM-DD (exclusive)", callback=simple_date
)
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def single_trip_statistics(
    ctx: Context,
    vin: str,
    anonymize: bool,
    start: datetime | None = None,
    end: datetime | None = None,
) -> None:
    """Retrieve detailed statistics about past trips.
    If you want to filter by date, provide both start and end date."""
    if (start is None) ^ (end is None):
        err_msg = "Both --start and --end must be provided."
        raise click.BadParameter(err_msg)

    kwargs: dict[str, datetime | bool | str] = {
        k: v
        for k, v in (
            ("vin", MethodArgument(text=vin).text),
            ("start", MethodArgument(timestamp=start).timestamp),
            ("end", MethodArgument(timestamp=end).timestamp),
            ("anonymize", MethodArgument(flag=anonymize).flag),
        )
        if v is not None
    }
    await handle_request(ctx, ctx.obj["myskoda"].get_single_trip_statistics, **kwargs)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def connection_status(ctx: Context, vin: str, anonymize: bool) -> None:
    """Get the vehicle connection state."""
    await handle_request(ctx, ctx.obj["myskoda"].get_connection_status, vin, anonymize)


@click.command()
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def garage(ctx: Context, anonymize: bool) -> None:
    """Print garage information (list of vehicles with limited information)."""
    await handle_request(ctx, ctx.obj["myskoda"].rest_api.get_garage, anonymize)


@click.command()
@click.option("spin", "--spin", type=str, required=True)
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def verify_spin(ctx: Context, spin: str, anonymize: bool) -> None:
    """Verify S-PIN."""
    await handle_request(ctx, ctx.obj["myskoda"].verify_spin, spin, anonymize)


@click.command()
@click.argument("vin")
@click.option("anonymize", "--anonymize", help="Strip all personal data.", is_flag=True)
@click.pass_context
async def departure_timers(ctx: Context, vin: str, anonymize: bool) -> None:
    """Get all departure timers."""
    await handle_request(ctx, ctx.obj["myskoda"].get_departure_timers, vin, anonymize)


@click.command()
@click.pass_context
async def auth(ctx: Context) -> None:
    """Extract the auth token."""
    myskoda: MySkoda = ctx.obj["myskoda"]
    print(await myskoda.get_auth_token())

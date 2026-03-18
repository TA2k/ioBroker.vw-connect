"""Utilities."""

import asyncio
import functools
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import ParamSpec

from .const import DEFAULT_DEBOUNCE_WAIT_SECONDS

# TODO @dvx76: Switch to Python 3.13 generics syntax once we're on 3.13
# https://docs.python.org/3/library/typing.html#typing.ParamSpec

P = ParamSpec("P")  # Represents the function parameters


def async_debounce(
    wait: float = DEFAULT_DEBOUNCE_WAIT_SECONDS, immediate: bool = False, queue: bool = True
) -> Callable[[Callable[P, Awaitable[object]]], Callable[P, Awaitable[None]]]:
    """Debounce decorator for async functions.

    NOTE: only works for functions returning None!

    Ensures that the decorated function is only executed once after the specified wait time,
    resetting if called again.

    When 'immediate' is True the first call is executed immediatally.
    When queue is True subsequent calls are still debounced normally. 'queue' does nothing when
    'immediate' is False.
    """
    task: asyncio.Task | None = None
    last_execution_time: float = 0.0

    def decorator(func: Callable[P, Awaitable[object]]) -> Callable[P, Awaitable[None]]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> None:
            nonlocal task, last_execution_time

            async def delayed_execution() -> object:
                nonlocal last_execution_time
                await asyncio.sleep(wait)
                last_execution_time = now
                return await func(*args, **kwargs)

            now = asyncio.get_running_loop().time()

            if immediate and now - last_execution_time >= wait:
                last_execution_time = now
                await func(*args, **kwargs)
                return

            if task:
                task.cancel()

            if not immediate or queue:
                task = asyncio.create_task(delayed_execution())

        return wrapper

    return decorator


def to_iso8601(dt: datetime) -> str:
    """Convert a datetime object to an ISO 8601 string.

    - Adds 'Z' if datetime is UTC.
    - Converts naive datetimes to UTC before formatting.
    """
    if dt.tzinfo is None:
        # Assume naive datetimes are in UTC
        dt = dt.replace(tzinfo=UTC)
    dt_utc = dt.astimezone(UTC)
    return dt_utc.isoformat().replace("+00:00", "Z")

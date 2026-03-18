"""Unit tests for utilities."""

import asyncio
from datetime import UTC, datetime, timedelta, timezone

import pytest

from myskoda.utils import async_debounce, to_iso8601


@pytest.mark.asyncio
async def test_async_debounce() -> None:
    """Test the async_debounce decorator.

    Debounced function:
    - Only executes once when called multiple times within 'wait'.
    - Executes twice when called two times with a delay > 'wait'.
    """
    test_val = 0

    @async_debounce(wait=0.2)
    async def increment() -> None:
        nonlocal test_val
        test_val += 1

    await increment()
    await increment()
    await asyncio.sleep(0.1)
    await increment()
    await asyncio.sleep(0.3)
    assert test_val == 1

    await increment()
    await asyncio.sleep(0.3)
    await increment()
    await asyncio.sleep(0.3)
    assert test_val == 3  # noqa: PLR2004


@pytest.mark.asyncio
async def test_async_debounce_immediate() -> None:
    """Test the async_debounce decorator when immediate is True.

    Debounced function:
    - Executes immediatally the first time called.
    - Subsequent calls are executed (once) after wait time.
    """
    test_val = 0

    @async_debounce(wait=0.2, immediate=True)
    async def increment() -> None:
        nonlocal test_val
        test_val += 1

    await increment()
    assert test_val == 1
    await increment()
    await increment()
    await asyncio.sleep(0.3)
    assert test_val == 2  # noqa: PLR2004


@pytest.mark.asyncio
async def test_async_debounce_immediate_noqueue() -> None:
    """Test the async_debounce decorator when immediate is True and queue is False.

    Debounced function:
    - Executes immediatally the first time called.
    - Subsequent calls are executed (once) after wait time.
    """
    test_val = 0

    @async_debounce(wait=0.2, immediate=True, queue=False)
    async def increment() -> None:
        nonlocal test_val
        test_val += 1

    await increment()
    assert test_val == 1
    await increment()
    await increment()
    await asyncio.sleep(0.3)
    assert test_val == 1


def test_to_is8601_utc_datetime() -> None:
    """Test the to_iso8601 function with UTC datetime input.

    Make sure time stays the same and end with Z
    """
    dt = datetime(2025, 9, 10, 10, 0, 0, tzinfo=UTC)
    result = to_iso8601(dt)
    assert result == "2025-09-10T10:00:00Z"


def test_to_iso8601_offset_datetime() -> None:
    """Test the to_iso8601 function with non-UTC datetime input.

    Make sure time stays the same UTC value and end with Z
    """
    tz = timezone(timedelta(hours=2))
    dt = datetime(2025, 9, 10, 12, 0, 0, tzinfo=tz)
    result = to_iso8601(dt)
    assert result.startswith("2025-09-10T10:00")
    assert result.endswith("Z")

"""Test utilities for dealing with async callables.

Some functions exported from Rust via PyO3/pyo3-asyncio can appear as built-in
functions which are *awaitable* when called, but `inspect.iscoroutinefunction`
returns False.

These helpers let us assert "async-ness" in a robust way without performing any
network I/O.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable


def is_async_callable(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> bool:
    """Return True if `fn` behaves like an async function.

    Checks `inspect.iscoroutinefunction` first, then falls back to calling the
    function and checking `inspect.isawaitable` on the return value.

    NOTE: This should be used with arguments that don't trigger real side
    effects when merely creating the awaitable.
    """

    if inspect.iscoroutinefunction(fn):
        return True

    if not args and not kwargs:
        # Can't probe without arguments
        return False

    try:
        ret = fn(*args, **kwargs)
    except TypeError:
        # wrong signature; cannot determine
        return False

    ok = inspect.isawaitable(ret)

    # Avoid "coroutine was never awaited" warnings when ret is a coroutine
    if ok and inspect.iscoroutine(ret):
        ret.close()

    return ok

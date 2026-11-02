"""
Type checks for provider response fields.

Provider JSON is untrusted input. Each helper returns a value only when it has
the documented type, so ``None``, a string, a bool, ``NaN``, an infinity or a
negative number never reaches the scorer as if it were a real count or flag.
The adapters decide what a failed check means: an evidence field that fails
makes the whole answer invalid (:class:`InvalidResponse`), an optional context
field is simply dropped.
"""
from __future__ import annotations

import math
from typing import Any, List, Optional

#: Upper bound for any count a provider reports (engines, reports, pulses).
MAX_COUNT = 10**9


class InvalidResponse(ValueError):
    """
    A 2xx answer whose body breaks the provider's documented contract.

    The message names the field only; it never quotes provider data.
    """


def integer(
    value: Any, minimum: int = -MAX_COUNT, maximum: int = MAX_COUNT
) -> Optional[int]:
    """
    An integer within ``[minimum, maximum]``, else ``None``.

    Integral floats (``5.0``) are accepted; bools, strings, fractions, NaN and
    infinities are not.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        value = int(value)
    if isinstance(value, int) and minimum <= value <= maximum:
        return value
    return None


def count(value: Any, maximum: int = MAX_COUNT) -> Optional[int]:
    """A non-negative integer no larger than *maximum*, else ``None``."""
    return integer(value, 0, maximum)


def required_count(value: Any, field: str, maximum: int = MAX_COUNT) -> int:
    """A count the answer must carry, else :class:`InvalidResponse`."""
    result = count(value, maximum)
    if result is None:
        raise InvalidResponse(f"{field} is missing or not a valid count")
    return result


def flag(value: Any) -> Optional[bool]:
    """A JSON boolean, else ``None``: the string ``"false"`` is not ``True``."""
    return value if isinstance(value, bool) else None


def text(value: Any, limit: int = 256) -> Optional[str]:
    """A string cut to *limit* characters, else ``None``."""
    return value[:limit] if isinstance(value, str) else None


def text_list(value: Any, limit: int = 50, item_limit: int = 128) -> List[str]:
    """The string items of a list, cut and capped; anything else gives ``[]``."""
    if not isinstance(value, list):
        return []
    return [item[:item_limit] for item in value if isinstance(item, str)][:limit]

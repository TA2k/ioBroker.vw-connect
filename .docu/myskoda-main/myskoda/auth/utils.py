"""Utilities for authorization."""

import random
import string


def generate_nonce() -> str:
    """Generate a random nonce for oauth.

    Returns:
        str: The random nonce
    """
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=16))  # noqa: S311

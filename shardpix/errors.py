"""Exception hierarchy.

Every error the tool expects to meet in normal use derives from
``ShardpixError``, so the CLI can turn it into a one-line message and a
non-zero exit code. Anything else is a bug and is allowed to propagate.
"""

from __future__ import annotations


class ShardpixError(Exception):
    """Base class for every expected, user-facing failure."""


class UnsupportedImageError(ShardpixError):
    """The image cannot be used as a carrier, or the output format is lossy."""


class CapacityError(ShardpixError):
    """The payload does not fit in the carrier."""


class PayloadNotFoundError(ShardpixError):
    """No authentic payload could be read: wrong passphrase, or a modified image."""

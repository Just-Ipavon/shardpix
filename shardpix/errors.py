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


class ShareError(ShardpixError):
    """A problem with secret shares.

    ``rejected`` lists ``(share, reason)`` pairs for shares that were set aside
    before the failure, so the caller can explain what went wrong.
    """

    def __init__(self, message: str, rejected: tuple = ()) -> None:
        super().__init__(message)
        self.rejected = rejected


class ShareFormatError(ShareError):
    """A share is malformed or corrupted (bad encoding, checksum or field)."""


class InsufficientSharesError(ShareError):
    """Fewer usable shares than the threshold."""


class InconsistentSharesError(ShareError):
    """The shares do not belong to a single split."""


class ShareAuthenticationError(ShareError):
    """No set of shares reconstructs a secret that their MACs confirm."""

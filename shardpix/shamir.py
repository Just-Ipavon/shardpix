"""Shamir's secret sharing over GF(256), with authenticated shares.

A secret is split into ``n`` shares so that any ``k`` of them recover it and
any ``k - 1`` reveal nothing about it - not computationally, but in the
information-theoretic sense: every possible secret is equally consistent
with them.

Plain Shamir has a well-known gap: shares carry no integrity protection, so a
single corrupted or forged share makes the reconstruction silently return a
wrong secret. Each share here therefore carries a MAC. The MAC key is a fresh
random 256-bit value that is *shared together with the secret*, so it only
becomes known once ``k`` shares are combined. Keying the MAC with the secret
itself would hand anyone holding a single share an offline oracle for
guessing low-entropy secrets; sharing the key keeps ``k - 1`` shares
independent of the secret.

With more than ``k`` shares available, reconstruction tries ``k``-subsets until
one is confirmed by its own MACs, then checks every other share against the
recovered key - so corrupted or forged shares are not just detected but
identified.

Binary share format (big-endian)::

    magic       4  b"SPXS"
    version     1  1
    group id   16  random identifier common to all shares of one split
    threshold   1  k
    index       1  x coordinate, 1-255
    length      2  secret length in bytes, L
    value    L+32  f(index) for every byte of secret || MAC key
    mac        16  HMAC-SHA256(MAC key, "shardpix/share/v1" || every field above)[:16]
    checksum    4  SHA-256(every field above, mac included)[:4]

The checksum catches accidental damage without any key; the MAC catches
everything else once the MAC key has been reconstructed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import itertools
import os
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

import numpy as np

from . import gf256
from .errors import (
    InconsistentSharesError,
    InsufficientSharesError,
    ShareAuthenticationError,
    ShareFormatError,
)

MAGIC = b"SPXS"
VERSION = 1
GROUP_ID_BYTES = 16
MAC_KEY_BYTES = 32
MAC_BYTES = 16
CHECKSUM_BYTES = 4
HEADER_BYTES = len(MAGIC) + 1 + GROUP_ID_BYTES + 1 + 1 + 2
MAX_SECRET_BYTES = 0xFFFF
MAX_SHARES = 255
MAX_SUBSETS = 10_000
TEXT_PREFIX = "spx1-"

_MAC_DOMAIN = b"shardpix/share/v1"

RandomBytes = Callable[[int], bytes]


def share_size(secret_bytes: int) -> int:
    """Size in bytes of one encoded share for a secret of ``secret_bytes`` bytes."""
    return HEADER_BYTES + secret_bytes + MAC_KEY_BYTES + MAC_BYTES + CHECKSUM_BYTES


def _checksum(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:CHECKSUM_BYTES]


@dataclass(frozen=True)
class Share:
    """One share of a split secret."""

    group_id: bytes
    threshold: int
    index: int
    secret_length: int
    value: bytes
    mac: bytes

    @property
    def group(self) -> str:
        """Short printable form of the group id."""
        return self.group_id.hex()[:8]

    def _body(self) -> bytes:
        return (
            MAGIC
            + bytes([VERSION])
            + self.group_id
            + bytes([self.threshold, self.index])
            + self.secret_length.to_bytes(2, "big")
            + self.value
        )

    def compute_mac(self, mac_key: bytes) -> bytes:
        """MAC over every field of the share except the MAC itself."""
        return hmac.new(mac_key, _MAC_DOMAIN + self._body(), hashlib.sha256).digest()[:MAC_BYTES]

    def verify(self, mac_key: bytes) -> bool:
        """Check the share against a reconstructed MAC key, in constant time."""
        return hmac.compare_digest(self.mac, self.compute_mac(mac_key))

    def to_bytes(self) -> bytes:
        data = self._body() + self.mac
        return data + _checksum(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> Share:
        """Parse and validate an encoded share; raises :class:`ShareFormatError`."""
        if len(data) < share_size(0):
            raise ShareFormatError("share is truncated")
        if data[: len(MAGIC)] != MAGIC:
            raise ShareFormatError("not a shardpix share")
        if data[len(MAGIC)] != VERSION:
            raise ShareFormatError(f"unsupported share version {data[len(MAGIC)]}")
        content, checksum = data[:-CHECKSUM_BYTES], data[-CHECKSUM_BYTES:]
        if not hmac.compare_digest(checksum, _checksum(content)):
            raise ShareFormatError("share checksum mismatch: the share is corrupted")

        offset = len(MAGIC) + 1
        group_id = data[offset : offset + GROUP_ID_BYTES]
        offset += GROUP_ID_BYTES
        threshold, index = data[offset], data[offset + 1]
        offset += 2
        secret_length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        if len(data) != share_size(secret_length):
            raise ShareFormatError("share length does not match its header")
        value_end = offset + secret_length + MAC_KEY_BYTES
        if threshold < 2:
            raise ShareFormatError("share threshold must be at least 2")
        if index == 0:
            raise ShareFormatError("share index 0 is reserved for the secret")
        return cls(
            group_id=group_id,
            threshold=threshold,
            index=index,
            secret_length=secret_length,
            value=data[offset:value_end],
            mac=data[value_end : value_end + MAC_BYTES],
        )

    def to_text(self) -> str:
        """Printable form: ``spx1-`` followed by lowercase, unpadded base32."""
        encoded = base64.b32encode(self.to_bytes()).decode("ascii").rstrip("=").lower()
        return TEXT_PREFIX + encoded

    @classmethod
    def from_text(cls, text: str) -> Share:
        cleaned = "".join(text.split())
        if not cleaned.lower().startswith(TEXT_PREFIX):
            raise ShareFormatError(f"shares start with '{TEXT_PREFIX}'")
        body = cleaned[len(TEXT_PREFIX) :].upper()
        body += "=" * (-len(body) % 8)
        try:
            raw = base64.b32decode(body)
        except (binascii.Error, ValueError) as exc:
            raise ShareFormatError("share is not valid base32") from exc
        return cls.from_bytes(raw)


@dataclass(frozen=True)
class Rejection:
    """A share that was set aside, and why."""

    share: Share
    reason: str


@dataclass(frozen=True)
class Recovery:
    """Outcome of a successful reconstruction."""

    secret: bytes
    group_id: bytes
    threshold: int
    used: tuple[Share, ...]
    """The ``threshold`` shares that were interpolated."""
    confirmed: tuple[Share, ...]
    """Further shares that verified against the recovered MAC key."""
    rejected: tuple[Rejection, ...]
    """Shares that were set aside: other splits, mismatched fields, failed MACs."""


def split(
    secret: bytes,
    threshold: int,
    count: int,
    *,
    group_id: bytes | None = None,
    random_bytes: RandomBytes = os.urandom,
) -> list[Share]:
    """Split ``secret`` into ``count`` shares, any ``threshold`` of which recover it."""
    if not 1 <= len(secret) <= MAX_SECRET_BYTES:
        raise ValueError(f"secret must be between 1 and {MAX_SECRET_BYTES} bytes")
    if not 2 <= threshold <= count <= MAX_SHARES:
        raise ValueError(f"need 2 <= threshold <= count <= {MAX_SHARES}")
    if group_id is None:
        group_id = random_bytes(GROUP_ID_BYTES)
    if len(group_id) != GROUP_ID_BYTES:
        raise ValueError(f"group id must be {GROUP_ID_BYTES} bytes")

    mac_key = random_bytes(MAC_KEY_BYTES)
    shared = np.frombuffer(secret + mac_key, dtype=np.uint8)
    coefficients = [shared] + [
        np.frombuffer(random_bytes(shared.size), dtype=np.uint8) for _ in range(threshold - 1)
    ]

    shares = []
    for index in range(1, count + 1):
        unsigned = Share(
            group_id=group_id,
            threshold=threshold,
            index=index,
            secret_length=len(secret),
            value=gf256.eval_poly(coefficients, index).tobytes(),
            mac=b"",
        )
        shares.append(replace(unsigned, mac=unsigned.compute_mac(mac_key)))
    return shares


def _interpolate(shares: tuple[Share, ...]) -> tuple[bytes, bytes]:
    xs = [s.index for s in shares]
    ys = [np.frombuffer(s.value, dtype=np.uint8) for s in shares]
    shared = gf256.interpolate_at_zero(xs, ys).tobytes()
    length = shares[0].secret_length
    return shared[:length], shared[length:]


def _majority(values: Iterable[object], what: str, rejected: list[Rejection]) -> object:
    counts = Counter(values).most_common()
    if len(counts) > 1 and counts[0][1] == counts[1][1]:
        raise InconsistentSharesError(
            f"shares disagree on their {what} and there is no majority", tuple(rejected)
        )
    return counts[0][0]


def combine(shares: Iterable[Share]) -> Recovery:
    """Recover the secret from a collection of shares.

    Shares from a different split, or whose threshold or secret length
    disagree with the majority, are set aside. The remaining shares are tried
    ``threshold`` at a time until a subset reconstructs a MAC key that confirms
    every share in it; all other shares are then verified against that key.
    """
    unique: dict[bytes, Share] = {}
    for share in shares:
        unique.setdefault(share.to_bytes(), share)
    candidates = list(unique.values())
    if not candidates:
        raise InsufficientSharesError("no shares given")

    rejected: list[Rejection] = []

    def keep_majority(attribute: str, what: str, reason: str) -> None:
        nonlocal candidates
        winner = _majority((getattr(s, attribute) for s in candidates), what, rejected)
        rejected.extend(Rejection(s, reason) for s in candidates if getattr(s, attribute) != winner)
        candidates = [s for s in candidates if getattr(s, attribute) == winner]

    keep_majority("group_id", "group id", "belongs to a different split")
    keep_majority("threshold", "threshold", "threshold differs from the other shares")
    keep_majority("secret_length", "secret length", "secret length differs from the other shares")

    threshold = candidates[0].threshold
    distinct = {s.index for s in candidates}
    if len(distinct) < threshold:
        raise InsufficientSharesError(
            f"need {threshold} shares with distinct indices, have {len(distinct)}",
            tuple(rejected),
        )

    tried = 0
    for subset in itertools.combinations(candidates, threshold):
        if len({s.index for s in subset}) < threshold:
            continue
        tried += 1
        if tried > MAX_SUBSETS:
            raise ShareAuthenticationError(
                f"gave up after {MAX_SUBSETS} combinations without finding {threshold} shares "
                "that authenticate each other",
                tuple(rejected),
            )
        secret, mac_key = _interpolate(subset)
        if not all(s.verify(mac_key) for s in subset):
            continue
        others = [s for s in candidates if s not in subset]
        confirmed = tuple(s for s in others if s.verify(mac_key))
        rejected.extend(
            Rejection(s, "failed authentication: corrupted or forged")
            for s in others
            if s not in confirmed
        )
        return Recovery(
            secret=secret,
            group_id=subset[0].group_id,
            threshold=threshold,
            used=subset,
            confirmed=confirmed,
            rejected=tuple(rejected),
        )

    raise ShareAuthenticationError(
        f"no {threshold} of the {len(candidates)} shares authenticate each other: "
        "too many of them are corrupted or forged",
        tuple(rejected),
    )

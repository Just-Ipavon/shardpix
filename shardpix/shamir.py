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

Reconstruction looks for *clusters*: sets of shares that interpolate to a
secret and MAC key under which every one of them verifies. A share verifies
under one MAC key only, so clusters never overlap. Genuine shares form one
cluster; a damaged share forms none; someone who fabricates ``k`` mutually
consistent shares forms a second, separate cluster. The largest cluster
wins, a tie is reported as ambiguous, and every other share is identified
and reported with a reason. A caller holding an independent check - the
vault's AES-GCM tag - can instead try every cluster in turn.

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
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, replace
from typing import NoReturn

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


def _candidate_subsets(pool: list[Share], k: int) -> Iterator[tuple[Share, ...]]:
    """Candidate ``k``-subsets with distinct indices, most promising first.

    Disjoint blocks come first: if fewer shares are bad than there are
    blocks, some block is entirely good, so a 6-of-20 split with one damaged
    share is recovered at the second subset instead of after thousands. Then
    every choice of ``k`` indices is tried with every choice of one share per
    index, so a flood of shares reusing one index costs one extra attempt per
    impostor rather than an explosion of combinations.
    """
    by_index: dict[int, list[Share]] = {}
    for share in pool:
        by_index.setdefault(share.index, []).append(share)
    firsts = [members[0] for members in by_index.values()]
    blocks = [tuple(firsts[i : i + k]) for i in range(0, len(firsts) - k + 1, k)]
    yield from blocks
    tried = set(blocks)
    for indices in itertools.combinations(by_index, k):
        for subset in itertools.product(*(by_index[i] for i in indices)):
            if subset not in tried:
                yield subset


@dataclass
class _Budget:
    remaining: int
    exhausted: bool = False


def _find_cluster(
    pool: list[Share], k: int, budget: _Budget
) -> tuple[tuple[Share, ...], bytes, bytes] | None:
    """A ``k``-subset of ``pool`` whose shares all verify under its own MAC key."""
    if len({s.index for s in pool}) < k:
        return None
    for subset in _candidate_subsets(pool, k):
        if budget.remaining <= 0:
            budget.exhausted = True
            return None
        budget.remaining -= 1
        secret, mac_key = _interpolate(subset)
        if all(s.verify(mac_key) for s in subset):
            return subset, secret, mac_key
    return None


def recover_all(shares: Iterable[Share]) -> list[Recovery]:
    """Every secret that some ``threshold`` of the shares authenticate, best supported first.

    Shares are grouped by split (group id, threshold and secret length), and
    clusters are searched for in each group. Each :class:`Recovery` lists the
    shares of its own cluster as used or confirmed, and every other share as
    rejected with a reason.
    """
    unique: dict[bytes, Share] = {}
    for share in shares:
        unique.setdefault(share.to_bytes(), share)
    if not unique:
        raise InsufficientSharesError("no shares given")

    groups: dict[tuple[bytes, int, int], list[Share]] = {}
    for share in unique.values():
        groups.setdefault((share.group_id, share.threshold, share.secret_length), []).append(share)

    budget = _Budget(MAX_SUBSETS)
    clusters: list[tuple[tuple[Share, ...], list[Share], bytes]] = []
    for (_, threshold, _), members in groups.items():
        pool = list(members)
        while (found := _find_cluster(pool, threshold, budget)) is not None:
            subset, secret, mac_key = found
            cluster = [s for s in pool if s in subset or s.verify(mac_key)]
            clusters.append((subset, cluster, secret))
            pool = [s for s in pool if s not in cluster]

    if not clusters:
        _raise_no_cluster(list(unique.values()), groups, budget)

    clusters.sort(key=lambda c: len(c[1]), reverse=True)
    recoveries = []
    for subset, cluster, secret in clusters:
        rejected = []
        for share in unique.values():
            if share in cluster:
                continue
            if share.group_id != subset[0].group_id:
                reason = "belongs to a different split"
            elif share.threshold != subset[0].threshold:
                reason = "threshold differs from the other shares"
            elif share.secret_length != subset[0].secret_length:
                reason = "secret length differs from the other shares"
            elif any(share in other for _, other, _ in clusters):
                reason = "authenticates a different secret: one of the two sets is forged"
            else:
                reason = "failed authentication: corrupted or forged"
            rejected.append(Rejection(share, reason))
        recoveries.append(
            Recovery(
                secret=secret,
                group_id=subset[0].group_id,
                threshold=subset[0].threshold,
                used=subset,
                confirmed=tuple(s for s in cluster if s not in subset),
                rejected=tuple(rejected),
            )
        )
    return recoveries


def _raise_no_cluster(
    shares: list[Share], groups: dict[tuple[bytes, int, int], list[Share]], budget: _Budget
) -> NoReturn:
    best = max(groups.values(), key=lambda members: len({s.index for s in members}))
    threshold = best[0].threshold
    distinct = len({s.index for s in best})
    rejected = tuple(
        Rejection(s, "failed authentication: corrupted or forged")
        for s in best
        if distinct >= threshold
    )
    if budget.exhausted:
        raise ShareAuthenticationError(
            f"gave up after {MAX_SUBSETS} combinations without finding {threshold} shares "
            "that authenticate each other",
            rejected,
        )
    if distinct < threshold:
        others = tuple(
            Rejection(s, "belongs to a different split") for s in shares if s not in best
        )
        raise InsufficientSharesError(
            f"need {threshold} shares with distinct indices, have {distinct}", others
        )
    raise ShareAuthenticationError(
        f"no {threshold} of the {len(best)} shares authenticate each other: "
        "too many of them are corrupted or forged",
        rejected,
    )


def combine(shares: Iterable[Share]) -> Recovery:
    """Recover the secret from a collection of shares.

    Returns the recovery supported by the most shares. If two different
    secrets are each supported by the same number of shares there is no way
    to tell the genuine one from a forgery, and
    :class:`InconsistentSharesError` is raised - as it is when shares of two
    unrelated splits could each be recovered.
    """
    recoveries = recover_all(shares)
    groups = {r.group_id for r in recoveries}
    if len(groups) > 1:
        raise InconsistentSharesError(
            f"the shares come from {len(groups)} different splits that can each be recovered; "
            "combine them separately",
            recoveries[0].rejected,
        )
    if len(recoveries) > 1:
        first, second = recoveries[0], recoveries[1]
        support = len(first.used) + len(first.confirmed)
        if support == len(second.used) + len(second.confirmed):
            raise InconsistentSharesError(
                f"two different secrets are each authenticated by {support} shares; "
                "one of the two sets is forged and there is no way to tell which",
                first.rejected,
            )
    return recoveries[0]

"""RS steganalysis (Fridrich, Goljan and Du, 2001).

Pixels are taken in small groups and a *smoothness* measure is computed for
each: the sum of absolute differences between neighbours. Two flipping
operations are then applied to some pixels of every group:

* ``F1`` swaps 0<->1, 2<->3, ... - exactly what LSB replacement does;
* ``F-1`` swaps -1<->0, 1<->2, ... - the same move shifted by one.

A group is *regular* if flipping makes it less smooth and *singular* if it
makes it smoother. In a natural image both flips raise the share of regular
groups by about the same amount. LSB replacement breaks that symmetry in a
way that grows with the amount of embedded data, and by also measuring the
image with every LSB inverted the attack can solve for the embedding rate.

The estimate is the fraction of samples that carry a payload bit. Values
within a few percent of zero are noise: natural images are not perfectly
symmetric. LSB matching changes values by +-1 in either direction, so it does
not create the asymmetry this attack measures.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

GROUP_SIZE = 4
MASK = np.array([0, 1, 1, 0], dtype=bool)
"""Which pixels of each group are flipped; the classic choice from the paper."""


@dataclass(frozen=True)
class RSCounts:
    """Shares of regular and singular groups under the mask ``M`` and its negation ``-M``."""

    regular: float
    singular: float
    regular_neg: float
    singular_neg: float


@dataclass(frozen=True)
class RSResult:
    """RS estimate for one channel."""

    rate: float
    """Estimated fraction of samples carrying payload bits (may be slightly negative)."""
    counts: RSCounts
    counts_flipped: RSCounts


def _groups(channel: np.ndarray) -> np.ndarray:
    """Non-overlapping horizontal groups of ``GROUP_SIZE`` pixels, one per row."""
    height, width = channel.shape
    usable = width - width % GROUP_SIZE
    return channel[:, :usable].astype(np.int16).reshape(-1, GROUP_SIZE)


def _smoothness(groups: np.ndarray) -> np.ndarray:
    return np.abs(np.diff(groups, axis=1)).sum(axis=1)


def _flip_positive(values: np.ndarray) -> np.ndarray:
    return values ^ 1


def _flip_negative(values: np.ndarray) -> np.ndarray:
    return ((values + 1) ^ 1) - 1


def rs_counts(groups: np.ndarray) -> RSCounts:
    """Measure regular and singular group shares for ``M`` and ``-M``."""
    base = _smoothness(groups)
    positive = groups.copy()
    positive[:, MASK] = _flip_positive(positive[:, MASK])
    negative = groups.copy()
    negative[:, MASK] = _flip_negative(negative[:, MASK])
    f_pos = _smoothness(positive)
    f_neg = _smoothness(negative)
    return RSCounts(
        regular=float(np.mean(f_pos > base)),
        singular=float(np.mean(f_pos < base)),
        regular_neg=float(np.mean(f_neg > base)),
        singular_neg=float(np.mean(f_neg < base)),
    )


def _solve(c0: RSCounts, c1: RSCounts) -> float:
    """Solve the RS quadratic for the embedding rate.

    ``2(d1 + d0) z^2 + (d-0 - d-1 - d1 - 3 d0) z + d0 - d-0 = 0``, then
    ``p = z / (z - 1/2)``, taking the root of smaller magnitude.
    """
    d0 = c0.regular - c0.singular
    d1 = c1.regular - c1.singular
    dn0 = c0.regular_neg - c0.singular_neg
    dn1 = c1.regular_neg - c1.singular_neg
    a = 2.0 * (d1 + d0)
    b = dn0 - dn1 - d1 - 3.0 * d0
    c = d0 - dn0
    if abs(a) < 1e-12:
        if abs(b) < 1e-12:
            return 0.0
        z = -c / b
    else:
        discriminant = max(0.0, b * b - 4.0 * a * c)
        root = math.sqrt(discriminant)
        z = min(((-b + root) / (2 * a), (-b - root) / (2 * a)), key=abs)
    if abs(z - 0.5) < 1e-12:
        return 1.0
    return z / (z - 0.5)


def estimate_channel(channel: np.ndarray) -> RSResult:
    """Estimate the LSB replacement rate in one 8-bit channel (``H x W``)."""
    channel = np.asarray(channel, dtype=np.uint8)
    if channel.ndim != 2 or channel.shape[1] < GROUP_SIZE:
        raise ValueError("expected a 2-D channel at least four pixels wide")
    groups = _groups(channel)
    counts = rs_counts(groups)
    counts_flipped = rs_counts(groups ^ 1)
    return RSResult(
        rate=_solve(counts, counts_flipped), counts=counts, counts_flipped=counts_flipped
    )


def estimate(pixels: np.ndarray, channels: int | None = None) -> list[RSResult]:
    """Run RS on every colour channel of an ``H x W x C`` image."""
    pixels = np.asarray(pixels, dtype=np.uint8)
    if pixels.ndim == 2:
        pixels = pixels[..., np.newaxis]
    count = pixels.shape[2] if channels is None else channels
    return [estimate_channel(pixels[..., c]) for c in range(count)]


def mean_rate(results: list[RSResult]) -> float:
    """Average estimate over channels."""
    return float(np.mean([r.rate for r in results]))

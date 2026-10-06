"""The chi-square attack on LSB replacement (Westfeld and Pfitzmann, 1999).

LSB replacement only ever swaps a value with its partner in the pair
``(2k, 2k + 1)``. Writing random bits therefore pulls the two counts of every
pair towards their mean, while natural images show no such balance. The test
compares the observed count of each even value with the pair mean and turns
the chi-square statistic into a probability that the samples were embedded.

Run over a growing prefix of the image, the probability stays close to 1 as
long as the prefix lies inside a sequentially embedded region and collapses
where the payload ends - which is how the attack also estimates the payload
length. Scattering bits over the whole image, or changing values by +-1
instead of replacing the LSB, both defeat it; the benchmark measures by how
much.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

MIN_EXPECTED = 5.0
"""Pairs whose expected count is below this are dropped, as is usual for chi-square tests."""

_EPS = 1e-15
_TINY = 1e-300
_MAX_ITER = 10_000


def _lower_series(a: float, x: float) -> float:
    """Regularised lower incomplete gamma P(a, x) by its power series (x < a + 1)."""
    term = 1.0 / a
    total = term
    ap = a
    for _ in range(_MAX_ITER):
        ap += 1.0
        term *= x / ap
        total += term
        if abs(term) < abs(total) * _EPS:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _upper_fraction(a: float, x: float) -> float:
    """Regularised upper incomplete gamma Q(a, x) by Lentz's continued fraction (x >= a + 1)."""
    b = x + 1.0 - a
    c = 1.0 / _TINY
    d = 1.0 / b
    h = d
    for i in range(1, _MAX_ITER):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _TINY:
            d = _TINY
        c = b + an / c
        if abs(c) < _TINY:
            c = _TINY
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi2_sf(statistic: float, dof: int) -> float:
    """Survival function of the chi-square distribution, ``P(X >= statistic)``.

    Implemented through the regularised incomplete gamma function so the core
    package needs no SciPy; the test suite checks it against SciPy.
    """
    if dof <= 0:
        raise ValueError("degrees of freedom must be positive")
    if statistic <= 0:
        return 1.0
    a = dof / 2.0
    x = statistic / 2.0
    q = 1.0 - _lower_series(a, x) if x < a + 1.0 else _upper_fraction(a, x)
    return min(1.0, max(0.0, q))


@dataclass(frozen=True)
class ChiSquareResult:
    """Outcome of the pair test on one set of samples."""

    statistic: float
    dof: int
    p_value: float
    """Probability that the samples carry LSB-replaced data; close to 1 means suspicious."""


def pair_test(samples: np.ndarray) -> ChiSquareResult:
    """Run the pairs-of-values chi-square test on 8-bit samples."""
    hist = np.bincount(np.asarray(samples, dtype=np.uint8).ravel(), minlength=256)
    even = hist[0::2].astype(np.float64)
    odd = hist[1::2].astype(np.float64)
    expected = (even + odd) / 2.0
    keep = expected >= MIN_EXPECTED
    categories = int(keep.sum())
    if categories < 2:
        return ChiSquareResult(statistic=0.0, dof=0, p_value=0.0)
    statistic = float(np.sum((even[keep] - expected[keep]) ** 2 / expected[keep]))
    dof = categories - 1
    return ChiSquareResult(statistic=statistic, dof=dof, p_value=chi2_sf(statistic, dof))


@dataclass(frozen=True)
class ChiSquareCurve:
    """Embedding probability measured over growing prefixes of an image."""

    fractions: np.ndarray
    p_values: np.ndarray

    def detected_prefix(self, threshold: float = 0.5) -> float:
        """Fraction of the image, from the start, over which the attack stays above ``threshold``.

        For sequential LSB replacement this approximates the share of the image
        holding the payload; for a clean or keyed embedding it is usually 0.
        """
        below = np.nonzero(self.p_values < threshold)[0]
        if below.size == 0:
            return float(self.fractions[-1])
        first = int(below[0])
        return float(self.fractions[first - 1]) if first > 0 else 0.0


def sequential_attack(samples: np.ndarray, steps: int = 100) -> ChiSquareCurve:
    """Run :func:`pair_test` on the first 1/steps, 2/steps, ... of ``samples``."""
    flat = np.asarray(samples, dtype=np.uint8).ravel()
    if steps < 1:
        raise ValueError("steps must be at least 1")
    fractions = np.arange(1, steps + 1, dtype=np.float64) / steps
    p_values = np.array(
        [pair_test(flat[: max(1, int(round(f * flat.size)))]).p_value for f in fractions]
    )
    return ChiSquareCurve(fractions=fractions, p_values=p_values)

"""Arithmetic in GF(2^8), the finite field Shamir's scheme runs in.

Elements are the integers 0-255, read as polynomials over GF(2) of degree < 8.
Addition and subtraction are both XOR. Multiplication is polynomial
multiplication reduced modulo the AES polynomial ``x^8 + x^4 + x^3 + x + 1``
(``0x11B``), computed through log/antilog tables built over the generator
``0x03``.

Working in a field of 256 elements means every secret byte is shared
independently and every share byte is a byte: no big integers, no padding,
and shares are exactly as long as the secret.

The table lookups are not constant-time. That is acceptable for a local
command line tool, and it is stated as a limitation in the documentation.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

POLYNOMIAL = 0x11B
GENERATOR = 0x03
ORDER = 255
"""Size of the multiplicative group: every non-zero element is ``GENERATOR ** k``."""


def mul_reference(a: int, b: int) -> int:
    """Multiply by shift-and-add ("Russian peasant"); slow, used to build and test the tables."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= POLYNOMIAL
        b >>= 1
    return result


def _build_tables() -> tuple[tuple[int, ...], tuple[int, ...]]:
    exp = [0] * (2 * ORDER)
    log = [0] * 256
    value = 1
    for power in range(ORDER):
        exp[power] = value
        log[value] = power
        value = mul_reference(value, GENERATOR)
    for power in range(ORDER, 2 * ORDER):
        exp[power] = exp[power - ORDER]
    return tuple(exp), tuple(log)


EXP, LOG = _build_tables()
"""``EXP[k] = GENERATOR ** k`` (twice over, so log sums need no reduction); ``LOG`` inverts it."""

_EXP_ARRAY = np.array(EXP, dtype=np.uint8)
_LOG_ARRAY = np.array(LOG, dtype=np.int32)


def add(a: int, b: int) -> int:
    """Field addition (and subtraction): XOR."""
    return a ^ b


def mul(a: int, b: int) -> int:
    """Field multiplication."""
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def inv(a: int) -> int:
    """Multiplicative inverse."""
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(256)")
    return EXP[ORDER - LOG[a]]


def div(a: int, b: int) -> int:
    """Field division ``a / b``."""
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return EXP[LOG[a] + ORDER - LOG[b]]


def mul_bytes(values: np.ndarray, scalar: int) -> np.ndarray:
    """Multiply every byte of ``values`` by ``scalar``, vectorised."""
    values = np.asarray(values, dtype=np.uint8)
    if scalar == 0:
        return np.zeros_like(values)
    product = _EXP_ARRAY[_LOG_ARRAY[values] + LOG[scalar]]
    product[values == 0] = 0
    return product


def eval_poly(coefficients: Sequence[np.ndarray], x: int) -> np.ndarray:
    """Evaluate byte-wise polynomials at ``x`` by Horner's rule.

    ``coefficients[i]`` holds the degree-``i`` coefficient of every polynomial,
    one polynomial per byte position.
    """
    if not coefficients:
        raise ValueError("at least one coefficient is required")
    result = np.zeros_like(np.asarray(coefficients[0], dtype=np.uint8))
    for coefficient in reversed(coefficients):
        result = mul_bytes(result, x) ^ np.asarray(coefficient, dtype=np.uint8)
    return result


def lagrange_at_zero(xs: Sequence[int]) -> list[int]:
    """Lagrange basis coefficients for interpolating at ``x = 0``.

    ``f(0) = sum(c_i * y_i)`` where ``c_i = prod_{j != i} x_j / (x_j - x_i)``;
    in characteristic 2, subtraction is XOR.
    """
    if len(set(xs)) != len(xs):
        raise ValueError("x coordinates must be distinct")
    if any(x == 0 for x in xs):
        raise ValueError("x = 0 is the secret, not a share")
    coefficients = []
    for i, xi in enumerate(xs):
        c = 1
        for j, xj in enumerate(xs):
            if i != j:
                c = mul(c, div(xj, xj ^ xi))
        coefficients.append(c)
    return coefficients


def interpolate_at_zero(xs: Sequence[int], ys: Sequence[np.ndarray]) -> np.ndarray:
    """Recover ``f(0)`` byte-wise from the points ``(xs[i], ys[i])``."""
    if len(xs) != len(ys) or not xs:
        raise ValueError("need the same, non-zero number of x and y values")
    result = np.zeros_like(np.asarray(ys[0], dtype=np.uint8))
    for c, y in zip(lagrange_at_zero(xs), ys, strict=True):
        result ^= mul_bytes(y, c)
    return result

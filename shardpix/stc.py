"""Syndrome-trellis codes: write a message with the least total cost.

Filler, Judas and Fridrich (2011). The message is not written bit by bit:
it is the *syndrome* ``H x`` of the least significant bits ``x`` of a block
of ``n`` cover elements, with ``H`` a sparse binary matrix built from a small
``h x w`` submatrix repeated along the diagonal. The sender is free to pick
any ``x`` with the right syndrome and picks, with the Viterbi algorithm, the
one whose changes cost least; the receiver only multiplies by ``H``. That is
what lets the payload follow a cost map that the receiver never sees.

``w = n / m`` is the inverse of the rate: with a wider submatrix the coder
has more cover elements to choose from per message bit and the changes get
cheaper. ``h`` is the constraint height: the trellis has ``2^h`` states, and
larger ``h`` gets closer to the theoretical bound at the price of time.
"""

from __future__ import annotations

import hashlib

import numpy as np

HEIGHT = 10
"""Constraint height: 1,024 trellis states."""
WET = 1e13
"""Cost of an element that must not change."""


def submatrix(seed: bytes, width: int, height: int = HEIGHT) -> np.ndarray:
    """A pseudo-random ``height x width`` binary submatrix derived from ``seed``.

    The first and last rows are all ones, which every good STC submatrix
    has: each column then reaches both the current and the last message bit
    of its window. The bits come from SHAKE-256, not from a NumPy generator,
    so the matrix - and every image written with it - does not depend on the
    NumPy version.
    """
    stream = hashlib.shake_256(b"shardpix/stc|" + seed).digest((height * width + 7) // 8)
    bits = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))[: height * width]
    h_hat = bits.reshape(height, width).astype(np.uint8)
    h_hat[0, :] = 1
    h_hat[-1, :] = 1
    return h_hat


def _columns(h_hat: np.ndarray) -> np.ndarray:
    """Each column of the submatrix as an integer, row ``r`` in bit ``r``."""
    weights = 1 << np.arange(h_hat.shape[0], dtype=np.int64)
    return (h_hat.astype(np.int64) * weights[:, None]).sum(axis=0)


def syndrome(bits: np.ndarray, h_hat: np.ndarray, length: int) -> np.ndarray:
    """``H x`` for ``bits`` of length ``length * w``: the message they carry."""
    height, width = h_hat.shape
    if bits.size != length * width:
        raise ValueError("the block must hold exactly length * width elements")
    x = bits.reshape(length, width).astype(np.int64)
    message = np.zeros(length + height, dtype=np.int64)
    for r in range(height):
        message[r : r + length] ^= (x @ h_hat[r].astype(np.int64)) & 1
    return message[:length].astype(np.uint8)


def embed(bits: np.ndarray, costs: np.ndarray, message: np.ndarray, h_hat: np.ndarray):
    """Least-cost ``y`` with ``syndrome(y) == message``; returns ``(y, total cost)``.

    ``bits`` are the cover LSBs, ``costs`` the cost of flipping each one
    (use :data:`WET` to forbid a change). Raises ``ValueError`` when no
    solution avoids every wet element.
    """
    height, width = h_hat.shape
    m = message.size
    n = m * width
    if bits.size != n or costs.size != n:
        raise ValueError("bits and costs must hold exactly len(message) * width elements")
    states = 1 << height
    columns = _columns(h_hat)
    index = np.arange(states, dtype=np.int64)
    partner = [index ^ c for c in columns]
    bits = bits.astype(np.uint8)
    costs = costs.astype(np.float64)

    cost = np.full(states, np.inf)
    cost[0] = 0.0
    # One bit per state and element: which bit was written to reach the state.
    choice = np.zeros((n, max(1, states // 8)), dtype=np.uint8)
    half = states >> 1
    for b in range(m):
        for k in range(width):
            j = b * width + k
            flip = costs[j]
            keep0 = cost + (flip if bits[j] else 0.0)  # write 0
            take1 = cost + (0.0 if bits[j] else flip)  # write 1, moves the state
            moved = take1[partner[k]]
            chose = moved < keep0
            cost = np.where(chose, moved, keep0)
            choice[j] = np.packbits(chose)
        # The lowest bit of the state is this block's message bit: keep the
        # states that agree, then shift the window by one row.
        cost = np.concatenate([cost[int(message[b]) :: 2], np.full(half, np.inf)])

    best = int(np.argmin(cost))
    total = float(cost[best])
    if not np.isfinite(total) or total >= WET:
        raise ValueError("no solution avoids the forbidden elements")

    y = np.empty(n, dtype=np.uint8)
    state = best
    for b in range(m - 1, -1, -1):
        state = ((state << 1) | int(message[b])) & (states - 1)
        for k in range(width - 1, -1, -1):
            j = b * width + k
            if (choice[j, state >> 3] >> (7 - (state & 7))) & 1:
                y[j] = 1
                state ^= int(columns[k])
            else:
                y[j] = 0
    return y, total

"""Embedding costs: how risky it is to change each sample by +-1.

Adaptive steganography puts its changes where they are hardest to model -
in texture and noise - and avoids smooth regions, where a +-1 change stands
out against neighbours that predict each other well. A *cost* per sample
expresses that; the coder (:mod:`shardpix.stc`) then writes the payload with
the smallest total cost.

The costs here are HiLL (Li, Wang, Huang and Ni, 2014): a high-pass filter
measures how predictable each sample is, two low-pass filters spread that
measure so that changes cluster in textured areas instead of on isolated
edges. HiLL is among the strongest spatial-domain cost functions and needs
only four convolutions, so it runs in numpy on photographs of any size.

Costs are computed on the cover and are never needed to extract: the
receiver reads a syndrome and does not care where the changes are.
"""

from __future__ import annotations

import numpy as np

_KB = np.array([[-1, 2, -1], [2, -4, 2], [-1, 2, -1]], dtype=np.float64)
HILL_SMALL = 3
HILL_LARGE = 15
_EPSILON = 1e-10


def _filter3(x: np.ndarray, kernel: np.ndarray) -> np.ndarray:
    """Same-size correlation with a 3x3 kernel, symmetric padding."""
    padded = np.pad(x, 1, mode="symmetric")
    h, w = x.shape
    out = np.zeros((h, w))
    for i in range(3):
        for j in range(3):
            if kernel[i, j]:
                out += kernel[i, j] * padded[i : i + h, j : j + w]
    return out


def box_mean(x: np.ndarray, size: int) -> np.ndarray:
    """Same-size mean over a ``size`` x ``size`` window (odd), symmetric padding."""
    r = size // 2
    padded = np.pad(x, r, mode="symmetric")
    integral = np.zeros((padded.shape[0] + 1, padded.shape[1] + 1))
    integral[1:, 1:] = padded.cumsum(axis=0).cumsum(axis=1)
    h, w = x.shape
    total = (
        integral[size : size + h, size : size + w]
        - integral[:h, size : size + w]
        - integral[size : size + h, :w]
        + integral[:h, :w]
    )
    return total / (size * size)


def hill(channel: np.ndarray) -> np.ndarray:
    """HiLL cost of changing each sample of one greyscale channel by +-1."""
    x = channel.astype(np.float64)
    residual = np.abs(_filter3(x, _KB))
    smoothed = box_mean(residual, HILL_SMALL)
    return box_mean(1.0 / (smoothed + _EPSILON), HILL_LARGE)


def sample_costs(pixels: np.ndarray, channels: int) -> np.ndarray:
    """HiLL costs of the colour samples of an ``H x W x C`` image, in sample order.

    The order is that of :meth:`shardpix.images.Carrier.samples`: row-major,
    channel-interleaved. Each channel is filtered on its own.
    """
    per_channel = [hill(pixels[..., c]) for c in range(channels)]
    return np.stack(per_channel, axis=-1).reshape(-1)

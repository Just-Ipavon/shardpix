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

from .progress import Progress, span

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


def hill(channel: np.ndarray, progress: Progress | None = None) -> np.ndarray:
    """HiLL cost of changing each sample of one greyscale channel by +-1."""
    report = span(progress, 0.0, 1.0)
    x = channel.astype(np.float64)
    residual = np.abs(_filter3(x, _KB))
    report(1 / 3, "measuring the texture")
    smoothed = box_mean(residual, HILL_SMALL)
    report(2 / 3, "measuring the texture")
    return box_mean(1.0 / (smoothed + _EPSILON), HILL_LARGE)


def sample_costs(pixels: np.ndarray, channels: int, progress: Progress | None = None) -> np.ndarray:
    """HiLL costs of the colour samples of an ``H x W x C`` image, in sample order.

    The order is that of :meth:`shardpix.images.Carrier.samples`: row-major,
    channel-interleaved. Each channel is filtered on its own.
    """
    report = span(progress, 0.0, 1.0)
    per_channel = []
    for c in range(channels):
        report(c / channels, "measuring the texture")
        per_channel.append(hill(pixels[..., c], span(progress, c / channels, (c + 1) / channels)))
    report(1.0, "measuring the texture")
    return np.stack(per_channel, axis=-1).reshape(-1)


# --------------------------------------------------------------------------- JPEG


def uerd(blocks: np.ndarray, quant: np.ndarray) -> np.ndarray:
    """UERD cost of changing each quantised DCT coefficient by +-1.

    Guo, Ni, Su, Tang and Shi (2015). ``blocks`` is ``Hb x Wb x 8 x 8`` (one
    8x8 block of quantised coefficients per position), ``quant`` the 8x8
    quantisation table. The energy of a block is the sum of its AC
    coefficients weighted by their quantisation steps; a change costs the
    step of its frequency divided by the energy of its block plus a quarter
    of the energy of its eight neighbours. Changes are cheap in busy blocks
    and at low frequencies, and expensive in flat blocks and where the
    quantiser is coarse.
    """
    q = quant.astype(np.float64)
    weighted = np.abs(blocks.astype(np.float64)) * q
    energy = weighted.sum(axis=(2, 3)) - weighted[:, :, 0, 0]
    padded = np.pad(energy, 1, mode="edge")
    h, w = energy.shape
    neighbours = sum(
        padded[1 + dy : 1 + dy + h, 1 + dx : 1 + dx + w]
        for dy in (-1, 0, 1)
        for dx in (-1, 0, 1)
        if (dy, dx) != (0, 0)
    )
    denominator = energy + 0.25 * neighbours + _EPSILON
    steps = q.copy()
    steps[0, 0] = 0.5 * (q[0, 1] + q[1, 0])
    return steps[None, None, :, :] / denominator[:, :, None, None]

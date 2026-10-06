"""Hand-crafted steganalysis features for trained detectors.

Two feature sets, both built from the *noise residual* of the image - what is
left after predicting each pixel from its neighbours - because that is where
+-1 embedding changes show up, and where the image content is weakest:

* **SPAM** (Pevný, Bas and Fridrich, 2010): second-order Markov transition
  probabilities of neighbouring pixel differences in eight directions,
  truncated to ``[-3, 3]``. 686 features. Designed against LSB matching.
* **SRM-lite**: a compact subset of the spatial rich model (Fridrich and
  Kodovský, 2012). Five residual families (first, second and third order
  differences, the 3x3 and 5x5 "square" kernels), each quantised, truncated
  to ``[-2, 2]`` and summarised by fourth-order co-occurrences along rows and
  columns. 3125 features. The full SRM has 34,671; this keeps the residuals
  that matter most for non-adaptive embedding while staying fast in numpy.

Every function takes a 2-D ``uint8`` array (one greyscale channel) and returns
a ``float64`` vector. Colour images are handled by averaging the features of
each channel (:func:`extract`).
"""

from __future__ import annotations

from collections.abc import Callable

import numpy as np

SPAM_T = 3
SPAM_DIM = 2 * (2 * SPAM_T + 1) ** 3
SRM_T = 2
SRM_ORDER = 4

# --------------------------------------------------------------------------- SPAM


def _markov(a: np.ndarray, b: np.ndarray, c: np.ndarray) -> np.ndarray:
    """Transition probabilities P(c | a, b) of truncated differences, as a flat vector."""
    t = SPAM_T
    side = 2 * t + 1
    index = ((a + t) * side + (b + t)) * side + (c + t)
    counts = np.bincount(index.ravel(), minlength=side**3).reshape(side, side, side)
    totals = counts.sum(axis=2, keepdims=True)
    return (counts / np.maximum(totals, 1)).reshape(-1)


def _straight(image: np.ndarray) -> np.ndarray:
    """Left-to-right transitions along rows."""
    d = np.clip(image[:, :-1] - image[:, 1:], -SPAM_T, SPAM_T)
    return _markov(d[:, :-2], d[:, 1:-1], d[:, 2:])


def _diagonal(image: np.ndarray) -> np.ndarray:
    """Top-left to bottom-right transitions along diagonals."""
    d = np.clip(image[:-1, :-1] - image[1:, 1:], -SPAM_T, SPAM_T)
    return _markov(d[:-2, :-2], d[1:-1, 1:-1], d[2:, 2:])


def spam(channel: np.ndarray) -> np.ndarray:
    """The 686 second-order SPAM features of one greyscale channel."""
    x = channel.astype(np.int16)
    straight = (x, x[:, ::-1], x.T, x.T[:, ::-1])
    diagonal = (x, x[::-1, ::-1], x[:, ::-1], x[::-1, :])
    f1 = np.mean([_straight(v) for v in straight], axis=0)
    f2 = np.mean([_diagonal(v) for v in diagonal], axis=0)
    return np.concatenate([f1, f2])


# --------------------------------------------------------------------------- SRM-lite


def _correlate(x: np.ndarray, kernel: np.ndarray) -> np.ndarray:
    """Valid-mode 2-D correlation with a small integer kernel (no scipy needed)."""
    kh, kw = kernel.shape
    h, w = x.shape[0] - kh + 1, x.shape[1] - kw + 1
    out = np.zeros((h, w), dtype=np.int32)
    for i in range(kh):
        for j in range(kw):
            k = int(kernel[i, j])
            if k:
                out += k * x[i : i + h, j : j + w]
    return out


_FIRST = np.array([[-1, 1]])
_SECOND = np.array([[1, -2, 1]])
_THIRD = np.array([[1, -3, 3, -1]])
_SQUARE3 = np.array([[-1, 2, -1], [2, -4, 2], [-1, 2, -1]])
_SQUARE5 = np.array(
    [
        [-1, 2, -2, 2, -1],
        [2, -6, 8, -6, 2],
        [-2, 8, -12, 8, -2],
        [2, -6, 8, -6, 2],
        [-1, 2, -2, 2, -1],
    ]
)

SRM_RESIDUALS: tuple[tuple[str, np.ndarray, float, bool], ...] = (
    # name, kernel, quantisation step, directional
    ("first", _FIRST, 1.0, True),
    ("second", _SECOND, 2.0, True),
    ("third", _THIRD, 3.0, True),
    ("square3", _SQUARE3, 4.0, False),
    ("square5", _SQUARE5, 12.0, False),
)
SRM_DIM = len(SRM_RESIDUALS) * (2 * SRM_T + 1) ** SRM_ORDER


def _quantise(residual: np.ndarray, q: float) -> np.ndarray:
    return np.clip(np.round(residual / q), -SRM_T, SRM_T).astype(np.int64)


def _cooccurrence(r: np.ndarray) -> np.ndarray:
    """Counts of ``SRM_ORDER`` consecutive values along the rows of ``r``."""
    side = 2 * SRM_T + 1
    n = r.shape[1] - SRM_ORDER + 1
    index = np.zeros((r.shape[0], n), dtype=np.int64)
    for k in range(SRM_ORDER):
        index = index * side + (r[:, k : k + n] + SRM_T)
    return np.bincount(index.ravel(), minlength=side**SRM_ORDER).astype(np.float64)


def srm_lite(channel: np.ndarray) -> np.ndarray:
    """The 3125 SRM-lite features of one greyscale channel."""
    x = channel.astype(np.int32)
    parts = []
    for _, kernel, q, directional in SRM_RESIDUALS:
        if directional:
            # Horizontal residual scanned along rows, vertical one along columns.
            rh = _quantise(_correlate(x, kernel), q)
            rv = _quantise(_correlate(x.T, kernel), q)
            counts = _cooccurrence(rh) + _cooccurrence(rv)
        else:
            r = _quantise(_correlate(x, kernel), q)
            counts = _cooccurrence(r) + _cooccurrence(r.T)
        parts.append(counts / counts.sum())
    return np.concatenate(parts)


# --------------------------------------------------------------------------- public API

EXTRACTORS: dict[str, Callable[[np.ndarray], np.ndarray]] = {
    "spam": spam,
    "srm_lite": srm_lite,
}
DIMENSIONS = {"spam": SPAM_DIM, "srm_lite": SRM_DIM}


def extract(pixels: np.ndarray, name: str) -> np.ndarray:
    """Features ``name`` of an ``H x W`` or ``H x W x C`` image, averaged over channels."""
    extractor = EXTRACTORS[name]
    if pixels.ndim == 2:
        return extractor(pixels)
    return np.mean([extractor(pixels[..., c]) for c in range(pixels.shape[2])], axis=0)

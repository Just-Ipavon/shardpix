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

import functools
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


# --------------------------------------------------------------------------- DCTR (JPEG)

DCTR_T = 4
DCTR_DIM = 64 * 25 * (DCTR_T + 1)


def _dct_matrix() -> np.ndarray:
    """Orthonormal 8-point DCT-II, the transform JPEG uses: ``F = D f D^T``."""
    k = np.arange(8)[:, None]
    x = np.arange(8)[None, :]
    d = np.cos(np.pi * k * (2 * x + 1) / 16) / 2
    d[0] /= np.sqrt(2)
    return d


_DCT = _dct_matrix()


def decompress(blocks: np.ndarray, quant: np.ndarray) -> np.ndarray:
    """Pixels of a greyscale JPEG from its quantised coefficients, as a decoder would."""
    hb, wb = blocks.shape[:2]
    dequantised = blocks.astype(np.float64) * quant
    pixels = np.einsum("ux,hwuv,vy->hwxy", _DCT, dequantised, _DCT) + 128
    image = pixels.transpose(0, 2, 1, 3).reshape(hb * 8, wb * 8)
    return np.clip(np.round(image), 0, 255)


def dctr_step(quality: int) -> float:
    """DCTR quantisation step for a JPEG quality factor (4 at quality 75)."""
    return 8 * (2 - quality / 50) if quality > 50 else 8 * 50 / quality


def dctr(blocks: np.ndarray, quant: np.ndarray, step: float) -> np.ndarray:
    """DCTR features (Holub and Fridrich, 2015) of a greyscale JPEG: 8000 values.

    The decompressed image is filtered with the 64 DCT basis patterns; each
    residual is quantised by ``step``, truncated to ``[0, 4]`` in magnitude
    and histogrammed separately for each position within the 8x8 grid, with
    positions merged by the symmetry ``a -> min(a, 8 - a)`` into 25 classes.
    Steganography in the coefficients perturbs exactly these statistics.
    """
    image = decompress(blocks, quant).astype(np.float32)
    h, w = image.shape
    oh, ow = h - 7, w - 7
    rows = np.empty((8, h, ow), dtype=np.float32)
    for k in range(8):
        rows[k] = sum(float(_DCT[k, t]) * image[:, t : t + ow] for t in range(8))
    phase_r = np.minimum(np.arange(oh) % 8, 8 - np.arange(oh) % 8)
    phase_c = np.minimum(np.arange(ow) % 8, 8 - np.arange(ow) % 8)
    groups = (phase_r[:, None] * 5 + phase_c[None, :]).ravel()
    per_group = np.bincount(groups, minlength=25).astype(np.float64)
    bins = DCTR_T + 1
    out = []
    for v in range(8):
        for k in range(8):
            residual = sum(float(_DCT[v, t]) * rows[k, t : t + oh, :] for t in range(8))
            values = np.minimum(np.round(np.abs(residual) / step), DCTR_T).astype(np.int64)
            counts = np.bincount(groups * bins + values.ravel(), minlength=25 * bins)
            out.append((counts.reshape(25, bins) / per_group[:, None]).ravel())
    return np.concatenate(out)


GFR_SIGMAS = (0.5, 0.75, 1.0, 1.25)
GFR_ORIENTATIONS = 32
GFR_T = 4
GFR_DIM = 4 * 2 * 17 * 25 * (GFR_T + 1)
"""17,000: 4 scales x 2 phases x 17 merged orientations x 25 grid classes x 5 bins."""


def _gabor(sigma: float, theta: float, phi: float) -> np.ndarray:
    """An 8x8 Gabor kernel of GFR: zero mean, unit L2 norm (as the DCT patterns)."""
    grid = np.arange(8) - 3.5
    y, x = np.meshgrid(grid, grid, indexing="ij")
    u = x * np.cos(theta) + y * np.sin(theta)
    v = -x * np.sin(theta) + y * np.cos(theta)
    wavelength = sigma / 0.56
    kernel = np.exp(-(u**2 + (0.5 * v) ** 2) / (2 * sigma**2)) * np.cos(
        2 * np.pi * u / wavelength + phi
    )
    kernel -= kernel.mean()
    return kernel / np.linalg.norm(kernel)


_GFR_KERNELS = np.array(
    [
        [
            [_gabor(s, np.pi * k / GFR_ORIENTATIONS, phi) for k in range(GFR_ORIENTATIONS)]
            for phi in (0.0, np.pi / 2)
        ]
        for s in GFR_SIGMAS
    ]
)
"""Shape 4 x 2 x 32 x 8 x 8: scale, phase, orientation."""


@functools.lru_cache(maxsize=2)
def _gabor_spectra(h: int, w: int) -> np.ndarray:
    """Spectra of the 256 Gabor kernels for an ``h x w`` transform, computed once per size."""
    return np.fft.rfft2(_GFR_KERNELS, s=(h, w)).astype(np.complex64)


def gfr(blocks: np.ndarray, quant: np.ndarray, step: float) -> np.ndarray:
    """GFR features (Song et al., 2015) of a greyscale JPEG: 17,000 values.

    The decompressed image is filtered with 256 Gabor kernels (4 scales,
    32 orientations, 2 phases). Each residual is quantised by ``step``
    times the scale (the coarser the filter, the larger its response),
    truncated to ``[0, 4]`` in magnitude and histogrammed per position in
    the 8x8 grid, merged into 25 classes as in :func:`dctr`. Orientations
    ``k`` and ``32 - k`` are merged, as the image statistics are symmetric,
    leaving 17 per scale and phase. Stronger than DCTR against content-
    adaptive JPEG steganography.
    """
    image = decompress(blocks, quant).astype(np.float32)
    h, w = image.shape
    oh, ow = h - 7, w - 7
    spectrum = np.fft.rfft2(image, s=(h + 7, w + 7)).astype(np.complex64)
    kernel_spectra = _gabor_spectra(h + 7, w + 7)
    phase_r = np.minimum(np.arange(oh) % 8, 8 - np.arange(oh) % 8)
    phase_c = np.minimum(np.arange(ow) % 8, 8 - np.arange(ow) % 8)
    groups = (phase_r[:, None] * 5 + phase_c[None, :]).ravel()
    per_group = np.bincount(groups, minlength=25).astype(np.float64)
    bins = GFR_T + 1
    out = []
    for si, sigma in enumerate(GFR_SIGMAS):
        q = step * sigma / GFR_SIGMAS[0]
        for pi in range(2):
            histograms = []
            for k in range(GFR_ORIENTATIONS):
                full = np.fft.irfft2(spectrum * kernel_spectra[si, pi, k], s=(h + 7, w + 7))
                residual = full[7:h, 7:w]
                values = np.minimum(np.round(np.abs(residual) / q), GFR_T).astype(np.int64)
                counts = np.bincount(groups * bins + values.ravel(), minlength=25 * bins)
                histograms.append(counts.reshape(25, bins) / per_group[:, None])
            merged = [histograms[0]]
            merged += [(histograms[k] + histograms[GFR_ORIENTATIONS - k]) / 2 for k in range(1, 16)]
            merged.append(histograms[16])
            out.extend(m.ravel() for m in merged)
    return np.concatenate(out)


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

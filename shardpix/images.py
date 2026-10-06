"""Loading and saving carrier images.

A carrier is an 8-bit image whose colour samples can hold one payload bit
each. Alpha channels are carried through untouched: transparency is too
easy to inspect visually to be a safe place for data.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import numpy as np
from PIL import Image

from .errors import UnsupportedImageError

LOSSLESS_SUFFIXES = frozenset({".png"})

_KEEP_MODES = {"L": 1, "LA": 1, "RGB": 3, "RGBA": 3}
_REJECTED_MODES = {"I", "I;16", "I;16B", "I;16L", "I;16N", "F"}


@dataclass(frozen=True)
class Carrier:
    """An image held as an ``H x W x C`` array of ``uint8`` samples."""

    pixels: np.ndarray
    mode: str
    icc_profile: bytes | None = None

    @property
    def colour_channels(self) -> int:
        """Channels that may carry payload bits (alpha excluded)."""
        return _KEEP_MODES[self.mode]

    @property
    def geometry(self) -> tuple[int, int, int]:
        """``(height, width, colour channels)``: the shape of the payload area."""
        height, width = self.pixels.shape[:2]
        return height, width, self.colour_channels

    @property
    def n_samples(self) -> int:
        """Number of samples available for payload bits."""
        height, width, channels = self.geometry
        return height * width * channels

    def samples(self) -> np.ndarray:
        """Flat copy of the colour samples in row-major, channel-interleaved order."""
        return np.ascontiguousarray(self.pixels[..., : self.colour_channels]).reshape(-1)

    def with_samples(self, samples: np.ndarray) -> Carrier:
        """Return a new carrier whose colour samples are replaced by ``samples``."""
        if samples.size != self.n_samples:
            raise ValueError(f"expected {self.n_samples} samples, got {samples.size}")
        pixels = self.pixels.copy()
        height, width, channels = self.geometry
        pixels[..., :channels] = samples.reshape(height, width, channels).astype(np.uint8)
        return replace(self, pixels=pixels)


def _normalise_mode(image: Image.Image) -> Image.Image:
    """Convert an opened image to one of the supported 8-bit modes."""
    if image.mode in _KEEP_MODES:
        return image
    if image.mode in _REJECTED_MODES:
        raise UnsupportedImageError(
            f"{image.mode} images are not supported: use an 8-bit RGB or greyscale image"
        )
    if image.mode == "1":
        return image.convert("L")
    if image.mode == "P":
        has_alpha = "transparency" in image.info
        return image.convert("RGBA" if has_alpha else "RGB")
    if image.mode == "PA":
        return image.convert("RGBA")
    return image.convert("RGB")


def from_pil(image: Image.Image) -> Carrier:
    """Build a carrier from an already opened Pillow image."""
    icc = image.info.get("icc_profile")
    image = _normalise_mode(image)
    pixels = np.array(image, dtype=np.uint8)
    if pixels.ndim == 2:
        pixels = pixels[..., np.newaxis]
    return Carrier(pixels=pixels, mode=image.mode, icc_profile=icc)


def load_image(path: str | Path) -> Carrier:
    """Read an image from disk as a carrier."""
    path = Path(path)
    try:
        with Image.open(path) as image:
            image.load()
            return from_pil(image)
    except FileNotFoundError as exc:
        raise UnsupportedImageError(f"{path}: no such file") from exc
    except (OSError, SyntaxError, ValueError) as exc:
        raise UnsupportedImageError(f"{path}: not a readable image ({exc})") from exc


def to_pil(carrier: Carrier) -> Image.Image:
    """Convert a carrier back to a Pillow image."""
    pixels = carrier.pixels
    if pixels.shape[2] == 1:
        pixels = pixels[..., 0]
    # Pillow infers L, LA, RGB or RGBA from the array shape.
    return Image.fromarray(np.ascontiguousarray(pixels))


def save_png(carrier: Carrier, path: str | Path) -> None:
    """Write a carrier as a lossless PNG.

    Any lossy format would re-quantise the samples and destroy the payload,
    so anything but ``.png`` is refused rather than silently converted.
    """
    path = Path(path)
    if path.suffix.lower() not in LOSSLESS_SUFFIXES:
        raise UnsupportedImageError(
            f"{path.name}: output must be a .png file; lossy formats such as JPEG "
            "re-compress the pixels and destroy the payload"
        )
    params: dict[str, object] = {"optimize": True}
    if carrier.icc_profile:
        params["icc_profile"] = carrier.icc_profile
    to_pil(carrier).save(path, format="PNG", **params)

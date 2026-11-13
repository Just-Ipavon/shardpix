"""Loading and saving carrier images.

A carrier is an 8-bit image whose colour samples can hold one payload bit
each. Alpha channels are carried through untouched: transparency is too
easy to inspect visually to be a safe place for data.
"""

from __future__ import annotations

import contextlib
import io
import os
import secrets
import warnings
from dataclasses import dataclass, replace
from pathlib import Path

import numpy as np
from PIL import Image

from .errors import ShardpixError, UnsupportedImageError

LOSSLESS_SUFFIXES = frozenset({".png"})

MAX_PIXELS = 130_000_000
"""Largest image read, checked from the header before any pixel is decoded.

Above the largest phone sensors (108-120 megapixels); a few kilobytes of
crafted header could otherwise claim gigapixels and exhaust memory."""

_KEEP_MODES = {"L": 1, "LA": 1, "RGB": 3, "RGBA": 3}
_REJECTED_MODES = {"I", "I;16", "I;16B", "I;16L", "I;16N", "F"}


@dataclass(frozen=True)
class Carrier:
    """An image held as an ``H x W x C`` array of ``uint8`` samples."""

    pixels: np.ndarray
    mode: str
    icc_profile: bytes | None = None
    source_format: str | None = None
    """File format the carrier was read from (``"PNG"``, ``"JPEG"``, ...), if known."""

    @property
    def from_jpeg(self) -> bool:
        """True when the pixels come from a decoded JPEG.

        Decoded JPEG pixels obey the 8x8 block quantisation of the original
        file; changing them by +-1 breaks that structure, which "JPEG
        compatibility" steganalysis can detect at any embedding rate.
        """
        return self.source_format in {"JPEG", "MPO"}

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
    source_format = image.format
    image = _normalise_mode(image)
    pixels = np.array(image, dtype=np.uint8)
    if pixels.ndim == 2:
        pixels = pixels[..., np.newaxis]
    return Carrier(pixels=pixels, mode=image.mode, icc_profile=icc, source_format=source_format)


_HEIF_BRANDS = frozenset({b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"mif1", b"msf1"})


def is_heif(path: str | Path) -> bool:
    """True for an HEIF/HEIC file (ISO-BMFF ``ftyp`` box with a HEIF brand)."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(12)
    except OSError:
        return False
    return head[4:8] == b"ftyp" and head[8:12] in _HEIF_BRANDS


def _enable_heif(path: Path) -> None:
    """Register pillow-heif's opener, or explain how to get it."""
    try:
        from pillow_heif import register_heif_opener
    except ImportError as exc:
        raise UnsupportedImageError(
            f"{path}: HEIC needs the optional decoder: pip install 'shardpix[heic]' "
            "(or set the camera to 'Most Compatible' to take JPEG photos)"
        ) from exc
    register_heif_opener()


def load_image(path: str | Path) -> Carrier:
    """Read an image from disk as a carrier.

    HEIC/HEIF photos are read through the optional ``pillow-heif`` decoder
    (``shardpix[heic]``): decoded to pixels like any other lossy input, they
    give a PNG (format 6).
    """
    path = Path(path)
    if is_heif(path):
        _enable_heif(path)
    try:
        with warnings.catch_warnings():
            # Pillow's own warning starts at 89 megapixels; MAX_PIXELS decides here.
            warnings.simplefilter("ignore", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                check_size(path, *image.size)
                check_lossless_source(path, image)
                image.load()
                return from_pil(image)
    except FileNotFoundError as exc:
        raise UnsupportedImageError(f"{path}: no such file") from exc
    except Image.DecompressionBombError as exc:
        raise UnsupportedImageError(f"{path}: image is too large ({exc})") from exc
    except (OSError, SyntaxError, ValueError) as exc:
        raise UnsupportedImageError(f"{path}: not a readable image ({exc})") from exc


def _raw_modes(image: Image.Image) -> list[str]:
    modes = []
    for tile in image.tile:
        args = tile.args if hasattr(tile, "args") else tile[3]
        mode = args if isinstance(args, str) else (args[0] if args else "")
        if isinstance(mode, str):
            modes.append(mode)
    return modes


def check_lossless_source(path: str | Path, image: Image.Image) -> None:
    """Refuse a cover that would lose data on the way to an 8-bit carrier.

    Pillow opens a 16-bit RGB PNG or TIFF as an 8-bit ``RGB`` image, and keeps
    only the first frame of an animated GIF or PNG or of a multi-page TIFF;
    the stego image would then visibly differ from its cover. Call it on an
    opened image before ``load()``, while its tiles still describe the file.
    """
    depth = image.tag_v2.get(258) if hasattr(image, "tag_v2") else None
    deep = any(";16" in m or ";32" in m for m in _raw_modes(image)) or bool(
        depth and max(depth if isinstance(depth, tuple) else (depth,)) > 8
    )
    if deep and image.mode not in _REJECTED_MODES:
        raise UnsupportedImageError(
            f"{path}: 16-bit images are not supported; export the cover as 8-bit"
        )
    frames = getattr(image, "n_frames", 1)
    if frames > 1 and image.format not in {"JPEG", "MPO"}:
        raise UnsupportedImageError(
            f"{path}: image with {frames} frames or pages; only the first would be kept. "
            "Use a single still image"
        )


def check_size(path: str | Path, width: int, height: int) -> None:
    """Refuse an image larger than :data:`MAX_PIXELS`, or with no size, before decoding it."""
    if width <= 0 or height <= 0:
        raise UnsupportedImageError(f"{path}: the header gives no image size")
    if width * height > MAX_PIXELS:
        raise UnsupportedImageError(
            f"{path}: image is too large ({width}x{height}, more than "
            f"{MAX_PIXELS // 1_000_000} megapixels)"
        )


def to_pil(carrier: Carrier) -> Image.Image:
    """Convert a carrier back to a Pillow image."""
    pixels = carrier.pixels
    if pixels.shape[2] == 1:
        pixels = pixels[..., 0]
    # Pillow infers L, LA, RGB or RGBA from the array shape.
    return Image.fromarray(np.ascontiguousarray(pixels))


def write_new(path: str | Path, data: bytes, *, overwrite: bool = False) -> None:
    """Write ``data`` to ``path``, creating it exclusively unless ``overwrite``.

    Exclusive creation (``O_CREAT | O_EXCL``) closes the gap between checking
    that a file does not exist and writing it, and refuses to follow a symbolic
    link planted at the destination, even a dangling one. Every output is
    readable by its owner only (``0o600``): a stego image, a vault or a share is
    nobody else's business on a shared machine, whatever the umask.

    Overwriting never reuses the existing file, whose mode, owner and other
    hard links would survive truncation (a world-readable file, or one another
    user created in a shared directory, would then hold the plaintext). The
    data goes to a new private file next to it, which then replaces it in one
    step, so a crash never leaves a half-written vault either.
    """
    path = Path(path)
    # Windows follows a dangling link even with exclusive creation, which
    # would redirect the write to wherever the link points: refuse it first.
    if path.is_symlink():
        raise ShardpixError(
            f"{path} is a symbolic link; give the path of a regular file"
            if overwrite
            else f"{path} already exists; use --force to overwrite it"
        )
    if not overwrite:
        try:
            _create_private(path, data)
        except FileExistsError as exc:
            raise ShardpixError(f"{path} already exists; use --force to overwrite it") from exc
        except OSError as exc:
            raise ShardpixError(f"cannot write {path}: {exc.strerror or exc}") from exc
        return
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        _create_private(temporary, data)
        os.replace(temporary, path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise ShardpixError(f"cannot write {path}: {exc.strerror or exc}") from exc


def _create_private(path: Path, data: bytes) -> None:
    """Create ``path`` exclusively with mode ``0o600`` and write ``data`` to disk."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def save_png(carrier: Carrier, path: str | Path, *, overwrite: bool = False) -> None:
    """Write a carrier as a lossless PNG (default zlib level; ``optimize`` costs 8x the time).

    Any lossy format would re-quantise the samples and destroy the payload,
    so anything but ``.png`` is refused rather than silently converted.
    """
    path = Path(path)
    if path.suffix.lower() not in LOSSLESS_SUFFIXES:
        raise UnsupportedImageError(
            f"{path.name}: output must be a .png file; lossy formats such as JPEG "
            "re-compress the pixels and destroy the payload"
        )
    params: dict[str, object] = {}
    if carrier.icc_profile:
        params["icc_profile"] = carrier.icc_profile
    buffer = io.BytesIO()
    to_pil(carrier).save(buffer, format="PNG", **params)
    write_new(path, buffer.getvalue(), overwrite=overwrite)

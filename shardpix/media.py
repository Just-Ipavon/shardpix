"""One entry point for both kinds of cover: lossless pixels and JPEG.

A cover is embedded the way its file is stored:

* **JPEG** (every phone camera): in the quantised DCT coefficients, written
  back as a JPEG with the same tables and metadata (:mod:`shardpix.jpeg`,
  format 5);
* **anything else Pillow reads** (PNG, TIFF, BMP, RAW exports): in the
  pixels, written as PNG (:mod:`shardpix.stego`, format 4).

The choice is made from the file's first bytes, not its name, and the
output keeps the matching extension. Callers - the vault and the CLI - see
one ``open_cover`` / ``hide`` / ``reveal`` interface and never decide
between the two.
"""

from __future__ import annotations

import io
import os
from dataclasses import dataclass
from pathlib import Path

from . import jpeg, stego
from .images import Carrier, load_image, to_pil


@dataclass(frozen=True)
class Cover:
    """A cover image opened for embedding, in the domain its file uses."""

    path: Path
    pixels: Carrier | None = None
    coefficients: jpeg.JpegCover | None = None

    @property
    def is_jpeg(self) -> bool:
        return self.coefficients is not None

    @property
    def suffix(self) -> str:
        """Extension of the stego file: the cover's own kind."""
        return ".jpg" if self.is_jpeg else ".png"

    @property
    def format_name(self) -> str:
        return "JPEG (format 5)" if self.is_jpeg else "PNG (format 4)"

    def capacity(self) -> int:
        """Largest payload, in bytes, this cover can hold."""
        if self.coefficients is not None:
            return jpeg.capacity(self.coefficients)
        return stego.carrier_capacity(self._pixels())

    def _pixels(self) -> Carrier:
        if self.pixels is None:
            raise ValueError("cover holds neither pixels nor coefficients")
        return self.pixels


def kind_suffix(path: str | Path) -> str:
    """Extension the stego file of ``path`` will have, read from its first bytes."""
    return ".jpg" if jpeg.is_jpeg(path) else ".png"


def open_cover(path: str | Path) -> Cover:
    """Open ``path`` in the domain matching its file format."""
    path = Path(path)
    if jpeg.is_jpeg(path):
        return Cover(path, coefficients=jpeg.load(path))
    return Cover(path, pixels=load_image(path))


def encode_png(carrier: Carrier) -> bytes:
    """A carrier as PNG bytes, keeping its ICC profile."""
    params: dict[str, object] = {}
    if carrier.icc_profile:
        params["icc_profile"] = carrier.icc_profile
    buffer = io.BytesIO()
    to_pil(carrier).save(buffer, format="PNG", **params)
    return buffer.getvalue()


def hide(
    cover: Cover,
    payload: bytes,
    passphrase: str | None = None,
    random_bytes: stego.RandomBytes = os.urandom,
    method: stego.Method = stego.Method.ADAPTIVE,
) -> tuple[bytes, stego.EmbedReport]:
    """Embed ``payload``; return the stego file's bytes and a report.

    ``method`` only applies to pixel covers. Formats other than adaptive are
    kept for the benchmarks that compare against them, not for real use.
    """
    if cover.coefficients is not None:
        return jpeg.embed(cover.coefficients, payload, passphrase, random_bytes)
    stego_carrier, report = stego.embed(cover._pixels(), payload, passphrase, method, random_bytes)
    return encode_png(stego_carrier), report


def reveal(path: str | Path, passphrase: str | None = None) -> bytes:
    """Recover the payload of a stego file, whatever its kind."""
    cover = open_cover(path)
    if cover.coefficients is not None:
        return jpeg.extract(cover.coefficients, passphrase)
    return stego.extract(cover._pixels(), passphrase)

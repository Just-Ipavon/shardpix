"""Adaptive steganography inside JPEG files (stego format 5).

Phone cameras save JPEG. Hiding data in the decoded pixels of a JPEG and
saving PNG is detectable at any rate, because the pixels of a decoded JPEG
obey its 8x8 block quantisation (docs/07 §7.2). This module never decodes
the image: it changes the quantised DCT coefficients themselves and writes
a JPEG with the same quantisation tables and the same metadata (EXIF, ICC),
so the result is an ordinary camera JPEG with a few coefficients moved by
+-1.

**Where.** Only non-zero AC coefficients of the luminance carry data. Zero
coefficients are never touched (making one non-zero is the most detectable
change in JPEG steganography), DC coefficients neither, and a coefficient
at +-1 always moves away from zero. The set of usable coefficients is
therefore identical before and after embedding, and the extractor rebuilds
it from the stego file with no side information.

**How.** Exactly as format 4 (:mod:`shardpix.stego`): the public salt and
cost, the masked length and the sealed body are syndrome-trellis codes over
public or keyed candidate coefficients, and the coder picks the changes
with the lowest UERD cost (:func:`shardpix.costs.uerd`). Keys come from
their own domain, so a JPEG payload never shares a key with a PNG one.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import jpeglib
import numpy as np

from . import costs, stego
from .errors import CapacityError, PayloadNotFoundError, UnsupportedImageError
from .progress import Progress, span

VERSION = stego.JPEG_VERSION
MAX_COEFFICIENT = 1023
"""Largest magnitude of a baseline 8-bit JPEG coefficient."""

JPEG_MAGIC = b"\xff\xd8\xff"


def is_jpeg(path: str | Path) -> bool:
    """True when the file starts with the JPEG start-of-image marker."""
    try:
        with open(path, "rb") as handle:
            return handle.read(3) == JPEG_MAGIC
    except OSError:
        return False


@dataclass
class JpegCover:
    """A JPEG file held as quantised DCT coefficients."""

    path: Path
    image: jpeglib.DCTJPEG

    @property
    def blocks(self) -> np.ndarray:
        """Luminance coefficients, ``Hb x Wb x 8 x 8``."""
        return self.image.Y

    @property
    def quant(self) -> np.ndarray:
        """Quantisation table of the luminance."""
        return self.image.qt[self.image.quant_tbl_no[0]]

    def coefficients(self) -> np.ndarray:
        """Flat copy of the luminance coefficients, block by block."""
        return self.blocks.astype(np.int32).reshape(-1)

    def geometry(self) -> tuple[int, int]:
        return int(self.image.height), int(self.image.width)


def load(path: str | Path) -> JpegCover:
    """Read a JPEG's coefficients without decoding its pixels."""
    path = Path(path)
    if not is_jpeg(path):
        raise UnsupportedImageError(f"{path}: not a JPEG file")
    try:
        image = jpeglib.read_dct(str(path))
        image.load()
    except Exception as exc:  # noqa: BLE001 - libjpeg errors have no common type
        raise UnsupportedImageError(f"{path}: not a readable JPEG ({exc})") from exc
    if image.Y is None:
        raise UnsupportedImageError(f"{path}: JPEG without a luminance component")
    return JpegCover(path, image)


def eligible_mask(coefficients: np.ndarray) -> np.ndarray:
    """Non-zero AC coefficients: the only ones that may carry payload bits."""
    ac = np.ones(64, dtype=bool)
    ac[0] = False
    is_ac = np.tile(ac, coefficients.size // 64)
    return is_ac & (coefficients != 0)


def capacity(cover: JpegCover) -> int:
    """Largest payload, in bytes, that ``cover`` can hold."""
    return stego.capacity(int(np.count_nonzero(eligible_mask(cover.coefficients()))))


def _apply(
    coefficients: np.ndarray, flips: np.ndarray, random_bytes: stego.RandomBytes
) -> np.ndarray:
    """Move each flipped coefficient by +-1 without ever reaching 0 or the range limit."""
    out = coefficients.copy()
    values = out[flips]
    step = np.where(np.frombuffer(random_bytes(flips.size), dtype=np.uint8) & 1, 1, -1)
    step = np.where(values == 1, 1, np.where(values == -1, -1, step))
    step = np.where(values >= MAX_COEFFICIENT, -1, np.where(values <= -MAX_COEFFICIENT, 1, step))
    out[flips] = values + step
    return out


def embed(
    cover: JpegCover,
    payload: bytes,
    passphrase: str | None = None,
    random_bytes: stego.RandomBytes = os.urandom,
    progress: Progress | None = None,
) -> tuple[bytes, stego.EmbedReport]:
    """Hide ``payload`` in ``cover``; return the stego JPEG file and a report."""
    coefficients, report = embed_coefficients(
        cover.coefficients(),
        cover.blocks.shape,
        cover.quant,
        payload,
        passphrase,
        random_bytes,
        span(progress, 0.0, 0.9),
    )
    span(progress, 0.0, 1.0)(0.9, "writing the JPEG")
    return _encode(cover, coefficients), report


def embed_coefficients(
    coefficients: np.ndarray,
    shape: tuple[int, ...],
    quant: np.ndarray,
    payload: bytes,
    passphrase: str | None = None,
    random_bytes: stego.RandomBytes = os.urandom,
    progress: Progress | None = None,
) -> tuple[np.ndarray, stego.EmbedReport]:
    """The core of :func:`embed`, on a flat array of luminance coefficients.

    ``shape`` is the ``Hb x Wb x 8 x 8`` shape the coefficients come from and
    ``quant`` the luminance quantisation table. Benchmarks use it directly,
    without writing files.
    """
    eligible = eligible_mask(coefficients)
    n_eligible = int(np.count_nonzero(eligible))
    room = stego.max_frame_bytes(n_eligible) - stego.FRAME_OVERHEAD
    if room < 0:
        raise CapacityError("this JPEG has too few non-zero coefficients to hold any payload")
    if len(payload) > room:
        raise CapacityError(
            f"payload is {len(payload)} bytes but this image holds at most {room} bytes"
        )
    salt = random_bytes(stego.SALT_BYTES)
    log_n = stego.SCRYPT_LOG_N
    report_step = span(progress, 0.0, 1.0)
    report_step(0.0, "deriving the key")
    key = stego.derive_key(passphrase, salt, log_n, VERSION)
    frame = stego.build_frame(payload, key, random_bytes, VERSION)
    public = salt + bytes([log_n | stego.ADAPTIVE_FLAG])
    frame_bits = stego._to_bits(frame)

    hw = stego.header_width(n_eligible)
    public_positions = stego._salt_positions(coefficients.size, eligible, hw)
    order = stego._keyed_order(key, eligible, public_positions)
    body = frame_bits[stego.LENGTH_BITS :]
    free = order.n_samples - stego.LENGTH_BITS * hw
    if body.size > free:
        raise CapacityError("this JPEG is too small for this payload")
    width = stego.code_width(free, body.size)
    keyed = order.first(stego.LENGTH_BITS * hw + width * body.size)
    report_step(0.2, "measuring the texture")
    rho = costs.uerd(coefficients.reshape(shape), quant).reshape(-1)

    out, changed = coefficients, 0
    length_positions = keyed[: stego.LENGTH_BITS * hw]
    for positions, part, seed, steps in (
        (public_positions, stego._to_bits(public), stego._PUBLIC_CODE_SEED, None),
        (length_positions, frame_bits[: stego.LENGTH_BITS], stego._length_seed(key), None),
        (keyed[stego.LENGTH_BITS * hw :], body, key.code, span(progress, 0.35, 1.0)),
    ):
        flips = stego.choose_flips(out, positions, part, rho, seed, steps)
        out = _apply(out, flips, random_bytes)
        changed += int(flips.size)

    report = stego.EmbedReport(
        payload_bytes=len(payload),
        frame_bytes=len(frame),
        capacity_bytes=room,
        samples=coefficients.size,
        eligible_samples=n_eligible,
        bits_written=int(stego.PUBLIC_BITS + frame_bits.size),
        samples_changed=changed,
    )
    return out, report


def _encode(cover: JpegCover, coefficients: np.ndarray) -> bytes:
    """The JPEG file with new luminance coefficients and everything else unchanged."""
    image = cover.image.copy()
    image.Y = coefficients.reshape(cover.blocks.shape).astype(cover.blocks.dtype)
    with tempfile.TemporaryDirectory(prefix="shardpix-") as directory:
        target = Path(directory) / "stego.jpg"
        image.write_dct(str(target))
        return target.read_bytes()


def _not_found() -> PayloadNotFoundError:
    return stego._not_found()


def extract(cover: JpegCover, passphrase: str | None = None) -> bytes:
    """Recover and authenticate the payload hidden in a JPEG by :func:`embed`."""
    coefficients = cover.coefficients()
    eligible = eligible_mask(coefficients)
    n_eligible = int(np.count_nonzero(eligible))
    largest_frame = stego.max_frame_bytes(n_eligible)
    if largest_frame < stego.FRAME_OVERHEAD:
        raise _not_found()

    hw = stego.header_width(n_eligible)
    public_positions = stego._salt_positions(coefficients.size, eligible, hw)
    public = stego._bytes(
        stego.read_adaptive(
            coefficients, public_positions, stego.PUBLIC_BITS, stego._PUBLIC_CODE_SEED
        )
    )
    salt, cost_byte = public[: stego.SALT_BYTES], public[stego.SALT_BYTES]
    if not cost_byte & stego.ADAPTIVE_FLAG:
        raise _not_found()
    log_n = cost_byte & ~stego.ADAPTIVE_FLAG
    if log_n not in stego.SCRYPT_LOG_N_ACCEPTED:
        raise _not_found()
    key = stego.derive_key(passphrase, salt, log_n, VERSION)
    order = stego._keyed_order(key, eligible, public_positions)

    header_samples = stego.LENGTH_BITS * hw
    header = stego._bytes(
        stego.read_adaptive(
            coefficients, order.first(header_samples), stego.LENGTH_BITS, stego._length_seed(key)
        )
    )
    length = int.from_bytes(stego._xor(header, key.length_mask), "big")
    if length < stego.NONCE_BYTES + stego.TAG_BYTES or stego.LENGTH_BYTES + length > largest_frame:
        raise _not_found()
    body_bits = 8 * length
    free = order.n_samples - header_samples
    if body_bits > free:
        raise _not_found()
    width = stego.code_width(free, body_bits)
    positions = order.first(header_samples + width * body_bits)[header_samples:]
    sealed = stego._bytes(stego.read_adaptive(coefficients, positions, body_bits, key.code))
    nonce, body = sealed[: stego.NONCE_BYTES], sealed[stego.NONCE_BYTES :]
    try:
        return stego.AESGCM(key.aead).decrypt(nonce, body, stego._aad(length, VERSION))
    except stego.InvalidTag:
        raise _not_found() from None

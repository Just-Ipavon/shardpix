"""Adaptive steganography inside JPEG files (stego format 7; format 5 is still read).

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

**How.** Exactly as the PNG format (:mod:`shardpix.stego`): the public salt,
the masked length and the sealed body are syndrome-trellis codes over
public or keyed candidate coefficients, and the coder picks the changes
with the lowest UERD cost (:func:`shardpix.costs.uerd`). Keys come from
their own domain, so a JPEG payload never shares a key with a PNG one.
Format 5 also wrote the scrypt cost in a public byte, a constant anyone
could decode without a key (docs/06 SR-07); format 7 writes only the salt.
"""

from __future__ import annotations

import dataclasses
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import jpeglib
import numpy as np

from . import costs, stego
from .errors import CapacityError, PayloadNotFoundError, UnsupportedImageError
from .images import check_size
from .progress import Progress, span

VERSION = stego.JPEG_VERSION
LEGACY_VERSION = stego.JPEG_LEGACY_VERSION
MAX_COEFFICIENT = 1023
"""Largest magnitude of a baseline 8-bit JPEG coefficient."""

JPEG_MAGIC = b"\xff\xd8\xff"

SAFE_QUALITY = 90
"""Estimated quality below which a JPEG cover is reported as recompressed.

At quality 95 format 5 is at chance against DCTR even with fifty images of
one vault pooled; at quality 75 it falls to 7.8% (docs/05 §5.5.8). Phones
save at 90 or more; chat apps and social networks recompress to 70-85.
"""

# Luminance table of the JPEG standard (ITU-T T.81, Annex K), row by row.
_STANDARD_LUMINANCE = np.array(
    [
        [16, 11, 10, 16, 24, 40, 51, 61],
        [12, 12, 14, 19, 26, 58, 60, 55],
        [14, 13, 16, 24, 40, 57, 69, 56],
        [14, 17, 22, 29, 51, 87, 80, 62],
        [18, 22, 37, 56, 68, 109, 103, 77],
        [24, 35, 55, 64, 81, 104, 113, 92],
        [49, 64, 78, 87, 103, 121, 120, 101],
        [72, 92, 95, 98, 112, 100, 103, 99],
    ],
    dtype=np.float64,
)


def standard_table(quality: int) -> np.ndarray:
    """The luminance table libjpeg writes at ``quality`` (1-100)."""
    scale = 5000 / quality if quality < 50 else 200 - 2 * quality
    return np.clip(np.floor((_STANDARD_LUMINANCE * scale + 50) / 100), 1, 255)


def estimate_quality(quant: np.ndarray) -> int:
    """The libjpeg quality whose luminance table is closest to ``quant``.

    Exact for files written with the standard tables (libjpeg, Pillow, most
    editors); for the custom tables of phone cameras it gives the standard
    quality with the most similar quantisation, which is what matters for
    how much room the coefficients leave.
    """
    table = np.asarray(quant, dtype=np.float64).reshape(8, 8)
    errors = [np.abs(np.log(standard_table(q)) - np.log(table)).sum() for q in range(1, 101)]
    return int(np.argmin(errors)) + 1


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

    @property
    def quality(self) -> int:
        """Estimated JPEG quality, from the luminance quantisation table."""
        return estimate_quality(self.quant)


def load(path: str | Path) -> JpegCover:
    """Read a JPEG's coefficients without decoding its pixels."""
    path = Path(path)
    if not is_jpeg(path):
        raise UnsupportedImageError(f"{path}: not a JPEG file")
    check_size(path, *_dimensions(path))
    try:
        image = jpeglib.read_dct(str(path))
        image.load()
    except Exception as exc:  # noqa: BLE001 - libjpeg errors have no common type
        raise UnsupportedImageError(f"{path}: not a readable JPEG ({exc})") from exc
    if image.Y is None:
        raise UnsupportedImageError(f"{path}: JPEG without a luminance component")
    return JpegCover(path, image)


_SOF_MARKERS = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}


def _dimensions(path: Path) -> tuple[int, int]:
    """Width and height from the frame header, read before libjpeg allocates anything."""
    try:
        segments, _ = _segments(path.read_bytes())
    except OSError as exc:
        raise UnsupportedImageError(f"{path}: cannot read ({exc.strerror or exc})") from exc
    for marker, segment in segments:
        if marker in _SOF_MARKERS and len(segment) >= 9:
            height = int.from_bytes(segment[5:7], "big")
            width = int.from_bytes(segment[7:9], "big")
            return width, height
    raise UnsupportedImageError(f"{path}: JPEG without a frame header")


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
    data, kept = _encode(cover, coefficients)
    return data, dataclasses.replace(report, structure_kept=kept)


def embed_coefficients(
    coefficients: np.ndarray,
    shape: tuple[int, ...],
    quant: np.ndarray,
    payload: bytes,
    passphrase: str | None = None,
    random_bytes: stego.RandomBytes = os.urandom,
    progress: Progress | None = None,
    *,
    version: int = VERSION,
) -> tuple[np.ndarray, stego.EmbedReport]:
    """The core of :func:`embed`, on a flat array of luminance coefficients.

    ``shape`` is the ``Hb x Wb x 8 x 8`` shape the coefficients come from and
    ``quant`` the luminance quantisation table. Benchmarks use it directly,
    without writing files, and with ``version=5`` so that the published
    measurements stay reproducible.
    """
    if version not in (VERSION, LEGACY_VERSION):
        raise ValueError(f"JPEG covers take format {VERSION} or {LEGACY_VERSION}")
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
    key = stego.derive_key(passphrase, salt, log_n, version)
    frame = stego.build_frame(payload, key, random_bytes, version)
    public = stego.public_block(salt, version, log_n)
    frame_bits = stego._to_bits(frame)

    hw = stego.header_width(n_eligible)
    public_positions = stego._salt_positions(
        coefficients.size, eligible, hw, stego.public_bits(version)
    )
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
        bits_written=int(8 * len(public) + frame_bits.size),
        samples_changed=changed,
    )
    return out, report


_META_MARKERS = frozenset(range(0xE0, 0xF0)) | {0xFE}
"""APPn and COM: metadata, copied from the cover byte for byte."""
_DQT, _DHT, _SOS = 0xDB, 0xC4, 0xDA


def _segments(data: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """The header segments ``(marker, bytes)`` after SOI, and the rest from the first SOS."""
    segments, i = [], 2
    while True:
        if i + 4 > len(data) or data[i] != 0xFF:
            raise UnsupportedImageError("malformed JPEG header")
        marker = data[i + 1]
        if marker == 0xFF:  # fill byte
            i += 1
            continue
        if marker == _SOS:
            return segments, data[i:]
        length = int.from_bytes(data[i + 2 : i + 4], "big")
        if length < 2 or i + 2 + length > len(data):
            raise UnsupportedImageError("malformed JPEG segment")
        segments.append((marker, data[i : i + 2 + length]))
        i += 2 + length


def _tables(marker: int, segment: bytes) -> list[tuple[int, bytes]]:
    """The tables of a DQT or DHT segment, keyed by their class/id byte."""
    body, tables, j = segment[4:], [], 0
    while j < len(body):
        if marker == _DQT:
            size = 1 + (128 if body[j] >> 4 else 64)
        else:
            size = 17 + sum(body[j + 1 : j + 17])
        tables.append((body[j], body[j : j + size]))
        j += size
    return tables


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


def _huffman(segments: list[tuple[int, bytes]]) -> dict[int, bytes]:
    return {k: t for m, s in segments if m == _DHT for k, t in _tables(m, s)}


def _match_structure(source: bytes, encoded: bytes) -> tuple[bytes, bool]:
    """``encoded`` laid out like ``source``: same metadata, same segments in the same order.

    libjpeg writes its own JFIF header, then the cover's markers (so APP0
    appears twice, and a cover with only EXIF gains a JFIF it never had), and
    one table per segment in its own order. Here the metadata comes from the
    cover byte for byte and the tables are regrouped into the cover's
    segments. Returns the file and whether the layout could be matched; when
    it cannot (a progressive cover, restart markers libjpeg does not write),
    the cover's metadata are still restored.
    """
    src, _ = _segments(source)
    out, scan = _segments(encoded)
    tables = {(m, k): t for m, s in out if m in (_DQT, _DHT) for k, t in _tables(m, s)}
    others = {m: s for m, s in out if m not in _META_MARKERS and m not in (_DQT, _DHT)}
    used, layout = set(), []
    for marker, segment in src:
        if marker in _META_MARKERS:
            layout.append(segment)
        elif marker in (_DQT, _DHT):
            keys = [(marker, k) for k, _ in _tables(marker, segment)]
            if not all(key in tables for key in keys):
                break
            layout.append(_segment(marker, b"".join(tables[key] for key in keys)))
            used.update(keys)
        elif marker in others:
            layout.append(others[marker])
            used.add(marker)
        else:
            break
    else:
        if used == set(tables) | set(others):
            return b"\xff\xd8" + b"".join(layout) + scan, True
    meta = [s for m, s in src if m in _META_MARKERS]
    rest = [s for m, s in out if m not in _META_MARKERS]
    return b"\xff\xd8" + b"".join(meta + rest) + scan, False


def _encode(cover: JpegCover, coefficients: np.ndarray) -> tuple[bytes, bool]:
    """The JPEG file with new luminance coefficients, laid out like the cover.

    The coefficients of every component are written losslessly. Huffman
    tables are libjpeg's standard ones if the cover has them, optimised ones
    otherwise (cameras and editors that optimise produce per-image tables).
    Returns the file and whether its structure matches the cover's
    (:func:`_match_structure`).
    """
    image = cover.image.copy()
    image.Y = coefficients.reshape(cover.blocks.shape).astype(cover.blocks.dtype)
    source = cover.path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="shardpix-") as directory:
        target = Path(directory) / "stego.jpg"
        image.write_dct(str(target))
        encoded = target.read_bytes()
        if _huffman(_segments(encoded)[0]) != _huffman(_segments(source)[0]):
            image.write_dct(str(target), flags=["+OPTIMIZE_CODING"])
            encoded = target.read_bytes()
    return _match_structure(source, encoded)


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

    for version in (VERSION, LEGACY_VERSION):
        try:
            return _extract(coefficients, eligible, n_eligible, largest_frame, passphrase, version)
        except PayloadNotFoundError:
            continue
    raise _not_found()


def _extract(
    coefficients: np.ndarray,
    eligible: np.ndarray,
    n_eligible: int,
    largest_frame: int,
    passphrase: str | None,
    version: int,
) -> bytes:
    hw = stego.header_width(n_eligible)
    bits = stego.public_bits(version)
    public_positions = stego._salt_positions(coefficients.size, eligible, hw, bits)
    public = stego._bytes(
        stego.read_adaptive(coefficients, public_positions, bits, stego._PUBLIC_CODE_SEED)
    )
    salt, log_n = stego.parse_public(public, version)
    key = stego.derive_key(passphrase, salt, log_n, version)
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
        return stego.AESGCM(key.aead).decrypt(nonce, body, stego._aad(length, version))
    except stego.InvalidTag:
        raise _not_found() from None

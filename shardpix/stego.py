"""Keyed LSB steganography with an authenticated, encrypted payload.

The payload is never written to the image as-is. It is sealed with
AES-256-GCM, framed, and the frame bits are written into carrier samples
picked by a keyed pseudo-random walk. Without the passphrase an observer can
neither tell which samples were used nor distinguish the bits from noise.

**Per-image salt.** Every embedding draws a fresh 128-bit salt and writes it
first, with the scrypt cost, into samples chosen by a *public* walk (the
extractor must read them before it has a key). The keys are derived from the
passphrase and that salt, so two images sealed with the same passphrase use
unrelated keys and unrelated positions, and scrypt work cannot be
precomputed for common image sizes. Storing the cost lets it be raised in
future versions without breaking existing images.

**Eligible samples.** Only samples in the range 2-253 carry data, and
embedding never moves a sample out of that range. Samples at 0 or 255 can
only move one way, and in photos with clipped regions those forced moves
look exactly like LSB replacement to RS steganalysis; skipping them removes
almost all forced moves (only samples at exactly 2 or 253 keep a fixed
direction). Because the eligible set is identical before and after
embedding, the extractor recomputes it without any side information.

**Capacity.** At most half of the eligible samples are used. Beyond that an
image is easy prey for steganalysis anyway, and the keyed walk - which costs
time in proportion to the payload, not the image - would slow down sharply.

Layout, in the order the bits are written::

    salt    16 bytes   public walk; random per embedding
    cost     1 byte    public walk; log2 of the scrypt N parameter
    length   4 bytes   keyed walk from here on: size of nonce + body, XOR-masked
    nonce   12 bytes   AES-256-GCM nonce
    body     n bytes   AES-256-GCM ciphertext followed by its 16-byte tag
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import costs, stc
from .errors import CapacityError, PayloadNotFoundError
from .images import Carrier
from .progress import Progress, span

FORMAT_VERSION = 4
"""Format written by :attr:`Method.ADAPTIVE`; the other methods write format 3."""
LEGACY_VERSION = 3
SALT_BYTES = 16
COST_BYTES = 1
PUBLIC_BYTES = SALT_BYTES + COST_BYTES
PUBLIC_BITS = PUBLIC_BYTES * 8
LENGTH_BYTES = 4
NONCE_BYTES = 12
TAG_BYTES = 16
FRAME_OVERHEAD = LENGTH_BYTES + NONCE_BYTES + TAG_BYTES
"""Bytes added to every payload by the keyed frame (the salt is accounted for separately)."""

SCRYPT_LOG_N = 17
"""log2 of scrypt's N for new embeddings: N = 2^17, r = 8, p = 1 is OWASP's first choice."""
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LOG_N_ACCEPTED = range(10, 19)
"""Costs accepted when extracting; the upper bound caps memory at 256 MiB per attempt."""

ELIGIBLE_MIN = 2
ELIGIBLE_MAX = 253
"""Samples outside this range are never used and never produced."""

MAX_FILL = 2
"""Use at most one in ``MAX_FILL`` of the eligible samples."""

ADAPTIVE_FLAG = 0x80
"""Set in the public cost byte of a format-4 image; format 3 stores the bare cost."""
MAX_WIDTH = 128
"""Widest syndrome-trellis code: up to 128 candidate samples per payload bit."""
COLUMN_BUDGET = 1 << 20
"""Most samples the trellis visits for one payload, which bounds the time to embed."""
CHUNK_BITS = 1 << 13
"""Payload bits coded per trellis, which bounds its memory."""
HEADER_WIDTH = 64
"""Width of the codes carrying the public bytes and the length in format 4."""
LENGTH_BITS = LENGTH_BYTES * 8

JPEG_VERSION = 5
"""Format of payloads in JPEG coefficients (:mod:`shardpix.jpeg`)."""

_DOMAIN = b"shardpix/stego/v3"
_DOMAIN_V4 = b"shardpix/stego/v4"
_DOMAINS = {LEGACY_VERSION: _DOMAIN, FORMAT_VERSION: _DOMAIN_V4, JPEG_VERSION: b"shardpix/jpeg/v1"}
_PUBLIC_WALK_KEY = hashlib.sha256(_DOMAIN + b"|salt-walk").digest()
_PUBLIC_CODE_SEED = hashlib.sha256(_DOMAIN_V4 + b"|public-code").digest()

RandomBytes = Callable[[int], bytes]


class Method(str, Enum):
    """How a sample is changed when its LSB does not already match the bit."""

    MATCHING = "matching"
    """Add or subtract 1 at random (LSB matching, also known as +-1 embedding)."""

    REPLACEMENT = "replacement"
    """Overwrite the least significant bit (classic LSB replacement)."""

    ADAPTIVE = "adaptive"
    """+-1 changes placed by a syndrome-trellis code where HiLL costs are lowest (format 4)."""


@dataclass(frozen=True)
class StegoKey:
    """Key material derived from a passphrase and a per-image salt."""

    order: bytes
    aead: bytes
    length_mask: bytes
    keyed: bool
    code: bytes = b""
    """Seed of the syndrome-trellis submatrix (format 4 only)."""


@dataclass(frozen=True)
class EmbedReport:
    """What an embedding did to the carrier."""

    payload_bytes: int
    frame_bytes: int
    capacity_bytes: int
    samples: int
    """All colour samples in the carrier."""
    eligible_samples: int
    """Samples in the usable 2-253 range."""
    bits_written: int
    """Salt and frame bits."""
    samples_changed: int

    @property
    def embedding_rate(self) -> float:
        """Fraction of carrier samples that hold a payload bit."""
        return self.bits_written / self.samples if self.samples else 0.0

    @property
    def change_rate(self) -> float:
        """Fraction of carrier samples whose value actually changed."""
        return self.samples_changed / self.samples if self.samples else 0.0


def derive_key(
    passphrase: str | None,
    salt: bytes,
    log_n: int | None = None,
    version: int = LEGACY_VERSION,
) -> StegoKey:
    """Derive the walk, encryption and masking keys for one embedding.

    scrypt makes every passphrase guess expensive, and the per-image salt
    means guesses cannot be shared between images. Without a passphrase the
    keys depend on the salt alone: the payload is still scattered and
    encrypted, but anyone running shardpix can read it. Each format version
    has its own domain, so the two never share a key.
    """
    domain = _DOMAINS[version]
    if len(salt) != SALT_BYTES:
        raise ValueError(f"salt must be {SALT_BYTES} bytes")
    if log_n is None:
        log_n = SCRYPT_LOG_N
    if log_n not in SCRYPT_LOG_N_ACCEPTED:
        raise ValueError(f"scrypt cost 2^{log_n} is outside the accepted range")
    if passphrase:
        secret = unicodedata.normalize("NFC", passphrase).encode("utf-8")
        n = 1 << log_n
        master = hashlib.scrypt(
            secret,
            salt=domain + b"|" + salt,
            n=n,
            r=SCRYPT_R,
            p=SCRYPT_P,
            maxmem=2 * 128 * SCRYPT_R * n,
            dklen=32,
        )
    else:
        master = hashlib.sha256(domain + b"|public|" + salt).digest()

    def expand(label: bytes, length: int) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=domain + b"|" + label)
        return hkdf.derive(master)

    return StegoKey(
        order=expand(b"order", 32),
        aead=expand(b"aead", 32),
        length_mask=expand(b"length", LENGTH_BYTES),
        keyed=bool(passphrase),
        code=expand(b"code", 32) if version != LEGACY_VERSION else b"",
    )


def eligible_mask(samples: np.ndarray) -> np.ndarray:
    """Boolean mask of the samples that may carry payload bits."""
    return (samples >= ELIGIBLE_MIN) & (samples <= ELIGIBLE_MAX)


class SampleOrder:
    """A keyed pseudo-random walk over the eligible carrier samples.

    The walk reads 64-bit words from a ChaCha20 keystream, reduces each to a
    sample index (rejecting the few words that would bias the modulo), and
    keeps every index the first time it appears, if that sample is eligible.
    A stream cipher is used rather than ``numpy.random`` because the
    positions must be unpredictable to anyone without the key.

    The walk is a fixed sequence: how the stream is read in batches does not
    change it, every prefix of it is stable, and the work is proportional to
    the number of positions drawn rather than to the size of the image.
    """

    _BATCH_MIN = 1024
    _BATCH_MAX = 1 << 20

    def __init__(self, key: bytes, n_samples: int, eligible: np.ndarray | None = None) -> None:
        if eligible is None:
            eligible = np.ones(n_samples, dtype=bool)
        elif eligible.shape != (n_samples,):
            raise ValueError("eligibility mask does not match the number of samples")
        self._size = n_samples
        self._free = eligible.copy()
        self.n_samples = int(np.count_nonzero(eligible))
        """Number of samples the walk can visit."""
        self._stream = Cipher(algorithms.ChaCha20(key, bytes(16)), mode=None).encryptor()
        span = 1 << 64
        self._limit = None if n_samples == 0 or span % n_samples == 0 else span - span % n_samples
        self._order = np.empty(0, dtype=np.intp)

    def _extend(self, count: int) -> None:
        chunks = [self._order]
        found = self._order.size
        while found < count:
            batch = min(self._BATCH_MAX, max(self._BATCH_MIN, 2 * (count - found)))
            words = np.frombuffer(self._stream.update(bytes(8 * batch)), dtype="<u8")
            if self._limit is not None:
                words = words[words < np.uint64(self._limit)]
            candidates = (words % np.uint64(self._size)).astype(np.intp)
            candidates = candidates[self._free[candidates]]
            _, first = np.unique(candidates, return_index=True)
            accepted = candidates[np.sort(first)]
            self._free[accepted] = False
            chunks.append(accepted)
            found += accepted.size
        self._order = np.concatenate(chunks)

    def first(self, count: int) -> np.ndarray:
        """The first ``count`` positions of the walk."""
        if count < 0 or count > self.n_samples:
            raise ValueError(f"count must be between 0 and {self.n_samples}")
        if count > self._order.size:
            self._extend(count)
        return self._order[:count]


def max_frame_bytes(n_eligible: int) -> int:
    """Largest frame, in bytes, for a carrier with ``n_eligible`` eligible samples."""
    return max(0, n_eligible - PUBLIC_BITS) // MAX_FILL // 8


def capacity(n_eligible: int) -> int:
    """Largest payload, in bytes, for a carrier with ``n_eligible`` eligible samples."""
    return max(0, max_frame_bytes(n_eligible) - FRAME_OVERHEAD)


def carrier_capacity(carrier: Carrier) -> int:
    """Largest payload, in bytes, that ``carrier`` can hold."""
    return capacity(int(np.count_nonzero(eligible_mask(carrier.samples()))))


def write_bits(
    samples: np.ndarray,
    positions: np.ndarray,
    bits: np.ndarray,
    method: Method,
    random_bytes: RandomBytes = os.urandom,
    *,
    low: int = 0,
    high: int = 255,
) -> tuple[np.ndarray, int]:
    """Write ``bits`` into the LSBs of ``samples[positions]``.

    Returns the modified copy and the number of samples that changed. A sample
    whose LSB already equals the bit is left alone, so on average only half of
    the used samples change. With LSB matching, samples at or below ``low``
    always move up and samples at or above ``high`` always move down; every
    other change goes up or down at random.
    """
    out = samples.astype(np.int16, copy=True)
    current = out[positions]
    mismatch = (current & 1) != bits
    targets = positions[mismatch]
    if method is Method.REPLACEMENT:
        out[targets] ^= 1
    else:
        values = out[targets]
        step = np.where(np.frombuffer(random_bytes(targets.size), dtype=np.uint8) & 1, 1, -1)
        step = np.where(values <= low, 1, np.where(values >= high, -1, step))
        out[targets] = values + step
    return out.astype(np.uint8), int(targets.size)


def read_bits(samples: np.ndarray, positions: np.ndarray) -> np.ndarray:
    """Read the LSBs of ``samples[positions]``."""
    return (samples[positions] & 1).astype(np.uint8)


def _aad(length: int, version: int = LEGACY_VERSION) -> bytes:
    domain = _DOMAINS[version]
    return domain + bytes([version]) + length.to_bytes(LENGTH_BYTES, "big")


def _xor(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, mask, strict=True))


def _to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def build_frame(
    payload: bytes,
    key: StegoKey,
    random_bytes: RandomBytes = os.urandom,
    version: int = LEGACY_VERSION,
) -> bytes:
    """Seal ``payload`` and wrap it in a frame ready to be written bit by bit."""
    nonce = random_bytes(NONCE_BYTES)
    length = NONCE_BYTES + len(payload) + TAG_BYTES
    body = AESGCM(key.aead).encrypt(nonce, payload, _aad(length, version))
    header = _xor(length.to_bytes(LENGTH_BYTES, "big"), key.length_mask)
    return header + nonce + body


def _salt_positions(n_samples: int, eligible: np.ndarray, width: int = 1) -> np.ndarray:
    return SampleOrder(_PUBLIC_WALK_KEY, n_samples, eligible).first(PUBLIC_BITS * width)


def _keyed_order(key: StegoKey, eligible: np.ndarray, salt_positions: np.ndarray) -> SampleOrder:
    remaining = eligible.copy()
    remaining[salt_positions] = False
    return SampleOrder(key.order, eligible.size, remaining)


def header_width(n_eligible: int) -> int:
    """Width of the format-4 header codes: fixed by the image, read before any key."""
    return max(1, min(HEADER_WIDTH, n_eligible // (8 * (PUBLIC_BITS + LENGTH_BITS))))


def _length_seed(key: StegoKey) -> bytes:
    return hashlib.sha256(b"length|" + key.code).digest()


def code_width(free_samples: int, message_bits: int) -> int:
    """Width of the syndrome-trellis code for ``message_bits`` bits.

    As wide as the free samples, :data:`MAX_WIDTH` and :data:`COLUMN_BUDGET`
    allow. Embedder and extractor compute it from the same two numbers.
    """
    if message_bits <= 0:
        return 1
    return max(1, min(MAX_WIDTH, free_samples // message_bits, COLUMN_BUDGET // message_bits))


def _chunks(message_bits: int) -> list[tuple[int, int]]:
    """``(start, stop)`` of each trellis over the message bits."""
    return [(i, min(i + CHUNK_BITS, message_bits)) for i in range(0, message_bits, CHUNK_BITS)]


def choose_flips(
    samples: np.ndarray,
    positions: np.ndarray,
    bits: np.ndarray,
    sample_costs: np.ndarray,
    seed: bytes,
    progress: Progress | None = None,
) -> np.ndarray:
    """Indices among ``positions`` whose LSB must flip so they carry ``bits``.

    ``positions`` holds ``width`` candidates per bit, in order; the
    syndrome-trellis code picks the flips whose ``sample_costs`` add up to
    the least. Works on any integer samples (pixels or JPEG coefficients):
    only their parity is read.
    """
    width = positions.size // max(bits.size, 1)
    if positions.size != width * bits.size:
        raise ValueError("positions must hold the same number of candidates for every bit")
    h_hat = stc.submatrix(seed, width)
    report = span(progress, 0.0, 1.0)
    targets = []
    for start, stop in _chunks(bits.size):
        report(start / max(bits.size, 1), "choosing the changes")
        chunk = positions[start * width : stop * width]
        cover_bits = (samples[chunk] & 1).astype(np.uint8)
        stego_bits, _ = stc.embed(cover_bits, sample_costs[chunk], bits[start:stop], h_hat)
        targets.append(chunk[stego_bits != cover_bits])
    report(1.0, "choosing the changes")
    return np.concatenate(targets) if targets else np.zeros(0, dtype=np.intp)


def write_adaptive(
    samples: np.ndarray,
    positions: np.ndarray,
    bits: np.ndarray,
    sample_costs: np.ndarray,
    seed: bytes,
    random_bytes: RandomBytes = os.urandom,
    *,
    low: int = ELIGIBLE_MIN,
    high: int = ELIGIBLE_MAX,
    progress: Progress | None = None,
) -> tuple[np.ndarray, int]:
    """Write ``bits`` as the syndrome of the LSBs of ``samples[positions]``.

    The flips come from :func:`choose_flips`; each is a +-1 change, in a
    random direction except at ``low`` and ``high``. Returns the modified
    copy and the number of samples that changed.
    """
    out = samples.astype(np.int16, copy=True)
    flips = choose_flips(out, positions, bits, sample_costs, seed, progress)
    values = out[flips]
    step = np.where(np.frombuffer(random_bytes(flips.size), dtype=np.uint8) & 1, 1, -1)
    step = np.where(values <= low, 1, np.where(values >= high, -1, step))
    out[flips] = values + step
    return out.astype(np.uint8), int(flips.size)


def read_adaptive(samples: np.ndarray, positions: np.ndarray, length: int, seed: bytes):
    """The ``length`` bits written by :func:`write_adaptive` at ``positions``."""
    width = positions.size // max(length, 1)
    h_hat = stc.submatrix(seed, width)
    lsb = (samples[positions] & 1).astype(np.uint8)
    parts = [
        stc.syndrome(lsb[start * width : stop * width], h_hat, stop - start)
        for start, stop in _chunks(length)
    ]
    return np.concatenate(parts) if parts else np.zeros(0, dtype=np.uint8)


def embed(
    carrier: Carrier,
    payload: bytes,
    passphrase: str | None = None,
    method: Method = Method.ADAPTIVE,
    random_bytes: RandomBytes = os.urandom,
    progress: Progress | None = None,
) -> tuple[Carrier, EmbedReport]:
    """Hide ``payload`` in ``carrier`` and return the stego carrier."""
    cover = carrier.samples()
    eligible = eligible_mask(cover)
    n_eligible = int(np.count_nonzero(eligible))
    room = max_frame_bytes(n_eligible) - FRAME_OVERHEAD
    if room < 0:
        raise CapacityError("this image is too small, or too saturated, to hold any payload")
    if len(payload) > room:
        raise CapacityError(
            f"payload is {len(payload)} bytes but this image holds at most {room} bytes"
        )
    salt = random_bytes(SALT_BYTES)
    log_n = SCRYPT_LOG_N
    adaptive = method is Method.ADAPTIVE
    version = FORMAT_VERSION if adaptive else LEGACY_VERSION
    span(progress, 0.0, 1.0)(0.0, "deriving the key")
    key = derive_key(passphrase, salt, log_n, version)
    frame = build_frame(payload, key, random_bytes, version)
    public = salt + bytes([log_n | (ADAPTIVE_FLAG if adaptive else 0)])

    frame_bits = _to_bits(frame)
    bits = np.concatenate([_to_bits(public), frame_bits])
    if not adaptive:
        salt_positions = _salt_positions(cover.size, eligible)
        order = _keyed_order(key, eligible, salt_positions)
        positions = np.concatenate([salt_positions, order.first(frame_bits.size)])
        samples, changed = write_bits(
            cover, positions, bits, method, random_bytes, low=ELIGIBLE_MIN, high=ELIGIBLE_MAX
        )
    else:
        # Three codes, each read before the next can be located: the public
        # bytes (fixed width, public matrix), the masked length (fixed width,
        # keyed matrix) and the sealed body (width from the length).
        hw = header_width(n_eligible)
        public_positions = _salt_positions(cover.size, eligible, hw)
        order = _keyed_order(key, eligible, public_positions)
        body = frame_bits[LENGTH_BITS:]
        free = order.n_samples - LENGTH_BITS * hw
        if body.size > free:
            raise CapacityError("this image is too small for this payload in the adaptive format")
        width = code_width(free, body.size)
        keyed = order.first(LENGTH_BITS * hw + width * body.size)
        rho = costs.sample_costs(carrier.pixels, carrier.colour_channels, span(progress, 0.05, 0.8))
        samples, changed = cover, 0
        for positions, part, seed, steps in (
            (public_positions, _to_bits(public), _PUBLIC_CODE_SEED, None),
            (keyed[: LENGTH_BITS * hw], frame_bits[:LENGTH_BITS], _length_seed(key), None),
            (keyed[LENGTH_BITS * hw :], body, key.code, span(progress, 0.8, 1.0)),
        ):
            samples, flipped = write_adaptive(
                samples, positions, part, rho, seed, random_bytes, progress=steps
            )
            changed += flipped
    report = EmbedReport(
        payload_bytes=len(payload),
        frame_bytes=len(frame),
        capacity_bytes=room,
        samples=cover.size,
        eligible_samples=n_eligible,
        bits_written=int(bits.size),
        samples_changed=changed,
    )
    return carrier.with_samples(samples), report


def _not_found() -> PayloadNotFoundError:
    return PayloadNotFoundError(
        "no shardpix payload found: wrong passphrase, no payload, or the image was modified"
    )


def extract(carrier: Carrier, passphrase: str | None = None) -> bytes:
    """Recover and authenticate the payload hidden in ``carrier`` (format 3 or 4)."""
    samples = carrier.samples()
    eligible = eligible_mask(samples)
    largest_frame = max_frame_bytes(int(np.count_nonzero(eligible)))
    if largest_frame < FRAME_OVERHEAD:
        raise _not_found()

    # The format is not stored anywhere an observer could read without
    # trying: each format's public bytes are decoded its own way, and a
    # format is attempted only if its cost byte is plausible.
    n_eligible = int(np.count_nonzero(eligible))
    for version in (FORMAT_VERSION, LEGACY_VERSION):
        try:
            return _extract(samples, eligible, n_eligible, largest_frame, passphrase, version)
        except PayloadNotFoundError:
            continue
    raise _not_found()


def _bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


def _extract(
    samples: np.ndarray,
    eligible: np.ndarray,
    n_eligible: int,
    largest_frame: int,
    passphrase: str | None,
    version: int,
) -> bytes:
    adaptive = version == FORMAT_VERSION
    hw = header_width(n_eligible) if adaptive else 1
    public_positions = _salt_positions(samples.size, eligible, hw)
    if adaptive:
        public = _bytes(read_adaptive(samples, public_positions, PUBLIC_BITS, _PUBLIC_CODE_SEED))
    else:
        public = _bytes(read_bits(samples, public_positions))
    salt, cost_byte = public[:SALT_BYTES], public[SALT_BYTES]
    if bool(cost_byte & ADAPTIVE_FLAG) is not adaptive:
        raise _not_found()
    log_n = cost_byte & ~ADAPTIVE_FLAG
    if log_n not in SCRYPT_LOG_N_ACCEPTED:
        raise _not_found()
    key = derive_key(passphrase, salt, log_n, version)
    order = _keyed_order(key, eligible, public_positions)

    header_samples = LENGTH_BITS * hw
    if adaptive:
        keyed = order.first(header_samples)
        header = _bytes(read_adaptive(samples, keyed, LENGTH_BITS, _length_seed(key)))
    else:
        header = _bytes(read_bits(samples, order.first(LENGTH_BITS)))
    length = int.from_bytes(_xor(header, key.length_mask), "big")
    if length < NONCE_BYTES + TAG_BYTES or LENGTH_BYTES + length > largest_frame:
        raise _not_found()

    body_bits = 8 * length
    if adaptive:
        free = order.n_samples - header_samples
        if body_bits > free:
            raise _not_found()
        width = code_width(free, body_bits)
        positions = order.first(header_samples + width * body_bits)[header_samples:]
        sealed = _bytes(read_adaptive(samples, positions, body_bits, key.code))
    else:
        positions = order.first(LENGTH_BITS + body_bits)[LENGTH_BITS:]
        sealed = _bytes(read_bits(samples, positions))
    nonce, body = sealed[:NONCE_BYTES], sealed[NONCE_BYTES:]
    try:
        return AESGCM(key.aead).decrypt(nonce, body, _aad(length, version))
    except InvalidTag:
        raise _not_found() from None

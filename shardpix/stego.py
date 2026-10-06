"""Keyed LSB steganography with an authenticated, encrypted payload.

The payload is never written to the image as-is. It is sealed with
AES-256-GCM, framed, and the frame bits are written into carrier samples
picked by a keyed pseudo-random walk. Without the passphrase an observer can
neither tell which samples were used nor distinguish the bits from noise.

**Per-image salt.** Every embedding draws a fresh 128-bit salt and writes it
first, into samples chosen by a *public* walk (the extractor must read it
before it has a key). The keys are derived from the passphrase and that salt,
so two images sealed with the same passphrase use unrelated keys and
unrelated positions, and scrypt work cannot be precomputed for common image
sizes.

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

from .errors import CapacityError, PayloadNotFoundError
from .images import Carrier

FORMAT_VERSION = 2
SALT_BYTES = 16
SALT_BITS = SALT_BYTES * 8
LENGTH_BYTES = 4
NONCE_BYTES = 12
TAG_BYTES = 16
FRAME_OVERHEAD = LENGTH_BYTES + NONCE_BYTES + TAG_BYTES
"""Bytes added to every payload by the keyed frame (the salt is accounted for separately)."""

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

ELIGIBLE_MIN = 2
ELIGIBLE_MAX = 253
"""Samples outside this range are never used and never produced."""

MAX_FILL = 2
"""Use at most one in ``MAX_FILL`` of the eligible samples."""

_DOMAIN = b"shardpix/stego/v2"
_PUBLIC_WALK_KEY = hashlib.sha256(_DOMAIN + b"|salt-walk").digest()

RandomBytes = Callable[[int], bytes]


class Method(str, Enum):
    """How a sample is changed when its LSB does not already match the bit."""

    MATCHING = "matching"
    """Add or subtract 1 at random (LSB matching, also known as +-1 embedding)."""

    REPLACEMENT = "replacement"
    """Overwrite the least significant bit (classic LSB replacement)."""


@dataclass(frozen=True)
class StegoKey:
    """Key material derived from a passphrase and a per-image salt."""

    order: bytes
    aead: bytes
    length_mask: bytes
    keyed: bool


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


def derive_key(passphrase: str | None, salt: bytes) -> StegoKey:
    """Derive the walk, encryption and masking keys for one embedding.

    scrypt makes every passphrase guess expensive, and the per-image salt
    means guesses cannot be shared between images. Without a passphrase the
    keys depend on the salt alone: the payload is still scattered and
    encrypted, but anyone running shardpix can read it.
    """
    if len(salt) != SALT_BYTES:
        raise ValueError(f"salt must be {SALT_BYTES} bytes")
    if passphrase:
        secret = unicodedata.normalize("NFC", passphrase).encode("utf-8")
        master = hashlib.scrypt(
            secret,
            salt=_DOMAIN + b"|" + salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            maxmem=SCRYPT_MAXMEM,
            dklen=32,
        )
    else:
        master = hashlib.sha256(_DOMAIN + b"|public|" + salt).digest()

    def expand(label: bytes, length: int) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=length, salt=None, info=_DOMAIN + b"|" + label
        )
        return hkdf.derive(master)

    return StegoKey(
        order=expand(b"order", 32),
        aead=expand(b"aead", 32),
        length_mask=expand(b"length", LENGTH_BYTES),
        keyed=bool(passphrase),
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
    return max(0, n_eligible - SALT_BITS) // MAX_FILL // 8


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


def _aad(length: int) -> bytes:
    return _DOMAIN + bytes([FORMAT_VERSION]) + length.to_bytes(LENGTH_BYTES, "big")


def _xor(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, mask, strict=True))


def _to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def build_frame(payload: bytes, key: StegoKey, random_bytes: RandomBytes = os.urandom) -> bytes:
    """Seal ``payload`` and wrap it in a frame ready to be written bit by bit."""
    nonce = random_bytes(NONCE_BYTES)
    length = NONCE_BYTES + len(payload) + TAG_BYTES
    body = AESGCM(key.aead).encrypt(nonce, payload, _aad(length))
    header = _xor(length.to_bytes(LENGTH_BYTES, "big"), key.length_mask)
    return header + nonce + body


def _salt_positions(n_samples: int, eligible: np.ndarray) -> np.ndarray:
    return SampleOrder(_PUBLIC_WALK_KEY, n_samples, eligible).first(SALT_BITS)


def _keyed_order(key: StegoKey, eligible: np.ndarray, salt_positions: np.ndarray) -> SampleOrder:
    remaining = eligible.copy()
    remaining[salt_positions] = False
    return SampleOrder(key.order, eligible.size, remaining)


def embed(
    carrier: Carrier,
    payload: bytes,
    passphrase: str | None = None,
    method: Method = Method.MATCHING,
    random_bytes: RandomBytes = os.urandom,
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
    key = derive_key(passphrase, salt)
    frame = build_frame(payload, key, random_bytes)

    salt_positions = _salt_positions(cover.size, eligible)
    frame_bits = _to_bits(frame)
    frame_positions = _keyed_order(key, eligible, salt_positions).first(frame_bits.size)
    positions = np.concatenate([salt_positions, frame_positions])
    bits = np.concatenate([_to_bits(salt), frame_bits])
    samples, changed = write_bits(
        cover, positions, bits, method, random_bytes, low=ELIGIBLE_MIN, high=ELIGIBLE_MAX
    )
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
    """Recover and authenticate the payload hidden in ``carrier``."""
    samples = carrier.samples()
    eligible = eligible_mask(samples)
    largest_frame = max_frame_bytes(int(np.count_nonzero(eligible)))
    if largest_frame < FRAME_OVERHEAD:
        raise _not_found()

    salt_positions = _salt_positions(samples.size, eligible)
    salt = np.packbits(read_bits(samples, salt_positions)).tobytes()
    key = derive_key(passphrase, salt)
    order = _keyed_order(key, eligible, salt_positions)

    header_bits = LENGTH_BYTES * 8
    header = np.packbits(read_bits(samples, order.first(header_bits))).tobytes()
    length = int.from_bytes(_xor(header, key.length_mask), "big")
    if length < NONCE_BYTES + TAG_BYTES or LENGTH_BYTES + length > largest_frame:
        raise _not_found()

    positions = order.first(header_bits + 8 * length)[header_bits:]
    sealed = np.packbits(read_bits(samples, positions)).tobytes()
    nonce, body = sealed[:NONCE_BYTES], sealed[NONCE_BYTES:]
    try:
        return AESGCM(key.aead).decrypt(nonce, body, _aad(length))
    except InvalidTag:
        raise _not_found() from None

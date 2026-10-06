"""Keyed LSB steganography with an authenticated, encrypted payload.

The payload is never written to the image as-is. It is first sealed with
AES-256-GCM, then framed, and the frame bits are written into carrier samples
chosen by a key-dependent ranking. Without the passphrase an observer can
neither tell which samples were used nor distinguish the bits from noise.

Frame layout, in the order the bits are written::

    length   4 bytes   big-endian size of nonce + body, XOR-masked with a key-derived mask
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

FORMAT_VERSION = 1
LENGTH_BYTES = 4
NONCE_BYTES = 12
TAG_BYTES = 16
FRAME_OVERHEAD = LENGTH_BYTES + NONCE_BYTES + TAG_BYTES

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

_DOMAIN = b"shardpix/stego/v1"

RandomBytes = Callable[[int], bytes]


class Method(str, Enum):
    """How a sample is changed when its LSB does not already match the bit."""

    MATCHING = "matching"
    """Add or subtract 1 at random (LSB matching, also known as +-1 embedding)."""

    REPLACEMENT = "replacement"
    """Overwrite the least significant bit (classic LSB replacement)."""


@dataclass(frozen=True)
class StegoKey:
    """Key material derived from a passphrase and the carrier geometry."""

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
    bits_written: int
    samples_changed: int

    @property
    def embedding_rate(self) -> float:
        """Fraction of carrier samples that hold a payload bit."""
        return self.bits_written / self.samples if self.samples else 0.0

    @property
    def change_rate(self) -> float:
        """Fraction of carrier samples whose value actually changed."""
        return self.samples_changed / self.samples if self.samples else 0.0


def _salt(geometry: tuple[int, int, int]) -> bytes:
    height, width, channels = geometry
    return _DOMAIN + f"|{height}x{width}x{channels}".encode()


def derive_key(passphrase: str | None, geometry: tuple[int, int, int]) -> StegoKey:
    """Derive the ordering, encryption and masking keys for one carrier geometry.

    The salt cannot be stored in the image - the extractor needs the key before
    it knows where anything is - so it is built from a domain label and the
    carrier dimensions instead. scrypt keeps each passphrase guess expensive.
    Without a passphrase the keys are public constants: the payload is still
    scattered and encrypted, but anyone running shardpix can read it.
    """
    salt = _salt(geometry)
    if passphrase:
        secret = unicodedata.normalize("NFC", passphrase).encode("utf-8")
        master = hashlib.scrypt(
            secret,
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            maxmem=SCRYPT_MAXMEM,
            dklen=32,
        )
    else:
        master = hashlib.sha256(salt + b"|public").digest()

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


class SampleOrder:
    """A key-dependent ranking of every carrier sample.

    Each sample index receives a 64-bit rank taken from a ChaCha20 keystream;
    the payload goes into samples in increasing rank order. Ranks come from a
    stream cipher rather than ``numpy.random`` because the positions must be
    unpredictable to anyone without the key, and a statistical PRNG makes no
    such promise. With 64-bit ranks ties are negligible, so the ordering is
    unique and does not depend on the sorting algorithm.
    """

    def __init__(self, key: bytes, n_samples: int) -> None:
        cipher = Cipher(algorithms.ChaCha20(key, bytes(16)), mode=None)
        stream = cipher.encryptor().update(bytes(8 * n_samples))
        self._ranks = np.frombuffer(stream, dtype="<u8")
        self.n_samples = n_samples

    def first(self, count: int) -> np.ndarray:
        """Indices of the ``count`` lowest-ranked samples, in rank order."""
        if count < 0 or count > self.n_samples:
            raise ValueError(f"count must be between 0 and {self.n_samples}")
        if count == 0:
            return np.empty(0, dtype=np.intp)
        if count == self.n_samples:
            return np.argsort(self._ranks, kind="stable")
        candidates = np.argpartition(self._ranks, count - 1)[:count]
        return candidates[np.argsort(self._ranks[candidates], kind="stable")]


def capacity(n_samples: int) -> int:
    """Largest payload, in bytes, that fits in ``n_samples`` carrier samples."""
    return max(0, n_samples // 8 - FRAME_OVERHEAD)


def write_bits(
    samples: np.ndarray,
    positions: np.ndarray,
    bits: np.ndarray,
    method: Method,
    random_bytes: RandomBytes = os.urandom,
) -> tuple[np.ndarray, int]:
    """Write ``bits`` into the LSBs of ``samples[positions]``.

    Returns the modified copy and the number of samples that changed. A sample
    whose LSB already equals the bit is left alone, so on average only half of
    the used samples change.
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
        step = np.where(values == 0, 1, np.where(values == 255, -1, step))
        out[targets] = values + step
    return out.astype(np.uint8), int(targets.size)


def read_bits(samples: np.ndarray, positions: np.ndarray) -> np.ndarray:
    """Read the LSBs of ``samples[positions]``."""
    return (samples[positions] & 1).astype(np.uint8)


def _aad(length: int) -> bytes:
    return _DOMAIN + bytes([FORMAT_VERSION]) + length.to_bytes(LENGTH_BYTES, "big")


def _xor(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, mask, strict=True))


def build_frame(payload: bytes, key: StegoKey, random_bytes: RandomBytes = os.urandom) -> bytes:
    """Seal ``payload`` and wrap it in a frame ready to be written bit by bit."""
    nonce = random_bytes(NONCE_BYTES)
    length = NONCE_BYTES + len(payload) + TAG_BYTES
    body = AESGCM(key.aead).encrypt(nonce, payload, _aad(length))
    header = _xor(length.to_bytes(LENGTH_BYTES, "big"), key.length_mask)
    return header + nonce + body


def embed(
    carrier: Carrier,
    payload: bytes,
    passphrase: str | None = None,
    method: Method = Method.MATCHING,
    random_bytes: RandomBytes = os.urandom,
) -> tuple[Carrier, EmbedReport]:
    """Hide ``payload`` in ``carrier`` and return the stego carrier."""
    n_samples = carrier.n_samples
    room = capacity(n_samples)
    if len(payload) > room:
        raise CapacityError(
            f"payload is {len(payload)} bytes but this image holds at most {room} bytes"
        )
    key = derive_key(passphrase, carrier.geometry)
    frame = build_frame(payload, key, random_bytes)
    bits = np.unpackbits(np.frombuffer(frame, dtype=np.uint8))
    positions = SampleOrder(key.order, n_samples).first(bits.size)
    samples, changed = write_bits(carrier.samples(), positions, bits, method, random_bytes)
    report = EmbedReport(
        payload_bytes=len(payload),
        frame_bytes=len(frame),
        capacity_bytes=room,
        samples=n_samples,
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
    n_samples = carrier.n_samples
    header_bits = LENGTH_BYTES * 8
    if n_samples < header_bits:
        raise _not_found()
    key = derive_key(passphrase, carrier.geometry)
    order = SampleOrder(key.order, n_samples)
    samples = carrier.samples()

    header = np.packbits(read_bits(samples, order.first(header_bits))).tobytes()
    length = int.from_bytes(_xor(header, key.length_mask), "big")
    if length < NONCE_BYTES + TAG_BYTES or header_bits + 8 * length > n_samples:
        raise _not_found()

    positions = order.first(header_bits + 8 * length)[header_bits:]
    sealed = np.packbits(read_bits(samples, positions)).tobytes()
    nonce, body = sealed[:NONCE_BYTES], sealed[NONCE_BYTES:]
    try:
        return AESGCM(key.aead).decrypt(nonce, body, _aad(length))
    except InvalidTag:
        raise _not_found() from None

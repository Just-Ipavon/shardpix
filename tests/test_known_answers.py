"""Known-answer tests: pin every on-disk format to fixed bytes.

Everything else in the suite checks that shardpix agrees with itself. These
tests check that it agrees with the version that produced the images people
already hold: a refactor, a NumPy upgrade or a change in ``cryptography``
that alters a single position or byte fails here instead of silently making
old images unreadable. If a change to a format is intended, bump the format
version and update the expected values.
"""

from __future__ import annotations

import hashlib
import itertools

import numpy as np
import pytest
from PIL import Image

from shardpix import shamir, stc, stego, vault
from shardpix.images import from_pil, load_image

from .conftest import PRODUCTION_SCRYPT


def deterministic_random(seed: bytes = b"shardpix-test"):
    """A reproducible stand-in for ``os.urandom``."""
    counter = itertools.count()

    def random_bytes(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(seed + next(counter).to_bytes(8, "big")).digest()
        return out[:n]

    return random_bytes


def arithmetic_cover(height: int = 64, width: int = 80) -> np.ndarray:
    """A cover built from integer arithmetic only, so it never depends on a RNG version."""
    y, x = np.mgrid[0:height, 0:width]
    channels = [(x * 7 + y * 13 + c * 29) % 200 + 30 for c in range(3)]
    return np.stack(channels, axis=-1).astype(np.uint8)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def production_scrypt(monkeypatch):
    monkeypatch.setattr(stego, "SCRYPT_LOG_N", PRODUCTION_SCRYPT[0])


def test_sample_order():
    zero_key = stego.SampleOrder(bytes(32), 1000).first(8)
    counting_key = stego.SampleOrder(bytes(range(32)), 1000).first(8)
    assert zero_key.tolist() == [830, 128, 677, 440, 42, 111, 250, 43]
    assert counting_key.tolist() == [593, 893, 858, 610, 707, 711, 381, 66]


def test_share_encoding():
    shares = shamir.split(b"known answer", 2, 3, random_bytes=deterministic_random())
    assert shares[0].to_text() == (
        "spx1-knifquybbx2uuk2k43sxnbekiy3gsezbyabacaam27m557iibkwtvpb7heby2v33pjngph357r5l2pm2n4"
        "nghbncfzs63e5ahgj7745tcy5wyzlljb2rw35hz44xkzdkrh2gipk4fzt2qri"
    )
    assert sha256(b"".join(s.to_bytes() for s in shares)) == (
        "40e2b7196fbe06b39cde4848f0e30d1bf106ae84fd57dc6c3371c31bef848635"
    )


FORMAT_3 = stego.Method.MATCHING
FORMAT_4 = stego.Method.ADAPTIVE


def test_stc_submatrix():
    """The code matrix is part of format 4: pin it, independently of NumPy."""
    h_hat = stc.submatrix(bytes(32), 8)
    assert sha256(np.packbits(h_hat).tobytes()) == (
        "73c2e3d99b4282fb686765d97a0341e974a54bcc0c55449412ea9ffae39c2776"
    )


def test_stego_pixels(production_scrypt):
    carrier = from_pil(Image.fromarray(arithmetic_cover()))
    stego_carrier, _ = stego.embed(
        carrier, b"known answer", "pw", FORMAT_3, random_bytes=deterministic_random()
    )
    assert sha256(stego_carrier.pixels.tobytes()) == (
        "2672c59ad37c888ca2217dde3ba79532e5fa2d2856bc8bc32bc6c5703413bb48"
    )
    assert stego.extract(stego_carrier, "pw") == b"known answer"


def test_stego_pixels_format_4(production_scrypt):
    carrier = from_pil(Image.fromarray(arithmetic_cover()))
    stego_carrier, _ = stego.embed(
        carrier, b"known answer", "pw", FORMAT_4, random_bytes=deterministic_random()
    )
    assert sha256(stego_carrier.pixels.tobytes()) == (
        "dc94896bfff08879cd7ab29dd07ed130ea7b6fcde0444c8ad9720a3eea024b7a"
    )
    assert stego.extract(stego_carrier, "pw") == b"known answer"


def test_vault_file_and_image(tmp_path, production_scrypt):
    covers = []
    for i in range(3):
        path = tmp_path / f"c{i}.png"
        Image.fromarray(np.roll(arithmetic_cover(), i, axis=1)).save(path)
        covers.append(path)
    source = tmp_path / "secret.txt"
    source.write_bytes(b"pinned vault content")
    result = vault.seal(
        source,
        covers,
        2,
        tmp_path / "out",
        "pw",
        method=FORMAT_3,
        random_bytes=deterministic_random(b"vault"),
    )
    assert sha256(result.vault_path.read_bytes()) == (
        "d210c0702a3f981197e26dc7873bc312e84c46ad7be66ac4cd6a8aea2ecea969"
    )
    assert sha256(load_image(result.images[0].output).pixels.tobytes()) == (
        "4cbba34a7216babc8c12813d5eccebb0006f2e2a6b0e823cbe5b4837d39ce910"
    )
    opened = vault.unseal(result.vault_path, [i.output for i in result.images[1:]], "pw")
    assert opened.data == b"pinned vault content"


def test_stego_pixels_without_passphrase():
    """Public mode has its own key derivation; pin it too (found by mutation testing)."""
    carrier = from_pil(Image.fromarray(arithmetic_cover()))
    stego_carrier, _ = stego.embed(
        carrier, b"public payload", None, FORMAT_3, random_bytes=deterministic_random(b"public")
    )
    assert sha256(stego_carrier.pixels.tobytes()) == (
        "b33b6b23db6d180c7fb3b4a331de776148b30030ec3419dd9b1b6957aac481e1"
    )


def test_stego_pixels_without_passphrase_format_4():
    carrier = from_pil(Image.fromarray(arithmetic_cover()))
    stego_carrier, _ = stego.embed(
        carrier, b"public payload", None, FORMAT_4, random_bytes=deterministic_random(b"public")
    )
    assert sha256(stego_carrier.pixels.tobytes()) == (
        "67d970a38da7f92fdfdc8cc567d31753de95cd9ec3224d7ef264325e6f47ce0a"
    )
    assert stego.extract(stego_carrier) == b"public payload"

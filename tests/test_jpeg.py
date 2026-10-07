"""Format 5: adaptive embedding in JPEG coefficients, for phone photos."""

from __future__ import annotations

import hashlib
import itertools

import jpeglib
import numpy as np
import pytest
from PIL import Image

from shardpix import costs, jpeg, media, stego
from shardpix.errors import CapacityError, PayloadNotFoundError, UnsupportedImageError

from .conftest import phone_jpeg


def deterministic_random(seed: bytes = b"jpeg-test"):
    counter = itertools.count()

    def random_bytes(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(seed + next(counter).to_bytes(8, "big")).digest()
        return out[:n]

    return random_bytes


def arithmetic_jpeg(path, blocks_high: int = 32, blocks_wide: int = 40):
    """A greyscale JPEG whose coefficients come from integer arithmetic alone."""
    b, a, u, v = np.meshgrid(
        np.arange(blocks_high), np.arange(blocks_wide), np.arange(8), np.arange(8), indexing="ij"
    )
    values = ((b * 7 + a * 13 + u * 5 + v * 3) % 23) - 11
    values = np.where(u + v < 6, values, 0)
    values[:, :, 0, 0] = ((b[:, :, 0, 0] + a[:, :, 0, 0]) % 50) - 25
    quant = (np.arange(64).reshape(1, 8, 8) // 4 + 2).astype(np.uint16)
    image = jpeglib.from_dct(Y=values.astype(np.int16), qt=quant)
    image.write_dct(str(path))
    return path


@pytest.fixture
def photo(tmp_path):
    return phone_jpeg(tmp_path / "photo.jpg")


def round_trip(tmp_path, cover, payload, passphrase="pw", **kwargs):
    data, report = jpeg.embed(cover, payload, passphrase, **kwargs)
    out = tmp_path / "stego.jpg"
    out.write_bytes(data)
    return jpeg.load(out), report


class TestFormat5:
    @pytest.mark.parametrize("payload", [b"x", bytes(109), bytes(range(256))])
    def test_round_trip(self, tmp_path, photo, payload):
        stego_cover, report = round_trip(tmp_path, jpeg.load(photo), payload)
        assert jpeg.extract(stego_cover, "pw") == payload
        assert report.payload_bytes == len(payload)

    def test_wrong_passphrase_is_not_found(self, tmp_path, photo):
        stego_cover, _ = round_trip(tmp_path, jpeg.load(photo), b"secret")
        with pytest.raises(PayloadNotFoundError):
            jpeg.extract(stego_cover, "other")

    def test_clean_jpeg_holds_nothing(self, photo):
        with pytest.raises(PayloadNotFoundError):
            jpeg.extract(jpeg.load(photo), "pw")

    def test_only_nonzero_ac_coefficients_move_by_one(self, tmp_path, photo):
        cover = jpeg.load(photo)
        stego_cover, report = round_trip(tmp_path, cover, bytes(109))
        before, after = cover.coefficients(), stego_cover.coefficients()
        diff = after - before
        assert set(np.unique(diff)) <= {-1, 0, 1}
        assert np.count_nonzero(diff) == report.samples_changed > 0
        assert not np.any(diff.reshape(-1, 64)[:, 0])  # DC never touched
        assert np.all(before[diff != 0] != 0)  # zeros never touched
        assert np.all(after[before != 0] != 0)  # nothing becomes zero
        assert np.array_equal(jpeg.eligible_mask(before), jpeg.eligible_mask(after))

    def test_ones_move_away_from_zero(self):
        coefficients = np.array([1, -1, 5, -5, 1023, -1023], dtype=np.int32)
        flips = np.arange(6)
        for seed in (b"a", b"b", b"c"):
            out = jpeg._apply(coefficients, flips, deterministic_random(seed))
            assert out[0] == 2 and out[1] == -2
            assert out[4] == 1022 and out[5] == -1022

    def test_tables_geometry_and_metadata_are_kept(self, tmp_path, photo):
        cover = jpeg.load(photo)
        stego_cover, _ = round_trip(tmp_path, cover, bytes(109))
        assert np.array_equal(cover.quant, stego_cover.quant)
        assert cover.blocks.shape == stego_cover.blocks.shape
        assert cover.geometry() == stego_cover.geometry()
        with Image.open(tmp_path / "stego.jpg") as image:
            assert image.getexif()[0x010F] == "ShardpixTestPhone"

    def test_tampering_is_detected(self, tmp_path, photo):
        cover = jpeg.load(photo)
        data, _ = jpeg.embed(cover, bytes(109), "pw")
        out = tmp_path / "s.jpg"
        out.write_bytes(data)
        stego_cover = jpeg.load(out)
        changed = np.flatnonzero(stego_cover.coefficients() != cover.coefficients())
        blocks = stego_cover.image.Y.reshape(-1).copy()
        index = changed[len(changed) // 2]
        blocks[index] = cover.coefficients()[index]
        stego_cover.image.Y = blocks.reshape(stego_cover.blocks.shape)
        with pytest.raises(PayloadNotFoundError):
            jpeg.extract(stego_cover, "pw")

    def test_png_and_jpeg_payloads_use_different_keys(self):
        salt = bytes(range(16))
        v4 = stego.derive_key("pw", salt, 10, stego.FORMAT_VERSION)
        v5 = stego.derive_key("pw", salt, 10, stego.JPEG_VERSION)
        assert v4.order != v5.order and v4.aead != v5.aead and v4.code != v5.code

    def test_flat_jpeg_has_no_room(self, tmp_path):
        flat = tmp_path / "flat.jpg"
        Image.fromarray(np.full((64, 64, 3), 120, np.uint8)).save(flat, quality=90)
        with pytest.raises(CapacityError):
            jpeg.embed(jpeg.load(flat), bytes(109), "pw")

    def test_not_a_jpeg(self, tmp_path, cover_png):
        assert not jpeg.is_jpeg(cover_png)
        with pytest.raises(UnsupportedImageError):
            jpeg.load(cover_png)

    def test_known_answer(self, tmp_path, monkeypatch):
        """Pin the format by coefficients built from integer arithmetic only.

        The cover is written straight from coefficients, so neither Pillow's
        encoder nor a random generator can change it; the result is pinned by
        its coefficients, not by libjpeg's file bytes.
        """
        monkeypatch.setattr(stego, "SCRYPT_LOG_N", 17)
        cover = jpeg.load(arithmetic_jpeg(tmp_path / "pinned.jpg"))
        data, _ = jpeg.embed(cover, b"known answer", "pw", deterministic_random())
        (tmp_path / "s.jpg").write_bytes(data)
        stego_cover = jpeg.load(tmp_path / "s.jpg")
        digest = hashlib.sha256(stego_cover.coefficients().astype("<i4").tobytes()).hexdigest()
        assert digest == ("bd3d599d7d79a5c9f5e6485a9ac7d8f66d1bcb892e6651f5cb83d435a253f3cb")
        assert jpeg.extract(stego_cover, "pw") == b"known answer"


class TestUERD:
    def test_busy_blocks_are_cheaper_than_flat_ones(self):
        rng = np.random.default_rng(0)
        blocks = np.zeros((4, 8, 8, 8))
        blocks[:, 4:] = rng.integers(-20, 20, size=(4, 4, 8, 8))
        rho = costs.uerd(blocks, np.full((8, 8), 10.0))
        assert rho[:, 6:].mean() < rho[:, :2].mean() / 5

    def test_coarse_frequencies_cost_more(self):
        rng = np.random.default_rng(1)
        blocks = rng.integers(-10, 10, size=(3, 3, 8, 8))
        quant = np.arange(1, 65, dtype=float).reshape(8, 8)
        rho = costs.uerd(blocks, quant)[1, 1]
        assert rho[7, 7] > rho[0, 1]


class TestMedia:
    def test_kind_follows_the_file_not_its_name(self, tmp_path, photo, cover_png):
        disguised = tmp_path / "really_a_jpeg.png"
        disguised.write_bytes(photo.read_bytes())
        assert media.kind_suffix(disguised) == ".jpg"
        assert media.open_cover(cover_png).suffix == ".png"

    def test_hide_and_reveal_both_kinds(self, tmp_path, photo, cover_png):
        for cover_path, name in ((photo, "a.jpg"), (cover_png, "b.png")):
            cover = media.open_cover(cover_path)
            data, _ = media.hide(cover, b"either way", "pw")
            out = tmp_path / name
            out.write_bytes(data)
            assert media.reveal(out, "pw") == b"either way"

"""Adaptive embedding building blocks: HiLL costs and syndrome-trellis codes."""

from __future__ import annotations

import numpy as np
import pytest

from shardpix import costs, stc, stego
from shardpix.errors import PayloadNotFoundError
from shardpix.images import Carrier

from .conftest import natural_image

ADAPTIVE = stego.Method.ADAPTIVE


class TestSTC:
    @pytest.mark.parametrize(("width", "length"), [(1, 30), (2, 40), (5, 60), (17, 25)])
    def test_the_receiver_reads_the_message(self, width, length):
        rng = np.random.default_rng(width)
        h_hat = stc.submatrix(bytes(32), width, height=6)
        bits = rng.integers(0, 2, width * length).astype(np.uint8)
        message = rng.integers(0, 2, length).astype(np.uint8)
        y, _ = stc.embed(bits, rng.exponential(size=bits.size), message, h_hat)
        assert np.array_equal(stc.syndrome(y, h_hat, length), message)

    def test_reported_cost_is_the_cost_of_the_flips(self):
        rng = np.random.default_rng(1)
        h_hat = stc.submatrix(b"x" * 32, 8)
        bits = rng.integers(0, 2, 8 * 50).astype(np.uint8)
        rho = rng.exponential(size=bits.size)
        y, total = stc.embed(bits, rho, rng.integers(0, 2, 50).astype(np.uint8), h_hat)
        assert total == pytest.approx(rho[y != bits].sum())

    def test_wider_codes_change_fewer_elements(self):
        rng = np.random.default_rng(2)
        flips = []
        for width in (2, 8, 32):
            h_hat = stc.submatrix(bytes(32), width)
            bits = rng.integers(0, 2, width * 200).astype(np.uint8)
            message = rng.integers(0, 2, 200).astype(np.uint8)
            y, _ = stc.embed(bits, np.ones(bits.size), message, h_hat)
            flips.append(int(np.count_nonzero(y != bits)))
        # Plain LSB embedding changes half of the 200 elements it writes.
        assert flips[0] < 100 and flips[2] < flips[1] < flips[0]

    def test_cheap_elements_are_preferred(self):
        rng = np.random.default_rng(3)
        h_hat = stc.submatrix(bytes(32), 16)
        bits = rng.integers(0, 2, 16 * 100).astype(np.uint8)
        rho = np.where(np.arange(bits.size) % 2 == 0, 1.0, 100.0)
        y, _ = stc.embed(bits, rho, rng.integers(0, 2, 100).astype(np.uint8), h_hat)
        changed = np.flatnonzero(y != bits)
        assert np.mean(changed % 2 == 0) > 0.95

    def test_wet_elements_never_change(self):
        rng = np.random.default_rng(4)
        h_hat = stc.submatrix(bytes(32), 8)
        bits = rng.integers(0, 2, 8 * 60).astype(np.uint8)
        rho = np.ones(bits.size)
        wet = rng.random(bits.size) < 0.3
        rho[wet] = stc.WET
        message = rng.integers(0, 2, 60).astype(np.uint8)
        y, _ = stc.embed(bits, rho, message, h_hat)
        assert np.array_equal(y[wet], bits[wet])
        assert np.array_equal(stc.syndrome(y, h_hat, 60), message)

    def test_many_expensive_changes_are_not_mistaken_for_wet_ones(self):
        # Flat areas cost ~1e10 per change: thousands of them add up past WET
        # without any single element being forbidden.
        rng = np.random.default_rng(5)
        h_hat = stc.submatrix(bytes(32), 1)
        bits = rng.integers(0, 2, 4000).astype(np.uint8)
        message = rng.integers(0, 2, 4000).astype(np.uint8)
        y, total = stc.embed(bits, np.full(bits.size, 1e10), message, h_hat)
        assert total >= stc.WET
        assert np.array_equal(stc.syndrome(y, h_hat, 4000), message)

    def test_impossible_when_everything_is_wet(self):
        h_hat = stc.submatrix(bytes(32), 4)
        bits = np.zeros(40, dtype=np.uint8)
        with pytest.raises(ValueError):
            stc.embed(bits, np.full(40, stc.WET), np.ones(10, dtype=np.uint8), h_hat)

    def test_rejects_a_block_of_the_wrong_size(self):
        h_hat = stc.submatrix(bytes(32), 4)
        with pytest.raises(ValueError):
            stc.embed(np.zeros(39, np.uint8), np.ones(39), np.zeros(10, np.uint8), h_hat)
        with pytest.raises(ValueError):
            stc.syndrome(np.zeros(39, np.uint8), h_hat, 10)

    def test_submatrix_is_deterministic_and_keyed(self):
        a = stc.submatrix(b"a" * 32, 12)
        assert np.array_equal(a, stc.submatrix(b"a" * 32, 12))
        assert not np.array_equal(a, stc.submatrix(b"b" * 32, 12))
        assert a.shape == (stc.HEIGHT, 12) and a[0].all() and a[-1].all()


class TestHiLL:
    def test_box_mean_of_a_constant_is_the_constant(self):
        assert np.allclose(costs.box_mean(np.full((9, 11), 3.0), 5), 3.0)

    def test_box_mean_matches_a_direct_average(self):
        x = np.random.default_rng(5).normal(size=(20, 20))
        padded = np.pad(x, 1, mode="symmetric")
        direct = np.mean([padded[i : i + 20, j : j + 20] for i in range(3) for j in range(3)], 0)
        assert np.allclose(costs.box_mean(x, 3), direct)

    def test_texture_is_cheaper_than_smooth_regions(self):
        rng = np.random.default_rng(6)
        image = np.full((64, 64), 120, dtype=np.uint8)
        image[:, 32:] = rng.integers(60, 200, (64, 32))
        rho = costs.hill(image)
        assert rho[:, 40:].mean() < rho[:, :24].mean() / 10

    def test_costs_are_positive_and_follow_sample_order(self):
        rgb = natural_image(24, 32, 3, seed=7)
        flat = costs.sample_costs(rgb, 3)
        assert flat.shape == (24 * 32 * 3,) and np.all(flat > 0)
        assert np.allclose(flat[1::3].reshape(24, 32), costs.hill(rgb[..., 1]))


def carrier(seed: int = 0, height: int = 120, width: int = 160, channels: int = 3) -> Carrier:
    mode = "RGB" if channels == 3 else "L"
    return Carrier(pixels=natural_image(height, width, channels, seed=seed), mode=mode)


class TestFormat4:
    @pytest.mark.parametrize("channels", [1, 3])
    @pytest.mark.parametrize("payload", [b"x", bytes(109), bytes(range(256)) * 3])
    def test_round_trip(self, channels, payload):
        stego_carrier, report = stego.embed(carrier(channels=channels), payload, "pw", ADAPTIVE)
        assert stego.extract(stego_carrier, "pw") == payload
        assert report.payload_bytes == len(payload)

    def test_round_trip_without_passphrase(self):
        stego_carrier, _ = stego.embed(carrier(1), b"public", None, ADAPTIVE)
        assert stego.extract(stego_carrier) == b"public"

    def test_wrong_passphrase_is_not_found(self):
        stego_carrier, _ = stego.embed(carrier(2), b"secret", "pw", ADAPTIVE)
        with pytest.raises(PayloadNotFoundError):
            stego.extract(stego_carrier, "other")

    def test_changes_far_fewer_samples_than_format_3(self):
        cover = carrier(3)
        _, v4 = stego.embed(cover, bytes(109), "pw", ADAPTIVE)
        _, v3 = stego.embed(cover, bytes(109), "pw", stego.Method.MATCHING)
        assert v4.samples_changed < 0.6 * v3.samples_changed

    def test_every_change_is_plus_or_minus_one_inside_the_eligible_range(self):
        cover = carrier(4)
        stego_carrier, report = stego.embed(cover, bytes(400), "pw", ADAPTIVE)
        diff = stego_carrier.pixels.astype(int) - cover.pixels
        assert set(np.unique(diff)) <= {-1, 0, 1}
        assert np.count_nonzero(diff) == report.samples_changed
        moved = diff != 0
        assert stego.eligible_mask(cover.pixels[moved]).all()
        assert stego.eligible_mask(stego_carrier.pixels[moved]).all()

    def test_changes_avoid_smooth_regions(self):
        rng = np.random.default_rng(5)
        pixels = np.full((128, 128, 1), 120, dtype=np.uint8)
        pixels[:, 64:, 0] = rng.integers(40, 210, (128, 64))
        cover = Carrier(pixels=pixels, mode="L")
        stego_carrier, _ = stego.embed(cover, bytes(109), "pw", ADAPTIVE)
        moved = (stego_carrier.pixels != cover.pixels)[..., 0]
        assert moved[:, 64:].sum() > 20 * max(1, moved[:, :64].sum())

    def test_public_byte_marks_the_format(self):
        cover = carrier(6)
        samples = cover.samples()
        eligible = stego.eligible_mask(samples)
        hw = stego.header_width(int(eligible.sum()))
        v3_positions = stego._salt_positions(samples.size, eligible)
        v4_positions = stego._salt_positions(samples.size, eligible, hw)

        out, _ = stego.embed(cover, b"m", "pw", ADAPTIVE)
        bits = stego.read_adaptive(
            out.samples(), v4_positions, stego.PUBLIC_BITS, stego._PUBLIC_CODE_SEED
        )
        cost = np.packbits(bits).tobytes()[stego.SALT_BYTES]
        assert cost == stego.SCRYPT_LOG_N | stego.ADAPTIVE_FLAG

        out, _ = stego.embed(cover, b"m", "pw", stego.Method.MATCHING)
        cost = np.packbits(stego.read_bits(out.samples(), v3_positions)).tobytes()[stego.SALT_BYTES]
        assert cost == stego.SCRYPT_LOG_N

    def test_format_3_images_are_still_read(self):
        stego_carrier, _ = stego.embed(carrier(7), b"old", "pw", stego.Method.MATCHING)
        assert stego.extract(stego_carrier, "pw") == b"old"

    def test_formats_use_separate_keys(self):
        salt = bytes(range(16))
        v3 = stego.derive_key("pw", salt, 10, stego.LEGACY_VERSION)
        v4 = stego.derive_key("pw", salt, 10, stego.FORMAT_VERSION)
        assert v3.order != v4.order and v3.aead != v4.aead and v4.code and not v3.code

    def test_tampering_with_the_body_is_detected(self):
        cover = carrier(8)
        stego_carrier, _ = stego.embed(cover, bytes(109), "pw", ADAPTIVE)
        pixels = stego_carrier.pixels.copy()
        changed = np.argwhere(pixels != cover.pixels)
        y, x, c = changed[len(changed) // 2]
        pixels[y, x, c] = cover.pixels[y, x, c]
        with pytest.raises(PayloadNotFoundError):
            stego.extract(Carrier(pixels=pixels, mode="RGB"), "pw")


class TestCodeWidth:
    def test_bounded_by_free_samples_cap_and_budget(self):
        assert stego.code_width(10_000, 100) == min(stego.MAX_WIDTH, 100)
        assert stego.code_width(10**9, 1000) == stego.MAX_WIDTH
        assert stego.code_width(10**9, 100_000) == stego.COLUMN_BUDGET // 100_000
        assert stego.code_width(10, 100) == 1
        assert stego.code_width(10, 0) == 1

    def test_long_payloads_are_split_into_trellises(self, monkeypatch):
        monkeypatch.setattr(stego, "CHUNK_BITS", 256)
        stego_carrier, _ = stego.embed(carrier(9), bytes(range(200)), "pw", ADAPTIVE)
        assert stego.extract(stego_carrier, "pw") == bytes(range(200))


def test_each_embedding_changes_different_samples():
    """A fresh salt per embedding gives fresh keys, positions and code matrices."""
    cover = carrier(10, 200, 200)
    first, _ = stego.embed(cover, bytes(109), "pw", ADAPTIVE)
    second, _ = stego.embed(cover, bytes(109), "pw", ADAPTIVE)
    a = np.flatnonzero(first.pixels != cover.pixels)
    b = np.flatnonzero(second.pixels != cover.pixels)
    assert len(np.intersect1d(a, b)) < 0.2 * min(a.size, b.size)


class TestFlatCovers:
    def test_a_flat_screenshot_holds_a_large_payload(self):
        # Regression: a screenshot of flat colours made every change cost the
        # maximum, and a payload of a few KiB was reported as impossible.
        pixels = np.full((200, 300, 3), 240, dtype=np.uint8)
        pixels[40:160, 30:270] = 30
        pixels[60:140:12, 40:250] = 220
        cover = Carrier(pixels=pixels, mode="RGB")
        payload = np.random.default_rng(0).bytes(4000)
        stego_carrier, _ = stego.embed(
            cover, payload, "pw", ADAPTIVE, np.random.default_rng(1).bytes
        )
        assert stego.extract(stego_carrier, "pw") == payload

"""Tests for keyed LSB embedding and extraction."""

from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

from shardpix import stego
from shardpix.errors import CapacityError, PayloadNotFoundError
from shardpix.images import from_pil
from shardpix.stego import Method, SampleOrder

from .conftest import PRODUCTION_SCRYPT, natural_image

PASSPHRASE = "correct horse battery staple"
FORMAT_3 = Method.MATCHING
"""Tests of the format-3 layout (positions, one bit per sample) pin the method."""


def frame_positions(samples: np.ndarray, passphrase: str | None, count: int) -> np.ndarray:
    """Where the first ``count`` frame bits of an embedded image live (white-box helper)."""
    eligible = stego.eligible_mask(samples)
    salt_positions = stego._salt_positions(samples.size, eligible)
    public = np.packbits(stego.read_bits(samples, salt_positions)).tobytes()
    key = stego.derive_key(passphrase, public[: stego.SALT_BYTES], public[stego.SALT_BYTES])
    return stego._keyed_order(key, eligible, salt_positions).first(count)


class TestRoundTrip:
    @pytest.mark.parametrize("method", list(Method))
    def test_payload_survives_embedding(self, rgb_carrier, method):
        payload = b"meet me at the library at noon"
        stego_carrier, _ = stego.embed(rgb_carrier, payload, PASSPHRASE, method)
        assert stego.extract(stego_carrier, PASSPHRASE) == payload

    def test_works_without_a_passphrase(self, rgb_carrier):
        stego_carrier, _ = stego.embed(rgb_carrier, b"public", None)
        assert stego.extract(stego_carrier, None) == b"public"

    def test_empty_payload(self, rgb_carrier):
        stego_carrier, _ = stego.embed(rgb_carrier, b"", PASSPHRASE)
        assert stego.extract(stego_carrier, PASSPHRASE) == b""

    def test_payload_filling_the_whole_capacity(self, rgb_carrier):
        payload = np.random.default_rng(1).bytes(stego.carrier_capacity(rgb_carrier))
        stego_carrier, report = stego.embed(rgb_carrier, payload, PASSPHRASE)
        assert report.bits_written <= rgb_carrier.n_samples
        assert stego.extract(stego_carrier, PASSPHRASE) == payload

    def test_greyscale_carrier(self):
        carrier = from_pil(Image.fromarray(natural_image(channels=1)[..., 0]))
        stego_carrier, _ = stego.embed(carrier, b"grey", PASSPHRASE)
        assert stego.extract(stego_carrier, PASSPHRASE) == b"grey"

    def test_unicode_passphrases_are_normalised(self, rgb_carrier):
        composed, decomposed = "caffè", "caffè"
        stego_carrier, _ = stego.embed(rgb_carrier, b"espresso", composed)
        assert stego.extract(stego_carrier, decomposed) == b"espresso"


class TestAuthentication:
    def test_wrong_passphrase_is_rejected(self, rgb_carrier):
        stego_carrier, _ = stego.embed(rgb_carrier, b"secret", PASSPHRASE)
        with pytest.raises(PayloadNotFoundError):
            stego.extract(stego_carrier, "Tr0ub4dor&3")

    def test_missing_passphrase_is_rejected(self, rgb_carrier):
        stego_carrier, _ = stego.embed(rgb_carrier, b"secret", PASSPHRASE)
        with pytest.raises(PayloadNotFoundError):
            stego.extract(stego_carrier, None)

    def test_clean_image_has_no_payload(self, rgb_carrier):
        with pytest.raises(PayloadNotFoundError):
            stego.extract(rgb_carrier, PASSPHRASE)

    def test_a_single_flipped_payload_bit_is_detected(self, rgb_carrier):
        stego_carrier, _ = stego.embed(rgb_carrier, b"integrity matters", PASSPHRASE, FORMAT_3)
        samples = stego_carrier.samples()
        positions = frame_positions(samples, PASSPHRASE, 200)
        samples[positions[150]] ^= 1
        with pytest.raises(PayloadNotFoundError):
            stego.extract(stego_carrier.with_samples(samples), PASSPHRASE)

    def test_the_same_payload_never_produces_the_same_image(self, rgb_carrier):
        first, _ = stego.embed(rgb_carrier, b"same", PASSPHRASE)
        second, _ = stego.embed(rgb_carrier, b"same", PASSPHRASE)
        assert not np.array_equal(first.pixels, second.pixels)


class TestCapacity:
    def test_capacity_accounts_for_salt_fill_limit_and_overhead(self):
        eligible = stego.PUBLIC_BITS + stego.MAX_FILL * 8 * 100
        assert stego.capacity(eligible) == 100 - stego.FRAME_OVERHEAD

    def test_capacity_is_never_negative(self):
        assert stego.capacity(10) == 0

    def test_oversized_payload_raises(self, rgb_carrier):
        too_big = bytes(stego.carrier_capacity(rgb_carrier) + 1)
        with pytest.raises(CapacityError, match="at most"):
            stego.embed(rgb_carrier, too_big, PASSPHRASE)


class TestDistortion:
    def test_matching_changes_samples_by_at_most_one(self, rgb_carrier):
        stego_carrier, _ = stego.embed(rgb_carrier, bytes(2000), PASSPHRASE, Method.MATCHING)
        diff = stego_carrier.pixels.astype(int) - rgb_carrier.pixels.astype(int)
        assert np.abs(diff).max() == 1

    def test_replacement_only_touches_the_lowest_bit(self, rgb_carrier):
        stego_carrier, _ = stego.embed(rgb_carrier, bytes(2000), PASSPHRASE, Method.REPLACEMENT)
        assert np.array_equal(stego_carrier.pixels >> 1, rgb_carrier.pixels >> 1)

    def test_about_half_of_the_written_samples_change(self, large_carrier):
        _, report = stego.embed(large_carrier, bytes(4000), PASSPHRASE, FORMAT_3)
        ratio = report.samples_changed / report.bits_written
        assert 0.45 < ratio < 0.55

    def test_report_rates(self, rgb_carrier):
        _, report = stego.embed(rgb_carrier, bytes(100), PASSPHRASE)
        assert report.frame_bytes == 100 + stego.FRAME_OVERHEAD
        assert report.bits_written == 8 * (stego.PUBLIC_BYTES + report.frame_bytes)
        assert report.embedding_rate == pytest.approx(report.bits_written / rgb_carrier.n_samples)

    def test_fully_saturated_images_have_no_capacity(self):
        for value in (0, 1, 254, 255):
            carrier = from_pil(Image.fromarray(np.full((64, 64, 3), value, np.uint8)))
            assert stego.carrier_capacity(carrier) == 0
            with pytest.raises(CapacityError):
                stego.embed(carrier, b"x", PASSPHRASE)


class TestSaturation:
    """Near-black and near-white samples are never used, and never created."""

    @pytest.fixture
    def clipped(self):
        pixels = natural_image(128, 128, seed=3)
        rng = np.random.default_rng(4)
        clip = rng.random(pixels.shape) < 0.3
        pixels[clip] = rng.choice(np.array([0, 1, 2, 253, 254, 255], np.uint8), clip.sum())
        return from_pil(Image.fromarray(pixels))

    @pytest.mark.parametrize("method", list(Method))
    def test_round_trip_on_a_clipped_image(self, clipped, method):
        payload = bytes(range(256)) * 4
        stego_carrier, _ = stego.embed(clipped, payload, PASSPHRASE, method)
        assert stego.extract(stego_carrier, PASSPHRASE) == payload

    @pytest.mark.parametrize("method", list(Method))
    def test_eligible_set_is_unchanged_by_embedding(self, clipped, method):
        payload = bytes(stego.carrier_capacity(clipped))
        stego_carrier, _ = stego.embed(clipped, payload, PASSPHRASE, method)
        before = stego.eligible_mask(clipped.samples())
        after = stego.eligible_mask(stego_carrier.samples())
        assert np.array_equal(before, after)

    def test_saturated_samples_are_never_touched(self, clipped):
        payload = bytes(stego.carrier_capacity(clipped))
        stego_carrier, _ = stego.embed(clipped, payload, PASSPHRASE)
        excluded = ~stego.eligible_mask(clipped.samples())
        assert np.array_equal(clipped.samples()[excluded], stego_carrier.samples()[excluded])

    def test_capacity_counts_only_eligible_samples(self, clipped):
        usable = int(stego.eligible_mask(clipped.samples()).sum())
        assert usable < clipped.n_samples
        assert stego.carrier_capacity(clipped) == stego.capacity(usable)

    def test_boundary_moves_stay_inside_the_range(self):
        samples = np.array([2, 2, 253, 253, 0, 255], dtype=np.uint8)
        bits = np.array([1, 1, 0, 0, 1, 0], dtype=np.uint8)
        out, _ = stego.write_bits(samples, np.arange(6), bits, Method.MATCHING, low=2, high=253)
        assert out.tolist() == [3, 3, 252, 252, 1, 254]


class TestSampleOrder:
    def test_is_deterministic(self):
        a = SampleOrder(b"k" * 32, 5000).first(300)
        b = SampleOrder(b"k" * 32, 5000).first(300)
        assert np.array_equal(a, b)

    def test_prefixes_are_consistent(self):
        order = SampleOrder(b"k" * 32, 5000)
        assert np.array_equal(order.first(100), order.first(1000)[:100])

    def test_full_order_is_a_permutation(self):
        order = SampleOrder(b"k" * 32, 4096).first(4096)
        assert np.array_equal(np.sort(order), np.arange(4096))

    def test_depends_on_the_key(self):
        a = SampleOrder(b"a" * 32, 5000).first(64)
        b = SampleOrder(b"b" * 32, 5000).first(64)
        assert not np.array_equal(a, b)

    def test_positions_are_spread_over_the_image(self):
        positions = SampleOrder(b"k" * 32, 100_000).first(1000)
        assert positions.min() < 10_000
        assert positions.max() > 90_000

    def test_rejects_impossible_counts(self):
        order = SampleOrder(b"k" * 32, 10)
        with pytest.raises(ValueError):
            order.first(11)
        assert order.first(0).size == 0

    def test_eligibility_mask_restricts_and_preserves_order(self):
        eligible = np.zeros(5000, dtype=bool)
        eligible[::3] = True
        full = SampleOrder(b"k" * 32, 5000).first(5000)
        restricted = SampleOrder(b"k" * 32, 5000, eligible).first(200)
        assert np.all(eligible[restricted])
        assert np.array_equal(restricted, full[eligible[full]][:200])

    def test_eligibility_mask_must_match(self):
        with pytest.raises(ValueError):
            SampleOrder(b"k" * 32, 10, np.ones(9, dtype=bool))


class TestKeyDerivation:
    SALT = bytes(range(16))

    def test_keys_depend_on_the_passphrase(self):
        a = stego.derive_key("one", self.SALT)
        b = stego.derive_key("two", self.SALT)
        assert a.order != b.order and a.aead != b.aead

    def test_keys_depend_on_the_salt(self):
        a = stego.derive_key(PASSPHRASE, self.SALT)
        b = stego.derive_key(PASSPHRASE, bytes(16))
        assert a.order != b.order and a.aead != b.aead

    def test_subkeys_are_independent(self):
        key = stego.derive_key(PASSPHRASE, self.SALT)
        assert key.order != key.aead
        assert key.keyed

    def test_public_key_is_flagged(self):
        assert not stego.derive_key(None, self.SALT).keyed

    def test_salt_length_is_checked(self):
        with pytest.raises(ValueError):
            stego.derive_key(PASSPHRASE, b"short")

    def test_cost_outside_the_accepted_range_is_refused(self):
        with pytest.raises(ValueError):
            stego.derive_key(PASSPHRASE, self.SALT, 30)

    def test_cost_is_read_from_the_image(self, rgb_carrier, monkeypatch):
        """Images keep opening after the default cost changes."""
        monkeypatch.setattr(stego, "SCRYPT_LOG_N", 11)
        stego_carrier, _ = stego.embed(rgb_carrier, b"old cost", PASSPHRASE)
        monkeypatch.setattr(stego, "SCRYPT_LOG_N", 12)
        assert stego.extract(stego_carrier, PASSPHRASE) == b"old cost"

    def test_forged_cost_is_rejected_before_any_key_derivation(self, rgb_carrier):
        """A cost of 2^30 would make scrypt allocate 128 GiB; it must never be attempted."""
        stego_carrier, _ = stego.embed(rgb_carrier, b"x", PASSPHRASE)
        samples = stego_carrier.samples()
        eligible = stego.eligible_mask(samples)
        cost_positions = stego._salt_positions(samples.size, eligible)[-8:]
        samples[cost_positions] = (samples[cost_positions] & 0xFE) | np.unpackbits(
            np.array([30], np.uint8)
        )
        with pytest.raises(PayloadNotFoundError):
            stego.extract(stego_carrier.with_samples(samples), PASSPHRASE)

    def test_same_passphrase_scatters_differently_in_every_image(self, large_carrier):
        """Each embedding draws its own salt, hence its own keys and positions."""
        first, _ = stego.embed(large_carrier, bytes(64), PASSPHRASE, FORMAT_3)
        second, _ = stego.embed(large_carrier, bytes(64), PASSPHRASE, FORMAT_3)
        a = frame_positions(first.samples(), PASSPHRASE, 400)
        b = frame_positions(second.samples(), PASSPHRASE, 400)
        assert len(np.intersect1d(a, b)) < 40

    def test_production_scrypt_cost(self):
        """Tests run with a cheaper cost; make sure the shipped one is what the docs claim."""
        assert PRODUCTION_SCRYPT == (17, 8, 1)


class TestImageModes:
    @pytest.mark.parametrize("channels", [1, 2, 3, 4])
    def test_round_trip_in_every_mode(self, channels):
        base = natural_image(64, 80, channels=min(channels, 3), seed=5)
        if channels == 2:
            base = np.dstack([base[..., 0], np.full((64, 80), 200, np.uint8)])
        elif channels == 4:
            base = np.dstack([base, np.full((64, 80), 200, np.uint8)])
        array = base[..., 0] if channels == 1 else base
        carrier = from_pil(Image.fromarray(array))
        stego_carrier, _ = stego.embed(carrier, b"every mode", PASSPHRASE)
        assert stego.extract(stego_carrier, PASSPHRASE) == b"every mode"
        if channels in (2, 4):
            assert np.array_equal(stego_carrier.pixels[..., -1], carrier.pixels[..., -1])


class TestNaiveBounds:
    """The default bounds model naive tools; only 0 and 255 are forced (mutation testing)."""

    def test_only_the_extremes_are_forced(self):
        samples = np.array([1] * 400 + [254] * 400, dtype=np.uint8)
        bits = np.array([0] * 400 + [1] * 400, dtype=np.uint8)
        out, changed = stego.write_bits(samples, np.arange(800), bits, Method.MATCHING)
        assert changed == 800
        assert set(out[:400].tolist()) == {0, 2}
        assert set(out[400:].tolist()) == {253, 255}

    def test_extremes_move_inwards(self):
        samples = np.array([0, 255], dtype=np.uint8)
        out, _ = stego.write_bits(
            samples, np.arange(2), np.array([1, 0], np.uint8), Method.MATCHING
        )
        assert out.tolist() == [1, 254]

    def test_output_dtype(self):
        out, _ = stego.write_bits(
            np.array([10, 11], np.uint8),
            np.arange(2),
            np.array([1, 1], np.uint8),
            Method.REPLACEMENT,
        )
        assert out.dtype == np.uint8


class TestBoundaries:
    """Exact capacity edges (from mutation testing)."""

    @staticmethod
    def carrier_with_eligible(count: int):
        pixels = np.zeros(count + 40, dtype=np.uint8)
        pixels[:count] = 100
        return from_pil(Image.fromarray(pixels.reshape(1, -1)))

    def test_smallest_usable_image_holds_an_empty_payload(self):
        smallest = stego.PUBLIC_BITS + stego.MAX_FILL * 8 * stego.FRAME_OVERHEAD
        carrier = self.carrier_with_eligible(smallest)
        assert stego.carrier_capacity(carrier) == 0
        stego_carrier, report = stego.embed(carrier, b"", PASSPHRASE)
        assert report.eligible_samples == smallest
        assert stego.extract(stego_carrier, PASSPHRASE) == b""

    def test_one_sample_less_holds_nothing(self):
        smallest = stego.PUBLIC_BITS + stego.MAX_FILL * 8 * stego.FRAME_OVERHEAD
        carrier = self.carrier_with_eligible(smallest - stego.MAX_FILL * 8)
        with pytest.raises(CapacityError, match="too small"):
            stego.embed(carrier, b"", PASSPHRASE)
        with pytest.raises(PayloadNotFoundError):
            stego.extract(carrier, PASSPHRASE)

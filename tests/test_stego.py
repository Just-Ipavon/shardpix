"""Tests for keyed LSB embedding and extraction."""

from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

from shardpix import stego
from shardpix.errors import CapacityError, PayloadNotFoundError
from shardpix.images import from_pil
from shardpix.stego import Method, SampleOrder

from .conftest import natural_image

PASSPHRASE = "correct horse battery staple"


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
        payload = np.random.default_rng(1).bytes(stego.capacity(rgb_carrier.n_samples))
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
        stego_carrier, _ = stego.embed(rgb_carrier, b"integrity matters", PASSPHRASE)
        key = stego.derive_key(PASSPHRASE, stego_carrier.geometry)
        positions = SampleOrder(key.order, stego_carrier.n_samples).first(200)
        samples = stego_carrier.samples()
        samples[positions[150]] ^= 1
        with pytest.raises(PayloadNotFoundError):
            stego.extract(stego_carrier.with_samples(samples), PASSPHRASE)

    def test_the_same_payload_never_produces_the_same_image(self, rgb_carrier):
        first, _ = stego.embed(rgb_carrier, b"same", PASSPHRASE)
        second, _ = stego.embed(rgb_carrier, b"same", PASSPHRASE)
        assert not np.array_equal(first.pixels, second.pixels)


class TestCapacity:
    def test_capacity_accounts_for_the_frame_overhead(self):
        assert stego.capacity(8 * 100) == 100 - stego.FRAME_OVERHEAD

    def test_capacity_is_never_negative(self):
        assert stego.capacity(10) == 0

    def test_oversized_payload_raises(self, rgb_carrier):
        too_big = bytes(stego.capacity(rgb_carrier.n_samples) + 1)
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
        _, report = stego.embed(large_carrier, bytes(4000), PASSPHRASE)
        ratio = report.samples_changed / report.bits_written
        assert 0.45 < ratio < 0.55

    def test_report_rates(self, rgb_carrier):
        _, report = stego.embed(rgb_carrier, bytes(100), PASSPHRASE)
        assert report.frame_bytes == 100 + stego.FRAME_OVERHEAD
        assert report.bits_written == 8 * report.frame_bytes
        assert report.embedding_rate == pytest.approx(report.bits_written / rgb_carrier.n_samples)

    def test_matching_handles_saturated_samples(self):
        white = from_pil(Image.fromarray(np.full((64, 64, 3), 255, np.uint8)))
        black = from_pil(Image.fromarray(np.zeros((64, 64, 3), np.uint8)))
        for carrier in (white, black):
            stego_carrier, _ = stego.embed(carrier, bytes(range(256)), PASSPHRASE)
            assert stego.extract(stego_carrier, PASSPHRASE) == bytes(range(256))


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


class TestKeyDerivation:
    def test_keys_depend_on_the_passphrase(self):
        a = stego.derive_key("one", (10, 10, 3))
        b = stego.derive_key("two", (10, 10, 3))
        assert a.order != b.order and a.aead != b.aead

    def test_keys_depend_on_the_geometry(self):
        a = stego.derive_key(PASSPHRASE, (10, 10, 3))
        b = stego.derive_key(PASSPHRASE, (10, 11, 3))
        assert a.order != b.order

    def test_subkeys_are_independent(self):
        key = stego.derive_key(PASSPHRASE, (10, 10, 3))
        assert key.order != key.aead
        assert key.keyed

    def test_public_key_is_flagged(self):
        assert not stego.derive_key(None, (10, 10, 3)).keyed

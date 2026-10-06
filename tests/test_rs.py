"""Tests for RS steganalysis."""

from __future__ import annotations

import numpy as np
import pytest

from shardpix import stego
from shardpix.analysis import rs
from shardpix.stego import Method, SampleOrder

from .conftest import processed_image


def embed_at_rate(
    pixels: np.ndarray, rate: float, method: Method, *, aware: bool = False, seed: int = 0
) -> np.ndarray:
    """Write random bits into a random ``rate`` fraction of the samples.

    ``aware`` reproduces what :func:`stego.embed` does - skip near-saturated
    samples and keep changes inside 2-253 - instead of naive embedding.
    """
    rng = np.random.default_rng(seed)
    samples = pixels.reshape(-1)
    eligible = stego.eligible_mask(samples) if aware else None
    order = SampleOrder(rng.bytes(32), samples.size, eligible)
    count = min(int(rate * samples.size), order.n_samples)
    bits = rng.integers(0, 2, count).astype(np.uint8)
    bounds = {"low": stego.ELIGIBLE_MIN, "high": stego.ELIGIBLE_MAX} if aware else {}
    out, _ = stego.write_bits(samples, order.first(count), bits, method, **bounds)
    return out.reshape(pixels.shape)


@pytest.fixture(scope="module")
def cover() -> np.ndarray:
    return processed_image(256, 256, seed=1)


class TestFlips:
    def test_positive_flip_pairs_values(self):
        values = np.array([0, 1, 2, 3, 254, 255], dtype=np.int16)
        assert rs._flip_positive(values).tolist() == [1, 0, 3, 2, 255, 254]

    def test_negative_flip_pairs_shifted_values(self):
        values = np.array([-1, 0, 1, 2, 255, 256], dtype=np.int16)
        assert rs._flip_negative(values).tolist() == [0, -1, 2, 1, 256, 255]

    def test_flips_are_involutions(self):
        values = np.arange(-1, 257, dtype=np.int16)
        assert np.array_equal(rs._flip_positive(rs._flip_positive(values)), values)
        assert np.array_equal(rs._flip_negative(rs._flip_negative(values)), values)


class TestEstimate:
    def test_clean_image_is_near_zero(self, cover):
        assert abs(rs.mean_rate(rs.estimate(cover))) < 0.05

    @pytest.mark.parametrize("rate", [0.1, 0.3, 0.5])
    def test_tracks_lsb_replacement(self, cover, rate):
        stego_pixels = embed_at_rate(cover, rate, Method.REPLACEMENT)
        assert rs.mean_rate(rs.estimate(stego_pixels)) == pytest.approx(rate, abs=0.06)

    def test_naive_lsb_matching_leaks_through_clipped_samples(self, cover):
        """Samples stuck at 0 or 255 can only move one way, which looks like replacement."""
        assert (cover == 0).mean() > 0.01
        stego_pixels = embed_at_rate(cover, 0.5, Method.MATCHING)
        assert rs.mean_rate(rs.estimate(stego_pixels)) > 0.08

    def test_saturation_aware_lsb_matching_stays_near_the_noise_floor(self, cover):
        clean = rs.mean_rate(rs.estimate(cover))
        stego_pixels = embed_at_rate(cover, 0.5, Method.MATCHING, aware=True)
        assert rs.mean_rate(rs.estimate(stego_pixels)) - clean < 0.04

    def test_one_result_per_channel(self, cover):
        assert len(rs.estimate(cover)) == 3
        assert len(rs.estimate(cover[..., 0])) == 1
        assert len(rs.estimate(cover, channels=2)) == 2

    def test_counts_are_proportions(self, cover):
        result = rs.estimate_channel(cover[..., 0])
        for counts in (result.counts, result.counts_flipped):
            assert 0 <= counts.regular + counts.singular <= 1
            assert 0 <= counts.regular_neg + counts.singular_neg <= 1

    def test_flat_channel_does_not_crash(self):
        assert rs.estimate_channel(np.full((16, 16), 128, np.uint8)).rate == pytest.approx(0.0)

    def test_rejects_tiny_or_malformed_input(self):
        with pytest.raises(ValueError):
            rs.estimate_channel(np.zeros((4, 3), np.uint8))
        with pytest.raises(ValueError):
            rs.estimate_channel(np.zeros(16, np.uint8))

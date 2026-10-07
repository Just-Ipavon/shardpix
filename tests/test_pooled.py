"""Pooled steganalysis: the simulation of an adversary holding several images."""

from __future__ import annotations

import numpy as np
import pytest

from shardpix.analysis import pooled


def votes(rng: np.random.Generator, n: int, a: float, b: float = 5.0) -> np.ndarray:
    """Ensemble-like scores: multiples of 1/51 between 0 and 1."""
    return np.round(rng.beta(a, b, n) * 51) / 51


@pytest.fixture
def rng():
    return np.random.default_rng(0)


class TestGroups:
    def test_groups_hold_distinct_indices(self, rng):
        groups = pooled._groups(100, 7, 500, rng)
        assert groups.shape == (500, 7)
        assert all(len(set(g)) == 7 for g in groups)
        assert groups.min() >= 0 and groups.max() < 100

    def test_group_larger_than_the_images_is_refused(self, rng):
        with pytest.raises(ValueError):
            pooled._groups(5, 6, 10, rng)


class TestLikelihoodModel:
    def test_log_odds_increase_towards_the_stego_scores(self, rng):
        c, s = votes(rng, 4000, 5), votes(rng, 4000, 7)
        model = pooled._llr_model(c, s)
        assert pooled._llr(np.array([0.7]), model)[0] > pooled._llr(np.array([0.3]), model)[0]

    def test_identical_classes_give_a_flat_ratio(self, rng):
        c, s = votes(rng, 4000, 5), votes(rng, 4000, 5)
        ratios = pooled._llr(np.linspace(0.2, 0.8, 7), pooled._llr_model(c, s))
        assert np.ptp(ratios) < 0.3


class TestPooled:
    @pytest.mark.parametrize("method", ["mean", "llr"])
    def test_no_signal_stays_at_chance_for_any_group(self, rng, method):
        c, s = votes(rng, 4000, 5), votes(rng, 4000, 5)
        for g in (1, 10):
            r = pooled.pooled(c, s, g, method, splits=8, trials=2000)
            assert r.p_e_low <= 0.5 <= r.p_e_high + 0.02
            assert abs(r.auc - 0.5) < 0.06

    @pytest.mark.parametrize("method", ["mean", "llr"])
    def test_a_weak_signal_grows_with_the_group(self, rng, method):
        c, s = votes(rng, 4000, 5), votes(rng, 4000, 5.6)
        single = pooled.pooled(c, s, 1, method, splits=8, trials=2000)
        many = pooled.pooled(c, s, 20, method, splits=8, trials=2000)
        assert many.p_e < single.p_e - 0.05
        assert many.auc > single.auc

    def test_rejects_bad_arguments(self, rng):
        c = votes(rng, 100, 5)
        with pytest.raises(ValueError):
            pooled.pooled(c, c, 1, "median")
        with pytest.raises(ValueError):
            pooled.pooled(c, c, 50, "mean")

    def test_is_reproducible(self, rng):
        c, s = votes(rng, 2000, 5), votes(rng, 2000, 5.5)
        a = pooled.pooled(c, s, 5, "llr", seed=3, splits=4, trials=1000)
        b = pooled.pooled(c, s, 5, "llr", seed=3, splits=4, trials=1000)
        assert a == b

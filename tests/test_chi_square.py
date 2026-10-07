"""Tests for the chi-square attack."""

from __future__ import annotations

import numpy as np
import pytest

from shardpix import stego
from shardpix.analysis import chi_square
from shardpix.stego import Method


class TestChi2Sf:
    @pytest.mark.parametrize(
        "statistic,dof,expected",
        [
            (3.841458820694124, 1, 0.05),
            (6.634896601021213, 1, 0.01),
            (18.307038053275146, 10, 0.05),
            (124.34211340400407, 100, 0.05),
        ],
    )
    def test_matches_textbook_critical_values(self, statistic, dof, expected):
        assert chi_square.chi2_sf(statistic, dof) == pytest.approx(expected, rel=1e-9)

    def test_matches_scipy_across_the_range_used(self):
        scipy_stats = pytest.importorskip("scipy.stats")
        for dof in (1, 2, 5, 30, 63, 127):
            for statistic in np.linspace(0.01, 4 * dof + 50, 40):
                ours = chi_square.chi2_sf(float(statistic), dof)
                assert ours == pytest.approx(
                    scipy_stats.chi2.sf(statistic, dof), rel=1e-8, abs=1e-14
                )

    def test_zero_statistic_is_certain(self):
        assert chi_square.chi2_sf(0.0, 5) == 1.0

    def test_subnormal_statistic_does_not_crash(self):
        """Found by fuzzing: 5e-324 / 2 underflows to 0 and log(0) raised."""
        assert chi_square.chi2_sf(5e-324, 1) == 1.0

    def test_rejects_non_positive_dof(self):
        with pytest.raises(ValueError):
            chi_square.chi2_sf(1.0, 0)


class TestPairTest:
    def test_clean_image_is_not_flagged(self, combed_carrier):
        assert chi_square.pair_test(combed_carrier.samples()).p_value < 0.01

    def test_full_lsb_replacement_is_flagged(self, combed_carrier):
        samples = combed_carrier.samples()
        bits = np.random.default_rng(3).integers(0, 2, samples.size).astype(np.uint8)
        full, _ = stego.write_bits(samples, np.arange(samples.size), bits, Method.REPLACEMENT)
        assert chi_square.pair_test(full).p_value > 0.9

    def test_flat_image_has_too_few_categories(self):
        result = chi_square.pair_test(np.full(1000, 128, np.uint8))
        assert result.dof == 0
        assert result.p_value == 0.0


class TestSequentialAttack:
    def test_estimates_the_length_of_a_sequential_payload(self, combed_carrier):
        samples = combed_carrier.samples()
        used = int(0.4 * samples.size)
        bits = np.random.default_rng(5).integers(0, 2, used).astype(np.uint8)
        embedded, _ = stego.write_bits(samples, np.arange(used), bits, Method.REPLACEMENT)
        prefix = chi_square.sequential_attack(embedded, steps=50).detected_prefix()
        assert 0.3 <= prefix <= 0.5

    def test_clean_image_shows_no_signature(self, combed_carrier):
        curve = chi_square.sequential_attack(combed_carrier.samples(), steps=50)
        assert curve.detected_prefix() < 0.1

    def test_keyed_low_rate_embedding_is_not_detected(self, combed_carrier):
        stego_carrier, _ = stego.embed(combed_carrier, bytes(500), "pw", Method.REPLACEMENT)
        curve = chi_square.sequential_attack(stego_carrier.samples(), steps=50)
        assert curve.detected_prefix() < 0.1

    def test_curve_shape(self, combed_carrier):
        curve = chi_square.sequential_attack(combed_carrier.samples(), steps=20)
        assert curve.fractions.size == curve.p_values.size == 20
        assert curve.fractions[-1] == 1.0

    def test_detected_prefix_covers_whole_image_when_never_below(self):
        curve = chi_square.ChiSquareCurve(np.array([0.5, 1.0]), np.array([0.9, 0.8]))
        assert curve.detected_prefix() == 1.0

    def test_rejects_zero_steps(self):
        with pytest.raises(ValueError):
            chi_square.sequential_attack(np.zeros(10, np.uint8), steps=0)


def _laplacian_coefficients(n: int = 200_000, seed: int = 0) -> np.ndarray:
    """Quantised DCT coefficients shaped like a photo's: peaked at 0, two-sided."""
    rng = np.random.default_rng(seed)
    return np.round(rng.laplace(0, 3.0, n)).astype(np.int64)


def _jsteg(coefficients: np.ndarray, fraction: float, seed: int = 1) -> np.ndarray:
    """Overwrite the lowest bit of the first ``fraction`` of usable coefficients, as JSteg."""
    out = coefficients.copy()
    usable = np.flatnonzero((out != 0) & (out != 1))
    chosen = usable[: int(fraction * usable.size)]
    out[chosen] = (out[chosen] & ~1) | np.random.default_rng(seed).integers(0, 2, chosen.size)
    return out


class TestCoefficients:
    def test_clean_coefficients_are_not_flagged(self):
        assert chi_square.coefficient_pair_test(_laplacian_coefficients()).p_value < 0.01

    def test_full_jsteg_embedding_is_flagged(self):
        stego_coefficients = _jsteg(_laplacian_coefficients(), 1.0)
        assert chi_square.coefficient_pair_test(stego_coefficients).p_value > 0.5

    def test_sequential_attack_finds_the_payload_length(self):
        # A million coefficients, as in a small photo: each step holds enough of them.
        stego_coefficients = _jsteg(_laplacian_coefficients(1_000_000), 0.5)
        curve = chi_square.sequential_coefficient_attack(stego_coefficients, steps=20)
        assert 0.4 <= curve.detected_prefix() <= 0.6

    def test_negative_values_pair_in_twos_complement(self):
        # -2 and -1 form a pair, as 2 and 3 do; (0, 1) is left out.
        values = np.array([-2] * 50 + [-1] * 50 + [0] * 900 + [1] * 10 + [2] * 50 + [3] * 50)
        result = chi_square.coefficient_pair_test(values)
        assert result.dof == 1
        assert result.statistic == 0.0

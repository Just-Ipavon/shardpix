"""Tests for GF(256) arithmetic."""

from __future__ import annotations

import itertools
import random

import numpy as np
import pytest

from shardpix import gf256


class TestTables:
    def test_multiplication_matches_the_reference_for_every_pair(self):
        for a, b in itertools.product(range(256), repeat=2):
            assert gf256.mul(a, b) == gf256.mul_reference(a, b)

    def test_generator_produces_every_non_zero_element(self):
        assert sorted(gf256.EXP[: gf256.ORDER]) == list(range(1, 256))

    @pytest.mark.parametrize(
        "a,b,product",
        [(0x57, 0x83, 0xC1), (0x57, 0x13, 0xFE), (0x53, 0xCA, 0x01)],
    )
    def test_fips_197_worked_examples(self, a, b, product):
        assert gf256.mul(a, b) == product


class TestFieldAxioms:
    def test_every_non_zero_element_has_an_inverse(self):
        for a in range(1, 256):
            assert gf256.mul(a, gf256.inv(a)) == 1

    def test_zero_has_no_inverse(self):
        with pytest.raises(ZeroDivisionError):
            gf256.inv(0)
        with pytest.raises(ZeroDivisionError):
            gf256.div(5, 0)

    def test_division_undoes_multiplication(self):
        for a in range(256):
            for b in range(1, 256, 7):
                assert gf256.mul(gf256.div(a, b), b) == a

    def test_distributive_and_associative(self):
        rng = random.Random(0)
        for _ in range(2000):
            a, b, c = (rng.randrange(256) for _ in range(3))
            assert gf256.mul(a, b ^ c) == gf256.mul(a, b) ^ gf256.mul(a, c)
            assert gf256.mul(gf256.mul(a, b), c) == gf256.mul(a, gf256.mul(b, c))

    def test_addition_is_its_own_inverse(self):
        for a in range(256):
            assert gf256.add(a, a) == 0


class TestVectorised:
    def test_mul_bytes_matches_scalar_multiplication(self):
        values = np.arange(256, dtype=np.uint8)
        for scalar in (0, 1, 2, 3, 0x53, 0xFF):
            expected = [gf256.mul(int(v), scalar) for v in values]
            assert gf256.mul_bytes(values, scalar).tolist() == expected

    def test_eval_poly_constant(self):
        constant = np.array([7, 8, 9], dtype=np.uint8)
        assert gf256.eval_poly([constant], 42).tolist() == [7, 8, 9]

    def test_eval_poly_matches_naive_evaluation(self):
        rng = np.random.default_rng(1)
        coefficients = [rng.integers(0, 256, 16, dtype=np.uint8) for _ in range(4)]
        for x in (1, 2, 200):
            expected = []
            for byte in range(16):
                total, power = 0, 1
                for coefficient in coefficients:
                    total ^= gf256.mul(int(coefficient[byte]), power)
                    power = gf256.mul(power, x)
                expected.append(total)
            assert gf256.eval_poly(coefficients, x).tolist() == expected

    def test_eval_poly_needs_coefficients(self):
        with pytest.raises(ValueError):
            gf256.eval_poly([], 1)


class TestInterpolation:
    def test_recovers_the_constant_term(self):
        rng = np.random.default_rng(2)
        coefficients = [rng.integers(0, 256, 32, dtype=np.uint8) for _ in range(5)]
        xs = [3, 77, 150, 201, 255]
        ys = [gf256.eval_poly(coefficients, x) for x in xs]
        assert np.array_equal(gf256.interpolate_at_zero(xs, ys), coefficients[0])

    def test_rejects_repeated_x(self):
        with pytest.raises(ValueError, match="distinct"):
            gf256.lagrange_at_zero([1, 1])

    def test_rejects_x_zero(self):
        with pytest.raises(ValueError):
            gf256.lagrange_at_zero([0, 1])

    def test_rejects_mismatched_points(self):
        with pytest.raises(ValueError):
            gf256.interpolate_at_zero([1, 2], [np.zeros(1, np.uint8)])

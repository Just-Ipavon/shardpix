"""Property-based tests and parser fuzzing (Hypothesis).

The example-based tests check chosen cases; these check *claims*, over
inputs Hypothesis generates and then shrinks to a minimal counterexample when
a claim fails. Two kinds of property are covered:

* correctness: any k shares recover the secret, any payload that fits round
  trips, encodings are lossless;
* robustness: arbitrary or corrupted bytes fed to a parser end in the
  module's own error, never in a crash or, worse, in wrong data.

The default profile keeps the suite fast; ``HYPOTHESIS_PROFILE=fuzz`` runs
thousands of examples per property (see docs/06-security-review.md).
"""

from __future__ import annotations

import os
import unicodedata

import numpy as np
import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from PIL import Image

from shardpix import gf256, shamir, stego, vault
from shardpix.analysis import chi_square, rs
from shardpix.errors import PayloadNotFoundError, ShareError, ShareFormatError, VaultError
from shardpix.images import from_pil

settings.register_profile(
    "default",
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
settings.register_profile(
    "fuzz",
    max_examples=3000,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

byte = st.integers(0, 255)
nonzero = st.integers(1, 255)


# --------------------------------------------------------------------------- GF(256)


@given(byte, byte, byte)
def test_field_axioms(a, b, c):
    assert gf256.mul(a, b) == gf256.mul(b, a)
    assert gf256.mul(a, gf256.mul(b, c)) == gf256.mul(gf256.mul(a, b), c)
    assert gf256.mul(a, b ^ c) == gf256.mul(a, b) ^ gf256.mul(a, c)
    assert gf256.mul(a, 1) == a


@given(byte, nonzero)
def test_division_inverts_multiplication(a, b):
    assert gf256.div(gf256.mul(a, b), b) == a


# --------------------------------------------------------------------------- Shamir


@st.composite
def split_parameters(draw):
    count = draw(st.integers(2, 10))
    threshold = draw(st.integers(2, count))
    secret = draw(st.binary(min_size=1, max_size=48))
    return secret, threshold, count


@given(split_parameters(), st.randoms(use_true_random=False))
def test_any_threshold_subset_recovers_the_secret(params, rnd):
    secret, threshold, count = params
    shares = shamir.split(secret, threshold, count)
    subset = rnd.sample(shares, rnd.randint(threshold, count))
    recovery = shamir.combine(subset)
    assert recovery.secret == secret
    assert len(recovery.used) + len(recovery.confirmed) == len(subset)
    assert recovery.rejected == ()


@given(split_parameters())
def test_fewer_than_threshold_shares_never_recover(params):
    secret, threshold, count = params
    shares = shamir.split(secret, threshold, count)
    with pytest.raises(ShareError):
        shamir.combine(shares[: threshold - 1])


@given(split_parameters())
def test_share_encodings_are_lossless(params):
    secret, threshold, count = params
    for share in shamir.split(secret, threshold, count):
        assert shamir.Share.from_bytes(share.to_bytes()) == share
        assert shamir.Share.from_text(share.to_text()) == share


@given(st.binary(max_size=300))
def test_share_parser_only_raises_its_own_error(data):
    try:
        shamir.Share.from_bytes(data)
    except ShareFormatError:
        pass


@given(st.text(max_size=300))
def test_share_text_parser_only_raises_its_own_error(text):
    try:
        shamir.Share.from_text(text)
    except ShareFormatError:
        pass


@given(st.data())
def test_any_corrupted_byte_is_caught_by_the_checksum(data):
    share = shamir.split(b"0123456789abcdef", 2, 3)[0]
    raw = bytearray(share.to_bytes())
    position = data.draw(st.integers(0, len(raw) - 1))
    raw[position] ^= data.draw(nonzero)
    with pytest.raises(ShareFormatError):
        shamir.Share.from_bytes(bytes(raw))


@given(st.data())
def test_a_forged_value_is_never_accepted(data):
    """Even with a valid checksum, an altered share is rejected by its MAC, never used."""
    secret = os.urandom(32)
    shares = shamir.split(secret, 3, 5)
    victim = data.draw(st.integers(0, 4))
    value = bytearray(shares[victim].value)
    position = data.draw(st.integers(0, len(value) - 1))
    value[position] ^= data.draw(nonzero)
    forged = shamir.Share(**{**shares[victim].__dict__, "value": bytes(value)})
    pool = shares[:victim] + [forged] + shares[victim + 1 :]
    recovery = shamir.combine(pool)
    assert recovery.secret == secret
    assert forged not in recovery.used + recovery.confirmed


# --------------------------------------------------------------------------- steganography


@st.composite
def carriers(draw):
    height = draw(st.integers(24, 48))
    width = draw(st.integers(24, 48))
    channels = draw(st.sampled_from([1, 3, 4]))
    seed = draw(st.integers(0, 2**32 - 1))
    rng = np.random.default_rng(seed)
    low = draw(st.integers(0, 120))
    pixels = rng.integers(low, low + draw(st.integers(20, 135)), (height, width, channels))
    pixels = np.clip(pixels, 0, 255).astype(np.uint8)
    array = pixels[..., 0] if channels == 1 else pixels
    return from_pil(Image.fromarray(array))


@given(carriers(), st.data(), st.sampled_from(list(stego.Method)))
def test_any_payload_that_fits_round_trips(carrier, data, method):
    room = stego.carrier_capacity(carrier)
    assume(room > 0)
    payload = data.draw(st.binary(max_size=min(room, 200)))
    stego_carrier, report = stego.embed(carrier, payload, "pw", method)
    assert stego.extract(stego_carrier, "pw") == payload
    assert np.abs(stego_carrier.pixels.astype(int) - carrier.pixels.astype(int)).max() <= 1
    assert report.bits_written <= carrier.n_samples


@given(carriers(), st.data())
def test_changing_one_sample_never_yields_different_data(carrier, data):
    """A modified image gives back the original payload or nothing - never something else."""
    assume(stego.carrier_capacity(carrier) >= 16)
    payload = b"exact sixteen by"
    stego_carrier, _ = stego.embed(carrier, payload, "pw")
    samples = stego_carrier.samples()
    position = data.draw(st.integers(0, samples.size - 1))
    samples[position] = (int(samples[position]) + data.draw(st.sampled_from([-1, 1]))) % 256
    try:
        assert stego.extract(stego_carrier.with_samples(samples), "pw") == payload
    except PayloadNotFoundError:
        pass


@given(carriers(), st.text(max_size=20))
def test_extracting_from_any_image_only_raises_its_own_error(carrier, passphrase):
    try:
        stego.extract(carrier, passphrase or None)
    except PayloadNotFoundError:
        pass


# --------------------------------------------------------------------------- vault


@given(st.binary(max_size=200))
def test_vault_header_parser_only_raises_its_own_error(data):
    try:
        vault.VaultHeader.from_bytes(data)
    except VaultError:
        pass


@given(st.text())
def test_restored_names_are_always_harmless(name):
    safe = vault.safe_filename(name)
    assert safe
    assert "/" not in safe and "\\" not in safe
    assert safe not in {".", ".."}
    assert not any(unicodedata.category(c) in {"Cc", "Cf"} for c in safe)
    assert safe.split(".")[0].upper() not in vault._WINDOWS_RESERVED


# --------------------------------------------------------------------------- analysis


@given(st.floats(0, 1e4), st.floats(0, 1e4), st.integers(1, 255))
def test_chi2_sf_is_a_decreasing_probability(x, y, dof):
    low, high = sorted((x, y))
    p_low, p_high = chi_square.chi2_sf(low, dof), chi_square.chi2_sf(high, dof)
    assert 0.0 <= p_high <= p_low <= 1.0


@given(st.integers(4, 40), st.integers(1, 40), st.integers(0, 2**32 - 1))
def test_rs_never_crashes_and_stays_finite(width, height, seed):
    channel = np.random.default_rng(seed).integers(0, 256, (height, width)).astype(np.uint8)
    assert np.isfinite(rs.estimate_channel(channel).rate)

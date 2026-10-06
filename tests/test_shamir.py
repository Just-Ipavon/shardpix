"""Tests for Shamir secret sharing with authenticated shares."""

from __future__ import annotations

import itertools
import os
from dataclasses import replace

import pytest

from shardpix import shamir
from shardpix.errors import (
    InconsistentSharesError,
    InsufficientSharesError,
    ShareAuthenticationError,
    ShareFormatError,
)
from shardpix.shamir import Share

SECRET = os.urandom(32)


def tamper(share: Share, **changes) -> Share:
    """A modified share whose checksum is valid - what a deliberate forger would produce."""
    return replace(share, **changes)


def flip_first_value_byte(share: Share) -> Share:
    return tamper(share, value=bytes([share.value[0] ^ 0x01]) + share.value[1:])


@pytest.fixture(scope="module")
def shares() -> list[Share]:
    return shamir.split(SECRET, threshold=3, count=5)


class TestSplitCombine:
    def test_every_threshold_subset_recovers_the_secret(self, shares):
        for subset in itertools.combinations(shares, 3):
            assert shamir.combine(subset).secret == SECRET

    def test_extra_shares_are_confirmed(self, shares):
        recovery = shamir.combine(shares)
        assert len(recovery.used) == 3
        assert len(recovery.confirmed) == 2
        assert recovery.rejected == ()

    def test_order_does_not_matter(self, shares):
        assert shamir.combine(reversed(shares[:3])).secret == SECRET

    def test_duplicates_count_once(self, shares):
        with pytest.raises(InsufficientSharesError, match="need 3"):
            shamir.combine([shares[0], shares[0], shares[1]])

    def test_too_few_shares(self, shares):
        with pytest.raises(InsufficientSharesError):
            shamir.combine(shares[:2])

    def test_no_shares(self):
        with pytest.raises(InsufficientSharesError):
            shamir.combine([])

    @pytest.mark.parametrize("threshold,count", [(2, 2), (2, 3), (5, 9), (255, 255)])
    def test_parameter_extremes(self, threshold, count):
        secret = b"\x00\xff" * 8
        result = shamir.split(secret, threshold, count)
        assert shamir.combine(result[-threshold:]).secret == secret

    def test_long_secret(self):
        secret = os.urandom(shamir.MAX_SECRET_BYTES)
        assert shamir.combine(shamir.split(secret, 2, 3)[1:]).secret == secret

    @pytest.mark.parametrize(
        "secret,threshold,count",
        [(b"", 2, 3), (b"x", 1, 3), (b"x", 4, 3), (b"x", 2, 256), (bytes(70_000), 2, 3)],
    )
    def test_invalid_parameters(self, secret, threshold, count):
        with pytest.raises(ValueError):
            shamir.split(secret, threshold, count)

    def test_shares_are_fresh_every_time(self):
        first = shamir.split(SECRET, 2, 2)
        second = shamir.split(SECRET, 2, 2)
        assert first[0].value != second[0].value
        assert first[0].group_id != second[0].group_id


class TestSecrecy:
    def test_one_share_of_a_2_of_n_split_is_independent_of_the_secret(self):
        """Every share value is equally likely whatever the secret.

        With threshold 2, a byte of share x is ``s + a * x`` for a random
        coefficient ``a``. Enumerating all 256 coefficients must produce all
        256 share bytes, for any secret byte: the share alone says nothing.
        """
        for secret_byte in (0x00, 0x55, 0xFF):
            seen = set()
            for coefficient in range(256):
                stream = iter([bytes(16), bytes(32), bytes([coefficient]) * 33])
                result = shamir.split(
                    bytes([secret_byte]), 2, 3, random_bytes=lambda n, s=stream: next(s)[:n]
                )
                seen.add(result[2].value[0])
            assert seen == set(range(256))


class TestEncoding:
    def test_bytes_round_trip(self, shares):
        for share in shares:
            assert Share.from_bytes(share.to_bytes()) == share

    def test_text_round_trip(self, shares):
        text = shares[0].to_text()
        assert text.startswith("spx1-")
        assert Share.from_text(text) == shares[0]

    def test_text_ignores_whitespace_and_case(self, shares):
        text = shares[0].to_text()
        messy = "  " + text[:20].upper() + "\n" + text[20:] + "  "
        assert Share.from_text(messy) == shares[0]

    def test_encoded_size(self, shares):
        assert len(shares[0].to_bytes()) == shamir.share_size(len(SECRET))

    def test_a_flipped_bit_breaks_the_checksum(self, shares):
        raw = bytearray(shares[0].to_bytes())
        raw[30] ^= 0x04
        with pytest.raises(ShareFormatError, match="checksum"):
            Share.from_bytes(bytes(raw))

    @pytest.mark.parametrize(
        "text,match",
        [
            ("hello", "start with"),
            ("spx1-!!!!", "base32"),
            ("spx1-aaaa", "truncated"),
        ],
    )
    def test_malformed_text(self, text, match):
        with pytest.raises(ShareFormatError, match=match):
            Share.from_text(text)

    def test_wrong_magic(self, shares):
        raw = b"XXXX" + shares[0].to_bytes()[4:]
        with pytest.raises(ShareFormatError, match="not a shardpix share"):
            Share.from_bytes(raw)

    def test_unsupported_version(self, shares):
        raw = bytearray(shares[0].to_bytes())
        raw[4] = 9
        with pytest.raises(ShareFormatError, match="version"):
            Share.from_bytes(bytes(raw))

    @pytest.mark.parametrize(
        "field,value,match", [("threshold", 1, "threshold"), ("index", 0, "0")]
    )
    def test_invalid_fields_are_rejected_even_with_a_valid_checksum(
        self, shares, field, value, match
    ):
        forged = tamper(shares[0], **{field: value})
        with pytest.raises(ShareFormatError, match=match):
            Share.from_bytes(forged.to_bytes())

    def test_length_mismatch(self, shares):
        forged = tamper(shares[0], secret_length=shares[0].secret_length + 1)
        with pytest.raises(ShareFormatError, match="length"):
            Share.from_bytes(forged.to_bytes())


class TestAuthentication:
    def test_corrupted_share_is_identified_when_enough_good_shares_remain(self, shares):
        bad = flip_first_value_byte(shares[1])
        recovery = shamir.combine([shares[0], bad, shares[2], shares[3]])
        assert recovery.secret == SECRET
        assert [r.share for r in recovery.rejected] == [bad]
        assert "failed authentication" in recovery.rejected[0].reason

    def test_corruption_is_detected_with_exactly_threshold_shares(self, shares):
        bad = flip_first_value_byte(shares[1])
        with pytest.raises(ShareAuthenticationError):
            shamir.combine([shares[0], bad, shares[2]])

    def test_forged_share_reusing_a_genuine_index(self, shares):
        forged = tamper(shares[0], value=os.urandom(len(shares[0].value)))
        recovery = shamir.combine([forged, *shares[:3]])
        assert recovery.secret == SECRET
        assert [r.share for r in recovery.rejected] == [forged]

    def test_altered_mac_is_detected(self, shares):
        forged = tamper(shares[4], mac=bytes(shamir.MAC_BYTES))
        recovery = shamir.combine([*shares[:3], forged])
        assert [r.share for r in recovery.rejected] == [forged]

    def test_mac_is_not_keyed_with_the_secret(self, shares):
        """A single share must not let anyone test guesses of the secret offline."""
        assert not shares[0].verify(SECRET)

    def test_mismatched_threshold_is_set_aside(self, shares):
        odd = tamper(shares[3], threshold=2)
        recovery = shamir.combine([*shares[:3], odd])
        assert recovery.secret == SECRET
        assert recovery.rejected[0].reason.startswith("threshold differs")


class TestMixedSplits:
    def test_shares_from_another_split_are_set_aside(self, shares):
        stranger = shamir.split(os.urandom(32), 3, 5)[0]
        recovery = shamir.combine([*shares[:3], stranger])
        assert recovery.secret == SECRET
        assert recovery.rejected[0].share == stranger
        assert "different split" in recovery.rejected[0].reason

    def test_no_majority_between_two_splits(self, shares):
        others = shamir.split(os.urandom(32), 3, 5)
        with pytest.raises(InconsistentSharesError, match="no majority"):
            shamir.combine([*shares[:2], *others[:2]])

    def test_rejections_are_reported_on_failure(self, shares):
        stranger = shamir.split(os.urandom(32), 3, 5)[0]
        with pytest.raises(InsufficientSharesError) as exc:
            shamir.combine([*shares[:2], stranger])
        assert exc.value.rejected[0].share == stranger

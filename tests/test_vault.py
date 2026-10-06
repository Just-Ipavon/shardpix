"""Tests for sealing and unsealing vaults."""

from __future__ import annotations

import itertools
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from shardpix import shamir, stego, vault
from shardpix.errors import VaultError
from shardpix.images import load_image, save_png
from shardpix.vault import Status

from .conftest import processed_image

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def covers(tmp_path: Path) -> list[Path]:
    paths = []
    for i in range(5):
        path = tmp_path / "covers" / f"photo{i}.png"
        path.parent.mkdir(exist_ok=True)
        Image.fromarray(processed_image(64, 80, seed=i)).save(path)
        paths.append(path)
    return paths


@pytest.fixture
def secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "minutes.pdf"
    path.write_bytes(np.random.default_rng(0).bytes(50_000))
    return path


@pytest.fixture
def sealed(tmp_path, covers, secret_file) -> vault.SealResult:
    return vault.seal(secret_file, covers, 3, tmp_path / "out", PASSPHRASE)


def images_of(result: vault.SealResult) -> list[Path]:
    return [image.output for image in result.images]


class TestRoundTrip:
    def test_every_threshold_subset_opens_the_vault(self, sealed, secret_file):
        for subset in itertools.combinations(images_of(sealed), 3):
            result = vault.unseal(sealed.vault_path, subset, PASSPHRASE)
            assert result.data == secret_file.read_bytes()
            assert result.filename == "minutes.pdf"

    def test_extra_images_are_verified(self, sealed):
        result = vault.unseal(sealed.vault_path, images_of(sealed), PASSPHRASE)
        statuses = [o.status for o in result.outcomes]
        assert statuses.count(Status.USED) == 3
        assert statuses.count(Status.VERIFIED) == 2

    def test_outputs(self, sealed, tmp_path):
        assert sealed.vault_path == tmp_path / "out" / "minutes.pdf.spx"
        assert [i.output.name for i in sealed.images] == [f"photo{i}.png" for i in range(5)]
        assert [i.share_index for i in sealed.images] == [1, 2, 3, 4, 5]
        assert sealed.header.threshold == 3 and sealed.header.shares == 5

    def test_vault_file_size(self, sealed, secret_file):
        expected = vault.HEADER_BYTES + 2 + len("minutes.pdf") + secret_file.stat().st_size + 16
        assert sealed.vault_path.stat().st_size == expected

    def test_without_a_passphrase(self, tmp_path, covers, secret_file):
        result = vault.seal(secret_file, covers[:2], 2, tmp_path / "plain")
        opened = vault.unseal(result.vault_path, images_of(result))
        assert opened.data == secret_file.read_bytes()

    def test_jpeg_covers_become_png(self, tmp_path, secret_file):
        jpegs = []
        for i in range(2):
            path = tmp_path / f"cover{i}.jpg"
            Image.fromarray(processed_image(64, 80, seed=10 + i)).save(path, quality=90)
            jpegs.append(path)
        result = vault.seal(secret_file, jpegs, 2, tmp_path / "out")
        assert all(image.output.suffix == ".png" for image in result.images)
        assert vault.unseal(result.vault_path, images_of(result)).data == secret_file.read_bytes()

    def test_embedding_is_tiny(self, sealed):
        for image in sealed.images:
            assert image.report.bits_written == 8 * vault.PAYLOAD_FRAME_BYTES
            assert image.report.embedding_rate < 0.1


class TestFailures:
    def test_too_few_images(self, sealed):
        with pytest.raises(VaultError, match="need 3") as exc:
            vault.unseal(sealed.vault_path, images_of(sealed)[:2], PASSPHRASE)
        assert [o.status for o in exc.value.outcomes] == [Status.UNVERIFIED] * 2

    def test_wrong_passphrase(self, sealed):
        with pytest.raises(VaultError) as exc:
            vault.unseal(sealed.vault_path, images_of(sealed), "wrong")
        assert {o.status for o in exc.value.outcomes} == {Status.NO_PAYLOAD}

    def test_clean_cover_is_reported(self, sealed, covers):
        images = [*images_of(sealed)[:3], covers[4]]
        result = vault.unseal(sealed.vault_path, images, PASSPHRASE)
        assert result.outcomes[-1].status == Status.NO_PAYLOAD

    def test_image_from_another_vault(self, sealed, tmp_path, covers, secret_file):
        other = vault.seal(secret_file, covers, 2, tmp_path / "other", PASSPHRASE)
        images = [*images_of(sealed)[:3], other.images[0].output]
        result = vault.unseal(sealed.vault_path, images, PASSPHRASE)
        assert result.outcomes[-1].status == Status.OTHER_VAULT

    def test_copy_of_an_image_counts_once(self, sealed, tmp_path):
        first = images_of(sealed)[0]
        copy = tmp_path / "copy.png"
        copy.write_bytes(first.read_bytes())
        with pytest.raises(VaultError, match="need 3"):
            vault.unseal(sealed.vault_path, [first, copy, images_of(sealed)[1]], PASSPHRASE)
        images = [first, copy, *images_of(sealed)[1:3]]
        result = vault.unseal(sealed.vault_path, images, PASSPHRASE)
        assert result.outcomes[1].status == Status.DUPLICATE

    def test_same_path_given_twice_is_listed_once(self, sealed):
        first = images_of(sealed)[0]
        images = [first, *images_of(sealed)[1:3], first]
        assert len(vault.unseal(sealed.vault_path, images, PASSPHRASE).outcomes) == 3

    def test_forged_share_is_identified(self, sealed, tmp_path):
        """A share re-embedded with the right passphrase but a wrong value is caught by its MAC."""
        target = sealed.images[1].output
        carrier = load_image(target)
        share = shamir.Share.from_bytes(stego.extract(carrier, PASSPHRASE))
        forged = shamir.Share(
            group_id=share.group_id,
            threshold=share.threshold,
            index=share.index,
            secret_length=share.secret_length,
            value=bytes(len(share.value)),
            mac=share.mac,
        )
        forged_image = tmp_path / "forged.png"
        save_png(
            stego.embed(load_image(sealed.images[1].cover), forged.to_bytes(), PASSPHRASE)[0],
            forged_image,
        )
        images = [images_of(sealed)[0], forged_image, *images_of(sealed)[2:]]
        result = vault.unseal(sealed.vault_path, images, PASSPHRASE)
        rejected = [o for o in result.outcomes if o.status == Status.REJECTED]
        assert [o.path for o in rejected] == [forged_image]
        assert "failed authentication" in rejected[0].detail

    def test_tampered_vault_file(self, sealed):
        data = bytearray(sealed.vault_path.read_bytes())
        data[-1] ^= 1
        sealed.vault_path.write_bytes(bytes(data))
        with pytest.raises(VaultError, match="no set of shares opens the vault"):
            vault.unseal(sealed.vault_path, images_of(sealed), PASSPHRASE)

    def test_tampered_header_is_detected(self, sealed):
        data = bytearray(sealed.vault_path.read_bytes())
        data[len(vault.MAGIC) + 1 + 16] = 2  # threshold field
        sealed.vault_path.write_bytes(bytes(data))
        with pytest.raises(VaultError, match="no set of shares opens the vault"):
            vault.unseal(sealed.vault_path, images_of(sealed), PASSPHRASE)

    def test_not_a_vault(self, tmp_path, sealed):
        bogus = tmp_path / "bogus.spx"
        bogus.write_bytes(b"hello world" * 10)
        with pytest.raises(VaultError, match="not a shardpix vault"):
            vault.unseal(bogus, images_of(sealed), PASSPHRASE)

    def test_unreadable_image(self, sealed, tmp_path):
        junk = tmp_path / "junk.png"
        junk.write_text("not an image")
        result = vault.unseal(sealed.vault_path, [junk, *images_of(sealed)[:3]], PASSPHRASE)
        assert result.outcomes[0].status == Status.UNREADABLE


class TestSealValidation:
    def test_needs_two_covers(self, tmp_path, covers, secret_file):
        with pytest.raises(VaultError, match="at least 2"):
            vault.seal(secret_file, covers[:1], 2, tmp_path / "out")

    @pytest.mark.parametrize("threshold", [1, 6])
    def test_threshold_range(self, tmp_path, covers, secret_file, threshold):
        with pytest.raises(VaultError, match="threshold"):
            vault.seal(secret_file, covers, threshold, tmp_path / "out")

    def test_covers_must_be_distinct(self, tmp_path, covers, secret_file):
        with pytest.raises(VaultError, match="different file"):
            vault.seal(secret_file, [covers[0], covers[0]], 2, tmp_path / "out")

    def test_cover_names_must_not_collide(self, tmp_path, covers, secret_file):
        twin = tmp_path / "elsewhere" / covers[0].name
        twin.parent.mkdir()
        twin.write_bytes(covers[1].read_bytes())
        with pytest.raises(VaultError, match="same name"):
            vault.seal(secret_file, [covers[0], twin], 2, tmp_path / "out")

    def test_never_overwrites_a_cover(self, covers, secret_file):
        with pytest.raises(VaultError, match="overwrite one of the inputs"):
            vault.seal(secret_file, covers, 2, covers[0].parent, force=True)

    def test_refuses_existing_outputs_without_force(self, tmp_path, covers, secret_file):
        vault.seal(secret_file, covers, 2, tmp_path / "out")
        with pytest.raises(VaultError, match="already exists"):
            vault.seal(secret_file, covers, 2, tmp_path / "out")
        vault.seal(secret_file, covers, 2, tmp_path / "out", force=True)

    def test_small_cover_is_rejected_before_anything_is_written(
        self, tmp_path, covers, secret_file
    ):
        tiny = tmp_path / "tiny.png"
        Image.fromarray(processed_image(8, 8)).save(tiny)
        out = tmp_path / "out"
        with pytest.raises(VaultError, match="too small"):
            vault.seal(secret_file, [covers[0], tiny], 2, out)
        assert not out.exists()

    def test_missing_source(self, tmp_path, covers):
        with pytest.raises(VaultError, match="cannot read"):
            vault.seal(tmp_path / "missing.txt", covers, 2, tmp_path / "out")

    def test_custom_vault_name(self, tmp_path, covers, secret_file):
        result = vault.seal(secret_file, covers[:2], 2, tmp_path / "out", vault_name="blob.bin")
        assert result.vault_path.name == "blob.bin"


class TestSafeFilename:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("report.pdf", "report.pdf"),
            ("../../etc/passwd", "passwd"),
            ("/absolute/path.txt", "path.txt"),
            ("..\\..\\windows\\system.ini", "system.ini"),
            ("..", vault.FALLBACK_NAME),
            ("", vault.FALLBACK_NAME),
        ],
    )
    def test_strips_directories(self, name, expected):
        assert vault.safe_filename(name) == expected


def embed_share(cover: Path, share: shamir.Share, out: Path) -> Path:
    save_png(stego.embed(load_image(cover), share.to_bytes(), PASSPHRASE)[0], out)
    return out


class TestForgedSets:
    """Someone who knows the (public) group id fabricates mutually consistent shares."""

    def forged_images(self, sealed, tmp_path, count):
        fake = shamir.split(
            np.random.default_rng(9).bytes(vault.KEY_BYTES),
            3,
            count,
            group_id=sealed.header.group_id,
        )
        return [
            embed_share(sealed.images[i].cover, fake[i], tmp_path / f"forged{i}.png")
            for i in range(count)
        ]

    def test_smaller_forged_set_is_ignored(self, sealed, tmp_path, secret_file):
        forged = self.forged_images(sealed, tmp_path, 3)
        result = vault.unseal(sealed.vault_path, [*forged, *images_of(sealed)], PASSPHRASE)
        assert result.data == secret_file.read_bytes()
        statuses = {o.path: o.status for o in result.outcomes}
        assert all(statuses[p] == Status.REJECTED for p in forged)

    def test_larger_forged_set_is_beaten_by_the_vault_tag(self, sealed, tmp_path, secret_file):
        forged = self.forged_images(sealed, tmp_path, 4)
        result = vault.unseal(sealed.vault_path, [*forged, *images_of(sealed)[:3]], PASSPHRASE)
        assert result.data == secret_file.read_bytes()

    def test_only_forged_shares(self, sealed, tmp_path):
        forged = self.forged_images(sealed, tmp_path, 3)
        with pytest.raises(VaultError, match="no set of shares opens the vault") as exc:
            vault.unseal(sealed.vault_path, forged, PASSPHRASE)
        assert {o.status for o in exc.value.outcomes} == {Status.REJECTED}


class TestOutputCollisions:
    def test_vault_name_equal_to_an_image_name(self, tmp_path, covers, secret_file):
        with pytest.raises(VaultError, match="collide"):
            vault.seal(secret_file, covers, 2, tmp_path / "out", vault_name="photo0.png")

    def test_cover_names_differing_only_in_case(self, tmp_path, covers, secret_file):
        upper = tmp_path / "upper" / "PHOTO0.jpg"
        upper.parent.mkdir()
        Image.fromarray(processed_image(64, 80, seed=40)).save(upper)
        with pytest.raises(VaultError, match="collide"):
            vault.seal(secret_file, [covers[0], upper], 2, tmp_path / "out")

    def test_output_directory_is_a_file(self, tmp_path, covers, secret_file):
        not_a_dir = tmp_path / "file"
        not_a_dir.write_text("x")
        with pytest.raises(VaultError, match="not a directory"):
            vault.seal(secret_file, covers, 2, not_a_dir)


class TestRestoredNames:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("evil\x1b]0;pwned\x07.txt", "evil]0;pwned.txt"),
            ("nul\x00byte.txt", "nulbyte.txt"),
            ("rtl‮exe.txt", "rtlexe.txt"),
            ("CON", vault.FALLBACK_NAME),
            ("lpt1.txt", vault.FALLBACK_NAME),
            ("trailing. ", "trailing"),
        ],
    )
    def test_control_characters_and_reserved_names(self, name, expected):
        assert vault.safe_filename(name) == expected

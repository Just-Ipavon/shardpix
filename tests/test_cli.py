"""Tests for the command line interface."""

from __future__ import annotations

import argparse

import numpy as np
import pytest
from PIL import Image

from shardpix import cli, stego
from shardpix.images import load_image


def run(*argv: str) -> int:
    return cli.main([str(a) for a in argv])


class TestEmbedExtract:
    def test_text_round_trip_through_stdout(
        self, cover_png, passphrase_file, tmp_path, capsysbinary
    ):
        out = tmp_path / "stego.png"
        assert (
            run("embed", cover_png, "-o", out, "-t", "ciao", "--passphrase-file", passphrase_file)
            == 0
        )
        capsysbinary.readouterr()
        assert run("extract", out, "--passphrase-file", passphrase_file) == 0
        assert capsysbinary.readouterr().out == b"ciao"

    def test_file_round_trip(self, cover_png, passphrase_file, tmp_path):
        secret = tmp_path / "secret.bin"
        secret.write_bytes(bytes(range(256)) * 4)
        out = tmp_path / "stego.png"
        recovered = tmp_path / "recovered.bin"
        assert (
            run("embed", cover_png, "-o", out, "-i", secret, "--passphrase-file", passphrase_file)
            == 0
        )
        assert run("extract", out, "-o", recovered, "--passphrase-file", passphrase_file) == 0
        assert recovered.read_bytes() == secret.read_bytes()

    def test_warns_when_no_passphrase_is_used(self, cover_png, tmp_path, capsys):
        assert run("embed", cover_png, "-o", tmp_path / "s.png", "-t", "x") == 0
        assert "no passphrase" in capsys.readouterr().out

    def test_wrong_passphrase_exits_with_an_error(
        self, cover_png, passphrase_file, tmp_path, capsys
    ):
        out = tmp_path / "stego.png"
        run("embed", cover_png, "-o", out, "-t", "x", "--passphrase-file", passphrase_file)
        wrong = tmp_path / "wrong.txt"
        wrong.write_text("nope")
        assert run("extract", out, "--passphrase-file", wrong) == 1
        assert "no shardpix payload found" in capsys.readouterr().err

    def test_refuses_lossy_output(self, cover_png, tmp_path, capsys):
        assert run("embed", cover_png, "-o", tmp_path / "s.jpg", "-t", "x") == 1
        assert "must be a .png" in capsys.readouterr().err

    def test_refuses_to_overwrite_without_force(self, cover_png, tmp_path):
        out = tmp_path / "s.png"
        assert run("embed", cover_png, "-o", out, "-t", "x") == 0
        assert run("embed", cover_png, "-o", out, "-t", "x") == 1
        assert run("embed", cover_png, "-o", out, "-t", "x", "--force") == 0

    def test_refuses_to_overwrite_the_cover(self, cover_png, capsys):
        assert run("embed", cover_png, "-o", cover_png, "-t", "x", "--force") == 1
        assert "also an input" in capsys.readouterr().err

    def test_payload_too_large(self, cover_png, tmp_path, capsys):
        big = tmp_path / "big.bin"
        big.write_bytes(bytes(1_000_000))
        assert run("embed", cover_png, "-o", tmp_path / "s.png", "-i", big) == 1
        assert "at most" in capsys.readouterr().err


class TestPassphrase:
    def test_prompt_is_confirmed_when_embedding(self, monkeypatch):
        answers = iter(["first", "second"])
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(answers))
        args = argparse.Namespace(passphrase=True, passphrase_file=None)
        with pytest.raises(cli.ShardpixError, match="do not match"):
            cli.read_passphrase(args, confirm=True)

    def test_prompt_is_not_confirmed_when_extracting(self, monkeypatch):
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "only once")
        args = argparse.Namespace(passphrase=True, passphrase_file=None)
        assert cli.read_passphrase(args, confirm=False) == "only once"

    def test_empty_passphrase_file_is_rejected(self, tmp_path):
        empty = tmp_path / "empty.txt"
        empty.write_text("")
        args = argparse.Namespace(passphrase=False, passphrase_file=empty)
        with pytest.raises(cli.ShardpixError, match="empty"):
            cli.read_passphrase(args, confirm=False)

    def test_only_the_first_line_is_used(self, tmp_path):
        path = tmp_path / "p.txt"
        path.write_text("line one\nline two\n")
        args = argparse.Namespace(passphrase=False, passphrase_file=path)
        assert cli.read_passphrase(args, confirm=False) == "line one"

    def test_no_option_means_no_passphrase(self):
        args = argparse.Namespace(passphrase=False, passphrase_file=None)
        assert cli.read_passphrase(args, confirm=False) is None


class TestOtherCommands:
    def test_capacity(self, cover_png, capsys):
        assert run("capacity", cover_png) == 0
        out = capsys.readouterr().out
        assert "128 x 96" in out
        assert "Capacity" in out

    def test_analyze_clean_image(self, cover_png, capsys):
        assert run("analyze", cover_png, "--steps", "20") == 0
        assert "No LSB replacement detected" in capsys.readouterr().out

    def test_analyze_flags_lsb_replacement(self, cover_png, tmp_path, capsys):
        carrier = load_image(cover_png)
        samples = carrier.samples()
        bits = np.random.default_rng(0).integers(0, 2, samples.size).astype(np.uint8)
        replaced, _ = stego.write_bits(
            samples,
            np.arange(samples.size // 2),
            bits[: samples.size // 2],
            stego.Method.REPLACEMENT,
        )
        path = tmp_path / "suspicious.png"
        Image.fromarray(carrier.with_samples(replaced).pixels).save(path)
        assert run("analyze", path, "--steps", "20") == 0
        out = capsys.readouterr().out
        assert "Suspicious" in out
        assert "RS suggests" in out

    def test_missing_image(self, tmp_path, capsys):
        assert run("capacity", tmp_path / "missing.png") == 1
        assert "no such file" in capsys.readouterr().err

    def test_rejects_non_positive_steps(self, cover_png):
        with pytest.raises(SystemExit):
            run("analyze", cover_png, "--steps", "0")

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            run("--version")
        assert exc.value.code == 0
        assert "shardpix" in capsys.readouterr().out


class TestFormatBytes:
    @pytest.mark.parametrize(
        "size,expected",
        [(0, "0 B"), (1023, "1023 B"), (1536, "1.5 KiB"), (5 * 1024 * 1024, "5.0 MiB")],
    )
    def test_formats(self, size, expected):
        assert cli.format_bytes(size) == expected


class TestSplitCombine:
    def test_round_trip_through_stdout(self, tmp_path, capsysbinary):
        assert run("split", "-t", "the vault code is 4-8-15", "-k", "2", "-n", "3") == 0
        lines = capsysbinary.readouterr().out.decode().splitlines()
        assert len(lines) == 3 and all(line.startswith("spx1-") for line in lines)
        shares = tmp_path / "shares.txt"
        shares.write_text("\n".join(lines[1:]) + "\n")
        assert run("combine", shares) == 0
        assert capsysbinary.readouterr().out == b"the vault code is 4-8-15"

    def test_round_trip_through_files(self, tmp_path):
        secret = tmp_path / "key.bin"
        secret.write_bytes(bytes(range(64)))
        directory = tmp_path / "shares"
        assert run("split", "-i", secret, "-k", "3", "-n", "5", "-d", directory) == 0
        files = sorted(directory.iterdir())
        assert len(files) == 5
        recovered = tmp_path / "recovered.bin"
        assert run("combine", files[0], files[2], files[4], "-o", recovered) == 0
        assert recovered.read_bytes() == secret.read_bytes()

    def test_malformed_lines_are_skipped_not_fatal(self, tmp_path, capsys):
        assert run("split", "-t", "secret", "-k", "2", "-n", "3") == 0
        lines = capsys.readouterr().out.splitlines()
        shares = tmp_path / "shares.txt"
        shares.write_text("# my shares\n\nspx1-garbage\n" + "\n".join(lines) + "\n")
        out = tmp_path / "out.bin"
        assert run("combine", shares, "-o", out) == 0
        assert out.read_bytes() == b"secret"
        assert "skipped" in capsys.readouterr().out

    def test_not_enough_shares(self, tmp_path, capsys):
        assert run("split", "-t", "secret", "-k", "3", "-n", "3") == 0
        lines = capsys.readouterr().out.splitlines()
        shares = tmp_path / "shares.txt"
        shares.write_text(lines[0] + "\n")
        assert run("combine", shares) == 1
        assert "need 3 shares" in capsys.readouterr().err

    def test_threshold_larger_than_shares(self, capsys):
        assert run("split", "-t", "secret", "-k", "4", "-n", "3") == 1
        assert "threshold" in capsys.readouterr().err

    def test_secret_too_large_points_to_seal(self, tmp_path, capsys):
        big = tmp_path / "big.bin"
        big.write_bytes(bytes(70_000))
        assert run("split", "-i", big, "-k", "2", "-n", "3") == 1
        assert "seal" in capsys.readouterr().err

    def test_split_refuses_to_overwrite_share_files(self, tmp_path, monkeypatch):
        directory = tmp_path / "shares"
        directory.mkdir()
        group = "deadbeef"
        (directory / f"share-{group}-1.txt").write_text("existing")
        monkeypatch.setattr(
            "shardpix.shamir.Share.group", property(lambda self: group), raising=True
        )
        assert run("split", "-t", "x", "-k", "2", "-n", "2", "-d", directory) == 1
        assert (directory / f"share-{group}-1.txt").read_text() == "existing"


class TestVaultCommands:
    @pytest.fixture
    def covers(self, tmp_path):
        from .conftest import processed_image

        paths = []
        for i in range(4):
            path = tmp_path / f"photo{i}.png"
            Image.fromarray(processed_image(64, 80, seed=20 + i)).save(path)
            paths.append(path)
        return paths

    def test_seal_and_unseal(self, tmp_path, covers, passphrase_file, capsys, monkeypatch):
        secret = tmp_path / "notes.txt"
        secret.write_text("the treasure is under the oak")
        out = tmp_path / "sealed"
        assert (
            run("seal", secret, *covers, "-k", "3", "-d", out, "--passphrase-file", passphrase_file)
            == 0
        )
        assert "any 3 of these 4 images" in capsys.readouterr().out

        monkeypatch.chdir(tmp_path)
        (tmp_path / "notes.txt").unlink()
        images = [out / f"photo{i}.png" for i in (0, 2, 3)]
        assert (
            run("unseal", out / "notes.txt.spx", *images, "--passphrase-file", passphrase_file) == 0
        )
        assert (tmp_path / "notes.txt").read_text() == "the treasure is under the oak"
        assert "Recovered notes.txt" in capsys.readouterr().out

    def test_unseal_failure_reports_each_image(self, tmp_path, covers, passphrase_file, capsys):
        secret = tmp_path / "s.txt"
        secret.write_text("x")
        out = tmp_path / "sealed"
        run("seal", secret, *covers, "-k", "3", "-d", out, "--passphrase-file", passphrase_file)
        capsys.readouterr()
        images = [out / "photo0.png", covers[1]]
        result = run(
            "unseal",
            out / "s.txt.spx",
            *images,
            "--passphrase-file",
            passphrase_file,
            "-o",
            tmp_path / "r.txt",
        )
        assert result == 1
        err = capsys.readouterr().err
        assert "no payload" in err
        assert "need 3 shares" in err

    def test_inspect_shows_the_share(self, tmp_path, covers, capsys):
        secret = tmp_path / "s.txt"
        secret.write_text("x")
        run("seal", secret, *covers[:2], "-k", "2", "-d", tmp_path / "sealed")
        capsys.readouterr()
        assert run("inspect", tmp_path / "sealed" / "photo1.png") == 0
        out = capsys.readouterr().out
        assert "shardpix share" in out
        assert "#2" in out

    def test_inspect_plain_payload(self, cover_png, tmp_path, capsys):
        stego_path = tmp_path / "s.png"
        run("embed", cover_png, "-o", stego_path, "-t", "hello")
        capsys.readouterr()
        assert run("inspect", stego_path) == 0
        assert "not a share" in capsys.readouterr().out

    def test_seal_rejects_bad_threshold(self, tmp_path, covers, capsys):
        secret = tmp_path / "s.txt"
        secret.write_text("x")
        assert run("seal", secret, *covers, "-k", "9", "-d", tmp_path / "o") == 1
        assert "threshold" in capsys.readouterr().err


class TestCleanErrors:
    """Every expected failure ends with a one-line error and exit code 1, never a traceback."""

    def test_output_in_a_missing_directory(self, cover_png, tmp_path, capsys):
        assert run("embed", cover_png, "-o", tmp_path / "missing" / "s.png", "-t", "x") == 1
        assert "error:" in capsys.readouterr().err

    def test_output_is_a_directory(self, cover_png, tmp_path, capsys):
        assert run("extract", cover_png, "-o", tmp_path) == 1
        assert "is a directory" in capsys.readouterr().err

    def test_too_many_shares(self, capsys):
        assert run("split", "-t", "x", "-k", "2", "-n", "300") == 1
        assert "at most 255" in capsys.readouterr().err

    def test_passphrase_file_not_utf8(self, cover_png, tmp_path, capsys):
        bad = tmp_path / "bad.txt"
        bad.write_bytes(b"\xff\xfe\xfa")
        assert (
            run("embed", cover_png, "-o", tmp_path / "s.png", "-t", "x", "--passphrase-file", bad)
            == 1
        )
        assert "not valid UTF-8" in capsys.readouterr().err

    def test_passphrase_file_with_bom(self, tmp_path):
        path = tmp_path / "bom.txt"
        path.write_bytes(b"\xef\xbb\xbfsecret\n")
        args = argparse.Namespace(passphrase=False, passphrase_file=path)
        assert cli.read_passphrase(args, confirm=False) == "secret"

    def test_analyze_tiny_image(self, tmp_path, capsys):
        path = tmp_path / "tiny.png"
        Image.fromarray(np.full((10, 3, 3), 100, np.uint8)).save(path)
        assert run("analyze", path) == 0
        assert "not applicable" in capsys.readouterr().out

    def test_decompression_bomb(self, cover_png, monkeypatch, capsys):
        monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 100)
        assert run("capacity", cover_png) == 1
        assert "too large" in capsys.readouterr().err

    def test_combine_never_overwrites_its_input(self, tmp_path, capsys):
        assert run("split", "-t", "x", "-k", "2", "-n", "2") == 0
        shares = tmp_path / "all.txt"
        shares.write_text(capsys.readouterr().out)
        assert run("combine", shares, "-o", shares, "--force") == 1
        assert shares.read_text().startswith("spx1-")

    def test_split_into_a_file_path(self, tmp_path, capsys):
        file = tmp_path / "file"
        file.write_text("x")
        assert run("split", "-t", "x", "-k", "2", "-n", "2", "-d", file) == 1
        assert "error:" in capsys.readouterr().err

    def test_jpeg_cover_warning(self, tmp_path, capsys):
        from .conftest import processed_image

        jpeg = tmp_path / "photo.jpg"
        Image.fromarray(processed_image()).save(jpeg, quality=90)
        assert run("embed", jpeg, "-o", tmp_path / "s.png", "-t", "x") == 0
        assert "JPEG-compatibility" in capsys.readouterr().out

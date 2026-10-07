"""Tests for the command line interface."""

from __future__ import annotations

import argparse
import sys

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
        assert "gives a .png file" in capsys.readouterr().err

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

    def test_jpeg_cover_gives_a_jpeg(self, tmp_path, capsys):
        from .conftest import phone_jpeg

        photo = phone_jpeg(tmp_path / "photo.jpg")
        assert run("embed", photo, "-o", tmp_path / "s.png", "-t", "x") == 1
        assert "gives a .jpg file" in capsys.readouterr().err
        assert run("embed", photo, "-o", tmp_path / "s.jpg", "-t", "hello") == 0
        out = capsys.readouterr().out
        assert "JPEG (format 5)" in out and "JPEG-compatibility" not in out
        assert run("extract", tmp_path / "s.jpg") == 0
        assert capsys.readouterr().out.endswith("hello")


class TestOutputSafety:
    def test_dangling_symlink_is_never_followed(self, cover_png, tmp_path, capsys):
        """A link planted where the output goes must not redirect the write."""
        target = tmp_path / "elsewhere.txt"
        link = tmp_path / "out.bin"
        link.symlink_to(target)
        stego_path = tmp_path / "s.png"
        run("embed", cover_png, "-o", stego_path, "-t", "secret")
        assert run("extract", stego_path, "-o", link) == 1
        assert not target.exists()
        assert "already exists" in capsys.readouterr().err

    def test_method_is_not_a_user_option(self, cover_png, tmp_path):
        """Formats other than adaptive exist for the benchmarks, not for users."""
        with pytest.raises(SystemExit):
            run("embed", cover_png, "-o", tmp_path / "s.png", "-t", "x", "-m", "replacement")


class TestHelp:
    @pytest.mark.parametrize(
        "command",
        [
            "capacity",
            "embed",
            "extract",
            "seal",
            "unseal",
            "inspect",
            "analyze",
            "split",
            "combine",
        ],
    )
    def test_every_command_explains_itself_with_examples(self, command, capsys):
        with pytest.raises(SystemExit) as exit_info:
            cli.main([command, "-h"])
        assert exit_info.value.code == 0
        out = capsys.readouterr().out
        assert "examples:" in out
        assert f"shardpix {command}" in out

    def test_options_are_explained(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["seal", "-h"])
        out = " ".join(capsys.readouterr().out.split())
        assert "how many images are needed to open the vault" in out
        assert "anyone running shardpix can read the payload" in out

    def test_overview_lists_a_quick_start(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["-h"])
        out = capsys.readouterr().out
        assert "quick start:" in out
        assert "shardpix seal" in out
        assert "options used by several commands:" in out


class TestBinaryOnTheTerminal:
    def _embed_png_payload(self, cover_png, passphrase_file, tmp_path):
        payload = tmp_path / "inner.png"
        Image.fromarray(np.zeros((8, 8, 3), dtype=np.uint8)).save(payload)
        out = tmp_path / "stego.png"
        args = ("embed", cover_png, "-o", out, "-i", payload, "--passphrase-file", passphrase_file)
        assert run(*args) == 0
        return out, payload

    def test_a_file_is_not_printed_on_a_terminal(
        self, cover_png, passphrase_file, tmp_path, capsysbinary, monkeypatch
    ):
        out, _ = self._embed_png_payload(cover_png, passphrase_file, tmp_path)
        capsysbinary.readouterr()
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert run("extract", out, "--passphrase-file", passphrase_file) == 1
        captured = capsysbinary.readouterr()
        assert captured.out == b""
        message = b" ".join(captured.err.split())
        assert b"a PNG image" in message
        assert b"-o FILE.png" in message

    def test_a_file_still_goes_through_a_pipe(
        self, cover_png, passphrase_file, tmp_path, capsysbinary
    ):
        out, payload = self._embed_png_payload(cover_png, passphrase_file, tmp_path)
        capsysbinary.readouterr()
        assert run("extract", out, "--passphrase-file", passphrase_file) == 0
        assert capsysbinary.readouterr().out == payload.read_bytes()

    def test_text_is_printed_on_a_terminal(
        self, cover_png, passphrase_file, tmp_path, capsysbinary, monkeypatch
    ):
        out = tmp_path / "stego.png"
        args = ("embed", cover_png, "-o", out, "-t", "ciao\n", "--passphrase-file", passphrase_file)
        assert run(*args) == 0
        capsysbinary.readouterr()
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert run("extract", out, "--passphrase-file", passphrase_file) == 0
        assert capsysbinary.readouterr().out == b"ciao\n"


class TestProgress:
    @pytest.mark.parametrize("kind", ["png", "jpeg"])
    def test_progress_moves_forward_to_the_end(self, kind, tmp_path):
        from shardpix import media

        from .conftest import natural_image, phone_jpeg

        if kind == "jpeg":
            path = phone_jpeg(tmp_path / "photo.jpg")
        else:
            path = tmp_path / "photo.png"
            Image.fromarray(natural_image()).save(path)
        steps: list[tuple[float, str]] = []
        media.hide(
            media.open_cover(path),
            b"x" * 100,
            "pw",
            progress=lambda f, label: steps.append((f, label)),
        )
        fractions = [f for f, _ in steps]
        assert fractions == sorted(fractions)
        assert fractions[0] == 0.0
        assert fractions[-1] >= 0.6
        labels = {label for _, label in steps}
        assert "deriving the key" in labels
        assert "choosing the changes" in labels

    def test_seal_reports_every_image(self, tmp_path):
        from shardpix import vault

        from .conftest import natural_image

        covers = []
        for i in range(3):
            path = tmp_path / f"c{i}.png"
            Image.fromarray(natural_image(seed=i + 1)).save(path)
            covers.append(path)
        secret = tmp_path / "secret.txt"
        secret.write_text("hello")
        steps: list[tuple[float, str]] = []
        vault.seal(
            secret, covers, 2, tmp_path / "out", progress=lambda f, label: steps.append((f, label))
        )
        fractions = [f for f, _ in steps]
        assert fractions == sorted(fractions)
        assert fractions[-1] > 0.9
        for cover in covers:
            assert any(label.startswith(f"{cover.name}: ") for _, label in steps)


class TestWildcards:
    """PowerShell and cmd.exe pass '*.png' to the program unexpanded."""

    def test_patterns_are_expanded_in_sorted_order(self, tmp_path):
        for name in ("b.png", "a.png", "c.jpg"):
            (tmp_path / name).write_bytes(b"x")
        found = cli.expand_wildcards([tmp_path / "*.png", tmp_path / "c.jpg"])
        assert found == [tmp_path / "a.png", tmp_path / "b.png", tmp_path / "c.jpg"]

    def test_an_existing_file_with_a_bracket_is_kept(self, tmp_path):
        odd = tmp_path / "photo[1].png"
        odd.write_bytes(b"x")
        assert cli.expand_wildcards([odd]) == [odd]

    def test_a_pattern_matching_nothing_is_reported_as_missing(self, tmp_path):
        assert cli.expand_wildcards([tmp_path / "*.gif"]) == [tmp_path / "*.gif"]

    def test_seal_and_unseal_with_unexpanded_patterns(self, tmp_path, passphrase_file):
        from .conftest import natural_image

        covers = tmp_path / "covers"
        covers.mkdir()
        for i in range(3):
            Image.fromarray(natural_image(seed=i + 1)).save(covers / f"c{i}.png")
        secret = tmp_path / "secret.txt"
        secret.write_text("hello")
        out = tmp_path / "sealed"
        pattern = covers / "*.png"
        assert (
            run("seal", secret, pattern, "-k", "2", "-d", out, "--passphrase-file", passphrase_file)
            == 0
        )
        recovered = tmp_path / "back.txt"
        args = ("unseal", out / "secret.txt.spx", out / "*.png", "-o", recovered)
        assert run(*args, "--passphrase-file", passphrase_file) == 0
        assert recovered.read_text() == "hello"


class TestLowQualityJpeg:
    def _photo(self, tmp_path, quality, name="photo.jpg", seed=0):
        from .conftest import phone_jpeg

        return phone_jpeg(tmp_path / name, seed=seed, quality=quality)

    def test_embed_warns_on_a_recompressed_photo(self, tmp_path, capsys):
        photo = self._photo(tmp_path, 75)
        assert run("embed", photo, "-o", tmp_path / "out.jpg", "-t", "x") == 0
        out = " ".join(capsys.readouterr().out.split())
        assert "JPEG quality about 75" in out
        assert "original files" in out

    def test_embed_is_quiet_on_a_camera_photo(self, tmp_path, capsys):
        photo = self._photo(tmp_path, 95)
        assert run("embed", photo, "-o", tmp_path / "out.jpg", "-t", "x") == 0
        assert "JPEG quality" not in capsys.readouterr().out

    def test_seal_names_only_the_recompressed_photos(self, tmp_path, capsys):
        good = self._photo(tmp_path, 95, "good.jpg", seed=1)
        bad = self._photo(tmp_path, 70, "bad.jpg", seed=2)
        secret = tmp_path / "secret.txt"
        secret.write_text("hello")
        assert run("seal", secret, good, bad, "-k", "2", "-d", tmp_path / "out") == 0
        out = " ".join(capsys.readouterr().out.split())
        assert "bad.jpg has JPEG quality about 70" in out
        assert "good.jpg has" not in out

    def test_capacity_shows_the_quality(self, tmp_path, capsys):
        assert run("capacity", self._photo(tmp_path, 75)) == 0
        out = capsys.readouterr().out
        assert "JPEG quality" in out
        assert "about 75" in out


class TestAnalyzeJpeg:
    def test_a_clean_photo_is_not_flagged(self, tmp_path, capsys):
        from .conftest import phone_jpeg

        photo = phone_jpeg(tmp_path / "photo.jpg", 384, 512, quality=92)
        assert run("analyze", photo, "--steps", "20") == 0
        out = capsys.readouterr().out
        assert "quantised DCT" in out
        assert "No JSteg-like embedding detected" in out

    def test_jsteg_like_embedding_is_flagged(self, tmp_path, capsys):
        import jpeglib

        from .conftest import phone_jpeg

        photo = phone_jpeg(tmp_path / "photo.jpg", 384, 512, quality=92)
        image = jpeglib.read_dct(str(photo))
        image.load()
        y = image.Y.astype(np.int64)
        usable = (y != 0) & (y != 1)
        bits = np.random.default_rng(0).integers(0, 2, y.shape)
        y = np.where(usable, (y & ~1) | bits, y)
        image.Y = y.astype(image.Y.dtype)
        image.write_dct(str(tmp_path / "jsteg.jpg"))
        assert run("analyze", tmp_path / "jsteg.jpg", "--steps", "20") == 0
        assert "Suspicious" in capsys.readouterr().out

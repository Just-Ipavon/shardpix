"""Cover suitability (#33): one definition used by lint, seal and embed."""

from __future__ import annotations

import pytest
from PIL import Image

from shardpix import covers, vault

from .conftest import natural_image, phone_jpeg


def _codes(assessment, level=None):
    return {f.code for f in assessment.findings if level is None or f.level == level}


def test_a_camera_jpeg_is_suitable(tmp_path):
    a = covers.assess(phone_jpeg(tmp_path / "p.jpg", quality=95), vault.SHARE_BYTES)
    assert a.suitable and a.findings == ()


def test_recompressed_and_progressive_jpegs_are_unsuitable(tmp_path):
    low = covers.assess(phone_jpeg(tmp_path / "low.jpg", quality=70))
    assert _codes(low, covers.UNSUITABLE) == {"low_quality"}
    photo = phone_jpeg(tmp_path / "prog.jpg", quality=95)
    Image.open(photo).save(photo, quality=95, progressive=True)
    assert "progressive" in _codes(covers.assess(photo), covers.UNSUITABLE)


def test_restart_markers_are_unsuitable(tmp_path):
    photo = phone_jpeg(tmp_path / "rst.jpg", quality=95)
    try:
        Image.open(photo).save(photo, quality=95, restart_marker_blocks=4)
    except TypeError:
        pytest.skip("this Pillow cannot write restart markers")
    assert "restart_markers" in _codes(covers.assess(photo), covers.UNSUITABLE)


def test_data_after_the_image_is_only_a_note(tmp_path):
    photo = phone_jpeg(tmp_path / "mpo.jpg", quality=95)
    photo.write_bytes(photo.read_bytes() + b"trailer" * 50)
    a = covers.assess(photo)
    assert a.suitable and _codes(a, covers.NOTE) == {"extra_images"}


def test_palette_png_is_unsuitable(tmp_path):
    path = tmp_path / "pal.png"
    Image.fromarray(natural_image(64, 64)).convert("P").save(path)
    assert _codes(covers.assess(path), covers.UNSUITABLE) == {"palette"}


def test_unreadable_and_too_small_are_refused(tmp_path):
    junk = tmp_path / "junk.png"
    junk.write_text("not an image")
    assert _codes(covers.assess(junk), covers.REFUSED) == {"unreadable"}
    tiny = tmp_path / "tiny.png"
    Image.fromarray(natural_image(8, 8)).save(tiny)
    a = covers.assess(tiny, vault.SHARE_BYTES)
    assert a.refused and "too_small" in _codes(a)


def test_lint_command_reports_and_sets_the_exit_status(tmp_path, capsys):
    from shardpix import cli

    good = phone_jpeg(tmp_path / "good.jpg", quality=95)
    assert cli.main(["lint", str(good)]) == 0
    assert "1 of 1 images are suitable" in capsys.readouterr().out
    bad = phone_jpeg(tmp_path / "bad.jpg", quality=70)
    assert cli.main(["lint", str(good), str(bad)]) == 1
    out = " ".join(capsys.readouterr().out.split())
    assert "unsuitable" in out and "1 of 2 images" in out


def test_seal_refuses_an_unsuitable_cover_before_writing(tmp_path, capsys):
    from shardpix import cli

    secret = tmp_path / "s.txt"
    secret.write_text("x")
    good = phone_jpeg(tmp_path / "a.jpg", quality=95, seed=1)
    bad = phone_jpeg(tmp_path / "b.jpg", quality=70, seed=2)
    out = tmp_path / "out"
    argv = [
        "seal",
        str(secret),
        str(good),
        str(bad),
        "-k",
        "2",
        "-d",
        str(out),
        "--insecure-no-passphrase",
    ]
    assert cli.main(argv) == 1
    assert not out.exists()
    assert "b.jpg: unsuitable cover" in capsys.readouterr().err

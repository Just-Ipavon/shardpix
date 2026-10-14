"""Tests for carrier loading and saving."""

from __future__ import annotations

import os
import stat
import sys

import numpy as np
import pytest
from PIL import Image

from shardpix.errors import UnsupportedImageError
from shardpix.images import from_pil, load_image, save_png

from .conftest import natural_image, phone_jpeg


class TestLoad:
    def test_rgb_keeps_three_colour_channels(self, rgb_carrier):
        assert rgb_carrier.mode == "RGB"
        assert rgb_carrier.geometry == (96, 128, 3)
        assert rgb_carrier.n_samples == 96 * 128 * 3

    def test_greyscale_has_one_channel(self):
        carrier = from_pil(Image.fromarray(natural_image(channels=1)[..., 0]))
        assert carrier.mode == "L"
        assert carrier.geometry == (96, 128, 1)

    def test_alpha_is_not_a_carrier_channel(self):
        rgba = np.dstack([natural_image(), np.full((96, 128), 200, np.uint8)])
        carrier = from_pil(Image.fromarray(rgba))
        assert carrier.mode == "RGBA"
        assert carrier.colour_channels == 3
        assert carrier.samples().size == 96 * 128 * 3

    def test_palette_image_is_converted_to_rgb(self):
        image = Image.fromarray(natural_image()).convert("P")
        assert from_pil(image).mode == "RGB"

    def test_sixteen_bit_images_are_rejected(self):
        image = Image.fromarray(np.zeros((8, 8), dtype=np.uint16))
        with pytest.raises(UnsupportedImageError):
            from_pil(image)

    def test_missing_file_raises_a_clear_error(self, tmp_path):
        with pytest.raises(UnsupportedImageError, match="no such file"):
            load_image(tmp_path / "missing.png")

    def test_non_image_file_is_rejected(self, tmp_path):
        path = tmp_path / "notes.png"
        path.write_text("not an image")
        with pytest.raises(UnsupportedImageError, match="not a readable image"):
            load_image(path)


class TestSamples:
    def test_with_samples_round_trips(self, rgb_carrier):
        samples = rgb_carrier.samples()
        assert np.array_equal(rgb_carrier.with_samples(samples).pixels, rgb_carrier.pixels)

    def test_with_samples_leaves_alpha_untouched(self):
        alpha = np.arange(96 * 128, dtype=np.uint32).reshape(96, 128) % 256
        rgba = np.dstack([natural_image(), alpha.astype(np.uint8)])
        carrier = from_pil(Image.fromarray(rgba))
        changed = carrier.with_samples(255 - carrier.samples())
        assert np.array_equal(changed.pixels[..., 3], rgba[..., 3])

    def test_with_samples_rejects_the_wrong_size(self, rgb_carrier):
        with pytest.raises(ValueError):
            rgb_carrier.with_samples(np.zeros(10, dtype=np.uint8))

    def test_with_samples_does_not_mutate_the_original(self, rgb_carrier):
        before = rgb_carrier.pixels.copy()
        rgb_carrier.with_samples(np.zeros(rgb_carrier.n_samples, dtype=np.uint8))
        assert np.array_equal(rgb_carrier.pixels, before)


class TestSave:
    def test_png_round_trip_is_lossless(self, rgb_carrier, tmp_path):
        path = tmp_path / "out.png"
        save_png(rgb_carrier, path)
        assert np.array_equal(load_image(path).pixels, rgb_carrier.pixels)

    @pytest.mark.parametrize("name", ["out.jpg", "out.jpeg", "out.webp", "out"])
    def test_lossy_or_unknown_formats_are_refused(self, rgb_carrier, tmp_path, name):
        with pytest.raises(UnsupportedImageError, match=r"\.png"):
            save_png(rgb_carrier, tmp_path / name)

    def test_greyscale_and_alpha_survive_saving(self, tmp_path):
        rgba = np.dstack([natural_image(), np.full((96, 128), 17, np.uint8)])
        for array in (natural_image(channels=1)[..., 0], rgba):
            carrier = from_pil(Image.fromarray(array))
            path = tmp_path / f"{carrier.mode}.png"
            save_png(carrier, path)
            reloaded = load_image(path)
            assert reloaded.mode == carrier.mode
            assert np.array_equal(reloaded.pixels, carrier.pixels)


class TestWriteNew:
    def test_refuses_existing_files(self, tmp_path):
        from shardpix.errors import ShardpixError
        from shardpix.images import write_new

        path = tmp_path / "f"
        write_new(path, b"one")
        with pytest.raises(ShardpixError, match="already exists"):
            write_new(path, b"two")
        write_new(path, b"three", overwrite=True)
        assert path.read_bytes() == b"three"

    def test_refuses_dangling_symlinks(self, tmp_path):
        from shardpix.errors import ShardpixError
        from shardpix.images import write_new

        link = tmp_path / "link"
        link.symlink_to(tmp_path / "target")
        with pytest.raises(ShardpixError):
            write_new(link, b"x")
        assert not (tmp_path / "target").exists()

    def test_overwrite_never_follows_a_link(self, tmp_path):
        from shardpix.errors import ShardpixError
        from shardpix.images import write_new

        target = tmp_path / "target"
        target.write_bytes(b"keep")
        link = tmp_path / "link"
        link.symlink_to(target)
        with pytest.raises(ShardpixError, match="symbolic link"):
            write_new(link, b"x", overwrite=True)
        assert target.read_bytes() == b"keep"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_new_files_are_private(self, tmp_path):
        from shardpix.images import write_new

        old = os.umask(0o022)
        try:
            write_new(tmp_path / "f", b"x")
        finally:
            os.umask(old)
        assert stat.S_IMODE((tmp_path / "f").stat().st_mode) == 0o600


class TestSizeLimit:
    """M1: the size is checked from the header, before anything is decoded."""

    def test_huge_png_header_is_refused(self, tmp_path):
        import struct
        import zlib

        path = tmp_path / "big.png"
        Image.fromarray(natural_image(16, 16, 3)).save(path)
        data = bytearray(path.read_bytes())
        ihdr = struct.pack(">II", 20_000, 20_000) + bytes(data[24:29])
        data[16:29] = ihdr
        data[29:33] = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
        path.write_bytes(bytes(data))
        with pytest.raises(UnsupportedImageError, match="too large"):
            load_image(path)

    def test_huge_jpeg_header_is_refused(self, tmp_path, monkeypatch):
        from shardpix import jpeg

        path = phone_jpeg(tmp_path / "big.jpg")
        data = path.read_bytes()
        segments, _ = jpeg._segments(data)
        offset = data.index(next(s for m, s in segments if m == 0xC0))
        patched = bytearray(data)
        patched[offset + 5 : offset + 9] = (20_000).to_bytes(2, "big") * 2
        path.write_bytes(bytes(patched))

        def never(*args, **kwargs):
            raise AssertionError("libjpeg must not be called")

        monkeypatch.setattr(jpeg.jpeglib, "read_dct", never)
        with pytest.raises(UnsupportedImageError, match="too large"):
            jpeg.load(path)

    def test_the_limit_admits_the_largest_phone_sensors(self):
        from shardpix import images

        assert 120_000_000 <= images.MAX_PIXELS

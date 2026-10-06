"""Tests for carrier loading and saving."""

from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

from shardpix.errors import UnsupportedImageError
from shardpix.images import from_pil, load_image, save_png

from .conftest import natural_image


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

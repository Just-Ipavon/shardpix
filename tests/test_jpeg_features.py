"""JPEG-domain steganalysis features: decompression, DCTR and GFR."""

from __future__ import annotations

import jpeglib
import numpy as np
import pytest

from shardpix.analysis import features, jpeg_benchmark

from .conftest import phone_jpeg


@pytest.fixture(scope="module")
def photo(tmp_path_factory):
    path = phone_jpeg(tmp_path_factory.mktemp("jpeg") / "photo.jpg", 64, 96, quality=90)
    image = jpeglib.read_dct(str(path))
    image.load()
    return path, image.Y.copy(), image.qt[image.quant_tbl_no[0]].copy()


def _mirrored(blocks: np.ndarray) -> np.ndarray:
    """The coefficients of the horizontally mirrored image: columns of blocks reversed,
    and every odd horizontal frequency negated."""
    sign = np.where(np.arange(8) % 2 == 0, 1, -1)
    return blocks[:, ::-1] * sign[None, None, None, :]


class TestDecompress:
    def test_matches_libjpeg_up_to_rounding(self, photo):
        path, blocks, quant = photo
        ours = features.decompress(blocks, quant)
        decoded = jpeglib.read_spatial(str(path), jpeglib.JCS_GRAYSCALE).spatial[..., 0]
        assert np.abs(ours - decoded.astype(np.float64)).max() <= 2


class TestDCTR:
    def test_dimension_and_normalisation(self, photo):
        _, blocks, quant = photo
        values = features.dctr(blocks, quant, features.dctr_step(90))
        assert values.shape == (8000,)
        assert np.allclose(values.reshape(-1, 25, features.DCTR_T + 1).sum(-1), 1)


class TestGFR:
    def test_dimension_and_normalisation(self, photo):
        _, blocks, quant = photo
        values = features.gfr(blocks, quant, features.dctr_step(90))
        assert values.shape == (features.GFR_DIM,) == (17000,)
        assert np.allclose(values.reshape(-1, 25, features.GFR_T + 1).sum(-1), 1)

    def test_kernels_are_zero_mean_and_unit_norm(self):
        kernels = features._GFR_KERNELS.reshape(-1, 8, 8)
        assert np.allclose(kernels.sum(axis=(1, 2)), 0, atol=1e-9)
        assert np.allclose(np.linalg.norm(kernels, axis=(1, 2)), 1)

    def test_invariant_to_a_mirror_image(self, photo):
        # Orientations k and 32 - k are merged and the 8x8 grid classes are
        # symmetric, so mirroring the image must not change the features.
        _, blocks, quant = photo
        step = features.dctr_step(90)
        original = features.gfr(blocks, quant, step)
        mirrored = features.gfr(_mirrored(blocks), quant, step)
        # Equal up to residuals that fall exactly on a rounding boundary, where
        # the FFT's last-bit noise can move a count to the next bin.
        differ = np.abs(original - mirrored) > 1e-6
        assert differ.mean() < 1e-3
        assert np.abs(original - mirrored).max() < 0.01

    def test_sees_a_change_in_the_coefficients(self, photo):
        _, blocks, quant = photo
        step = features.dctr_step(90)
        changed = blocks.copy()
        changed[2, 3, 1, 2] += 1
        assert not np.array_equal(
            features.gfr(blocks, quant, step), features.gfr(changed, quant, step)
        )


class TestBenchmarkDetectors:
    def test_one_embedding_feeds_every_detector(self, photo):
        path, _, _ = photo
        jpeg_benchmark._PATHS = [path]
        jpeg_benchmark._STEP = features.dctr_step(90)
        dctr, gfr = jpeg_benchmark._worker((0, "naive", "share", 0, ("dctr", "gfr")))
        assert dctr.shape == (8000,)
        assert gfr.shape == (17000,)

    def test_rows_without_a_detector_are_dctr(self):
        row = {"strategy": "jpeg", "payload": "share"}
        assert jpeg_benchmark._matches(row, "dctr", "jpeg", "share")
        assert not jpeg_benchmark._matches(row, "gfr", "jpeg", "share")

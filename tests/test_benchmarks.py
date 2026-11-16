"""The benchmark entry points, end to end on a handful of tiny synthetic covers.

The published numbers come from BOSSbase runs that take hours; these runs
only check that each `main()` reads covers, measures, writes its data and
draws its charts. They need matplotlib (the `ml` extra) and run in the `ml`
CI job.
"""

from __future__ import annotations

import json

import pytest
from PIL import Image

from shardpix.analysis import benchmark, jpeg_benchmark, ml_benchmark

from .conftest import processed_image

pytest.importorskip("matplotlib")


@pytest.fixture
def covers(tmp_path):
    png, jpg = tmp_path / "png", tmp_path / "jpg"
    png.mkdir()
    jpg.mkdir()
    for i in range(12):
        image = Image.fromarray(processed_image(96, 96, seed=i))
        image.save(png / f"c{i}.png")
        image.save(jpg / f"c{i}.jpg", quality=95)
    return png, jpg


def test_classical_benchmark_on_own_covers(covers, tmp_path, capsys):
    """Custom covers have none of the sample names the RS charts used to assume."""
    png, _ = covers
    out, data = tmp_path / "charts", tmp_path / "benchmark.json"
    assert (
        benchmark.main(
            [str(png / "c0.png"), str(png / "c1.png"), "--out", str(out), "--data", str(data)]
        )
        == 0
    )
    assert {p.name for p in out.glob("*.png")} >= {
        "rs-estimate-light.png",
        "rs-clipped-dark.png",
        "chi-square-light.png",
        "lsb-planes.png",
    }
    assert set(json.loads(data.read_text())["rs_sweep"]["replacement"]) == {"c0", "c1"}


def test_ml_benchmark_with_one_detector(covers, tmp_path):
    png, _ = covers
    data = tmp_path / "ml.json"
    assert (
        ml_benchmark.main(
            [
                str(png),
                "--size",
                "64",
                "--detectors",
                "spam",
                "--rates",
                "0.4",
                "--out",
                str(tmp_path / "charts"),
                "--data",
                str(data),
            ]
        )
        == 0
    )
    results = json.loads(data.read_text())
    assert results["images"] == 12 and "spam" in results["detectors"]


def test_jpeg_benchmark_with_dctr(covers, tmp_path):
    _, jpg = covers
    out = tmp_path / "data"
    assert jpeg_benchmark.main([str(jpg), "--quality", "95", "--data", str(out)]) == 0
    results = json.loads((out / "jpeg_benchmark_q95.json").read_text())
    assert results["images"] == 12 and results["rows"]

"""Shared fixtures.

Tests never depend on downloaded or bundled photographs: covers are
synthesised so the suite stays small, deterministic and offline. The
synthetic images mimic what matters for steganalysis - smooth regions with a
little sensor-like noise - rather than being uniform random noise, on which
every attack would trivially fail.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from shardpix import stego
from shardpix.images import Carrier, from_pil

PRODUCTION_SCRYPT = (stego.SCRYPT_N, stego.SCRYPT_R, stego.SCRYPT_P)


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    """Use a cheap scrypt cost in tests; the real cost is checked in test_stego."""
    monkeypatch.setattr(stego, "SCRYPT_N", 2**10)


def natural_image(
    height: int = 96, width: int = 128, channels: int = 3, seed: int = 0
) -> np.ndarray:
    """A smooth, slightly noisy synthetic photograph as an ``H x W x C`` uint8 array."""
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:height, 0:width].astype(np.float64)
    layers = []
    for c in range(channels):
        phase = rng.uniform(0, 2 * np.pi, size=3)
        base = (
            110
            + 60 * np.sin(x / (17 + 5 * c) + phase[0])
            + 40 * np.cos(y / (23 + 3 * c) + phase[1])
            + 20 * np.sin((x + y) / 31 + phase[2])
        )
        layers.append(base + rng.normal(0, 2.0, size=(height, width)))
    return np.clip(np.stack(layers, axis=-1), 0, 255).round().astype(np.uint8)


def combed_image(height: int = 256, width: int = 256, seed: int = 7) -> np.ndarray:
    """A synthetic photograph whose histogram favours even values.

    Processed photographs (gamma correction, contrast stretching, JPEG
    decoding) often have "combed" histograms in which the two values of an
    LSB pair are far from equal. That imbalance is exactly what the chi-square
    attack looks for, so these images make its behaviour measurable in tests;
    the benchmark covers real photographs.
    """
    rng = np.random.default_rng(seed + 1)
    base = natural_image(height, width, seed=seed)
    odd = (rng.random(base.shape) < 0.25).astype(np.uint8)
    return (base & 0xFE) | odd


def processed_image(height: int = 96, width: int = 128, seed: int = 1) -> np.ndarray:
    """A synthetic photograph after a contrast stretch, as most real photos have had.

    Neither the chi-square attack nor RS analysis flags it, which makes it a
    reliable clean cover for end-to-end tests.
    """
    base = natural_image(height, width, seed=seed).astype(np.float64)
    return np.clip(np.round((base - 20) * 1.3), 0, 255).astype(np.uint8)


@pytest.fixture
def rgb_carrier() -> Carrier:
    return from_pil(Image.fromarray(natural_image()))


@pytest.fixture
def large_carrier() -> Carrier:
    return from_pil(Image.fromarray(natural_image(256, 256, seed=7)))


@pytest.fixture
def combed_carrier() -> Carrier:
    return from_pil(Image.fromarray(combed_image()))


@pytest.fixture
def cover_png(tmp_path: Path) -> Path:
    path = tmp_path / "cover.png"
    Image.fromarray(processed_image()).save(path)
    return path


@pytest.fixture
def passphrase_file(tmp_path: Path) -> Path:
    path = tmp_path / "passphrase.txt"
    path.write_text("correct horse battery staple\n", encoding="utf-8")
    return path

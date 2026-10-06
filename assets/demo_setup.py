"""Prepare the directory the README demo is recorded in.

Writes five PNG photographs (scikit-image samples, public domain or CC0), a
dummy "docs/notes.pdf" and a passphrase file.

Usage:
    python assets/demo_setup.py <directory>
"""

import sys
from pathlib import Path

import numpy as np
from PIL import Image
from skimage import data

PHOTOS = {
    "cat": data.chelsea,
    "coffee": data.coffee,
    "rocket": data.rocket,
    "street": data.camera,
    "astronaut": data.astronaut,
}

target = Path(sys.argv[1] if len(sys.argv) > 1 else "demo")
(target / "photos").mkdir(parents=True, exist_ok=True)
(target / "docs").mkdir(exist_ok=True)
for name, load in PHOTOS.items():
    Image.fromarray(load()).save(target / "photos" / f"{name}.png")
(target / "docs" / "notes.pdf").write_bytes(np.random.default_rng(0).bytes(48_213))
(target / "key").write_text("correct horse battery staple\n", encoding="utf-8")
print(f"demo directory ready: {target}")

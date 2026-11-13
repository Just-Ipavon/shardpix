"""Malformed-image corpus (#31): every damaged cover ends in a formatted error.

The corpus is generated deterministically from three valid files (a phone
JPEG, a PNG and a two-frame MPO) by truncating them, flipping bytes, inserting
standalone markers and inflating the declared size. Every case must either
load or raise a ``ShardpixError`` (what the CLI turns into one line), and stay
under a memory bound: a header claiming gigapixels must be refused before
anything is allocated.
"""

from __future__ import annotations

import random
import struct
import tracemalloc
import zlib

import pytest
from PIL import Image

from shardpix import media
from shardpix.errors import ShardpixError

from .conftest import natural_image, phone_jpeg

PEAK_BYTES = 256 * 1024 * 1024


def _png(tmp_path):
    path = tmp_path / "base.png"
    Image.fromarray(natural_image(48, 64)).save(path)
    return path.read_bytes()


def _mpo(tmp_path, jpeg_path):
    with Image.open(jpeg_path) as image:
        image.load()
        path = tmp_path / "base.mpo.jpg"
        image.save(path, format="MPO", save_all=True, append_images=[image.rotate(90)])
    return path.read_bytes()


def _inflated_jpeg(data: bytes) -> bytes:
    """The frame header claims 65500 x 65500 pixels."""
    i = 2
    while i + 4 <= len(data):
        marker = data[i + 1]
        length = int.from_bytes(data[i + 2 : i + 4], "big")
        if marker in (0xC0, 0xC1, 0xC2):
            out = bytearray(data)
            out[i + 5 : i + 9] = struct.pack(">HH", 65500, 65500)
            return bytes(out)
        i += 2 + length
    raise AssertionError("no SOF")


def _inflated_png(data: bytes) -> bytes:
    ihdr = bytearray(data[16:29])
    ihdr[0:8] = struct.pack(">II", 60000, 60000)
    chunk = b"IHDR" + bytes(ihdr)
    return data[:12] + chunk + struct.pack(">I", zlib.crc32(chunk)) + data[33:]


def _cases(tmp_path):
    jpeg_path = phone_jpeg(tmp_path / "base.jpg")
    bases = {
        "jpeg": jpeg_path.read_bytes(),
        "png": _png(tmp_path),
        "mpo": _mpo(tmp_path, jpeg_path),
    }
    rng = random.Random(31)
    cases = []
    for kind, data in bases.items():
        for cut in (2, 3, 20, 100, len(data) // 3, len(data) // 2, len(data) - 2):
            cases.append((f"{kind}-cut{cut}", data[:cut]))
        for n in range(25):
            out = bytearray(data)
            for _ in range(rng.randint(1, 8)):
                pos = rng.randrange(2, min(len(out), 600))  # mostly headers
                out[pos] = rng.randrange(256)
            cases.append((f"{kind}-flip{n}", bytes(out)))
    jpeg = bases["jpeg"]
    cases.append(("jpeg-tem", jpeg[:2] + b"\xff\x01" + jpeg[2:]))
    cases.append(("jpeg-rst-in-header", jpeg[:2] + b"\xff\xd3" + jpeg[2:]))
    cases.append(("jpeg-huge", _inflated_jpeg(jpeg)))
    cases.append(("png-huge", _inflated_png(bases["png"])))
    cases.append(("empty", b""))
    cases.append(("soi-only", b"\xff\xd8\xff"))
    return cases


def test_every_malformed_cover_ends_in_a_formatted_error(tmp_path):
    unexpected = []
    for name, data in _cases(tmp_path):
        path = tmp_path / f"{name}.img"
        path.write_bytes(data)
        tracemalloc.start()
        try:
            cover = media.open_cover(path)
            cover.capacity()
            media.reveal(path, "pw")
        except ShardpixError:
            pass
        except Exception as exc:  # noqa: BLE001 - the point of the test
            unexpected.append(f"{name}: {type(exc).__name__}: {exc}")
        finally:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        if peak > PEAK_BYTES:
            unexpected.append(f"{name}: peak {peak / 2**20:.0f} MiB")
    assert unexpected == []


@pytest.mark.parametrize("name", ["jpeg-huge", "png-huge"])
def test_declared_gigapixels_are_refused_before_decoding(tmp_path, name):
    data = dict(_cases(tmp_path))[name]
    path = tmp_path / "huge"
    path.write_bytes(data)
    with pytest.raises(ShardpixError, match="too large"):
        media.open_cover(path)

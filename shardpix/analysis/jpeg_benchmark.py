"""Trained steganalysis of JPEG covers: format 5 against DCTR.

The JPEG counterpart of :mod:`.ml_benchmark`. BOSSbase photographs are
compressed at one quality factor; every detector sees the same covers and
the same stego images, produced by:

* ``jpeg`` - format 5 itself (:func:`shardpix.jpeg.embed_coefficients`):
  syndrome-trellis codes with UERD costs;
* ``naive`` - the non-adaptive baseline: random bits written one per
  coefficient at keyed-like random positions among the non-zero AC
  coefficients, +-1 away from zero, as format 3 does in pixels.

The payload is either one vault share (``share``, 1,264 bits whatever the
image) or a rate in bits per non-zero AC coefficient (bpnzAC), the unit of
JPEG steganography. The detector is DCTR with the ensemble classifier,
trained on half of the images at the exact payload and tested on the other
half. Per-image test scores are stored for :mod:`.pooled`.

Usage::

    python -m shardpix.analysis.jpeg_benchmark BOSSbase_jpeg_q95/ --quality 95 \\
        --strategy jpeg --payloads share,0.2
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import time
from pathlib import Path

import jpeglib
import numpy as np

from .. import jpeg, stego, vault
from . import ensemble, features
from .ml_benchmark import _summary, split

STRATEGIES = {
    "jpeg": "format 5: syndrome-trellis codes with UERD costs on non-zero AC coefficients",
    "naive": "one bit per coefficient at random non-zero AC positions, +-1 away from zero",
}

_PATHS: list[Path] = []
_STEP = 4.0


def _load(path: Path) -> tuple[np.ndarray, np.ndarray]:
    image = jpeglib.read_dct(str(path))
    image.load()
    return image.Y.copy(), image.qt[image.quant_tbl_no[0]].copy()


def _payload_bits(payload: str, n_eligible: int) -> int:
    if payload == "share":
        return 8 * vault.PAYLOAD_FRAME_BYTES
    return int(round(float(payload) * n_eligible))


def stego_blocks(
    blocks: np.ndarray, quant: np.ndarray, strategy: str, payload: str, rng: np.random.Generator
) -> np.ndarray:
    """The luminance blocks after embedding ``payload`` with ``strategy``."""
    coefficients = blocks.astype(np.int32).reshape(-1)
    eligible = np.flatnonzero(jpeg.eligible_mask(coefficients))
    bits = min(_payload_bits(payload, eligible.size), eligible.size // stego.MAX_FILL)
    if strategy == "naive":
        positions = rng.choice(eligible, size=bits, replace=False)
        mismatch = (coefficients[positions] & 1) != rng.integers(0, 2, bits)
        flips = positions[mismatch]
        out = jpeg._apply(coefficients, flips, rng.bytes)
    else:
        size = bits // 8 - stego.PUBLIC_BYTES - stego.FRAME_OVERHEAD
        size = max(0, min(size, stego.capacity(eligible.size)))
        out, _ = jpeg.embed_coefficients(
            coefficients, blocks.shape, quant, rng.bytes(size), "benchmark", rng.bytes
        )
    return out.reshape(blocks.shape)


def _worker(args: tuple[int, str, str, int]) -> np.ndarray:
    index, strategy, payload, seed = args
    blocks, quant = _load(_PATHS[index])
    if payload != "clean":
        rng = np.random.default_rng([seed, index, sum(map(ord, strategy + payload))])
        blocks = stego_blocks(blocks, quant, strategy, payload, rng)
    return features.dctr(blocks, quant, _STEP).astype(np.float32)


def feature_matrix(strategy: str, payload: str, seed: int, cache: Path | None) -> np.ndarray:
    name = "clean" if payload == "clean" else f"{strategy}-{payload}"
    path = None if cache is None else cache / f"dctr-{name}-{len(_PATHS)}-seed{seed}.npy"
    if path is not None and path.exists():
        return np.load(path)
    with mp.get_context("fork").Pool() as pool:
        rows = pool.map(
            _worker, [(i, strategy, payload, seed) for i in range(len(_PATHS))], chunksize=16
        )
    matrix = np.stack(rows)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        np.save(path, matrix)
    return matrix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("covers", type=Path, help="directory of JPEG covers")
    parser.add_argument("--quality", type=int, required=True, help="their JPEG quality factor")
    parser.add_argument("--strategy", choices=sorted(STRATEGIES), default="jpeg")
    parser.add_argument("--payloads", default="share", help="'share' and/or bpnzAC rates")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--cache", type=Path, default=None)
    parser.add_argument("--data", type=Path, default=Path("docs/data"))
    args = parser.parse_args(argv)

    global _PATHS, _STEP
    _PATHS = sorted(args.covers.glob("*.jpg"))[: args.limit]
    _STEP = features.dctr_step(args.quality)
    if not _PATHS:
        raise SystemExit("no JPEG covers found")
    data_path = args.data / f"jpeg_benchmark_q{args.quality}.json"
    scores_path = data_path.with_suffix(".scores.npz")
    results = json.loads(data_path.read_text("utf-8")) if data_path.exists() else {}
    if results.get("images") != len(_PATHS):
        results = {}
    results.update(
        {
            "dataset": "BOSSbase 1.01, 512x512, JPEG",
            "quality": args.quality,
            "images": len(_PATHS),
            "seed": args.seed,
            "detector": "DCTR + ensemble classifier",
            "strategies": STRATEGIES,
        }
    )
    rows = results.setdefault("rows", [])
    scores = dict(np.load(scores_path)) if scores_path.exists() else {}
    train_idx, test_idx = split(len(_PATHS), args.seed)

    start = time.time()
    clean = feature_matrix(args.strategy, "clean", args.seed, args.cache)
    print(
        f"{len(_PATHS)} covers at quality {args.quality}; cover DCTR in {time.time() - start:.0f} s"
    )
    for payload in [p.strip() for p in args.payloads.split(",") if p.strip()]:
        start = time.time()
        dirty = feature_matrix(args.strategy, payload, args.seed, args.cache)
        model = ensemble.train(clean[train_idx], dirty[train_idx], seed=args.seed)
        v0, v1 = model.votes(clean[test_idx]), model.votes(dirty[test_idx])
        row = {"strategy": args.strategy, "payload": payload, **_summary(v0, v1, 0.5)}
        rows[:] = [r for r in rows if (r["strategy"], r["payload"]) != (args.strategy, payload)]
        rows.append(row)
        scores["test_index"] = test_idx
        scores[f"dctr@{args.strategy}@{payload}"] = np.stack([v0, v1]).astype(np.float32)
        data_path.parent.mkdir(parents=True, exist_ok=True)
        data_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        np.savez_compressed(scores_path, **scores)
        print(
            f"  {args.strategy:6s} {payload:6s}: P_E {row['p_e']:.3f} "
            f"[{row['p_e_low']:.3f}, {row['p_e_high']:.3f}], AUC {row['auc']:.3f} "
            f"({time.time() - start:.0f} s)",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
CHUNK = 1000
"""Images per checkpoint of a feature matrix."""


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
        if stego.max_frame_bytes(eligible.size) < stego.FRAME_OVERHEAD:
            # A flat photo at a low quality can have too few non-zero AC
            # coefficients to hold even an empty frame: shardpix refuses it
            # as a cover, so it stays as it is.
            return blocks
        size = bits // 8 - stego.PUBLIC_BYTES - stego.FRAME_OVERHEAD
        size = max(0, min(size, stego.capacity(eligible.size)))
        out, _ = jpeg.embed_coefficients(
            coefficients, blocks.shape, quant, rng.bytes(size), "benchmark", rng.bytes
        )
    return out.reshape(blocks.shape)


DETECTORS = {
    "dctr": (features.dctr, "DCTR (8,000 features)"),
    "gfr": (features.gfr, "GFR (17,000 features)"),
}


def _worker(args: tuple[int, str, str, int, tuple[str, ...]]) -> list[np.ndarray]:
    """Features of one image for each detector, from a single embedding."""
    index, strategy, payload, seed, detectors = args
    blocks, quant = _load(_PATHS[index])
    if payload != "clean":
        rng = np.random.default_rng([seed, index, sum(map(ord, strategy + payload))])
        blocks = stego_blocks(blocks, quant, strategy, payload, rng)
    return [DETECTORS[d][0](blocks, quant, _STEP).astype(np.float32) for d in detectors]


def _cache_path(cache: Path, detector: str, tag: str, quality: int, name: str, seed: int) -> Path:
    prefix = f"{detector}-{tag}-" if tag else f"{detector}-"
    return cache / f"{prefix}q{quality}-{name}-{len(_PATHS)}-seed{seed}.npy"


def feature_matrices(
    strategy: str,
    payload: str,
    seed: int,
    cache: Path | None,
    quality: int,
    detectors: tuple[str, ...] = ("dctr",),
    tag: str = "",
) -> dict[str, np.ndarray]:
    """One feature matrix per detector; each image is embedded once for all of them."""
    name = "clean" if payload == "clean" else f"{strategy}-{payload}"
    paths = {
        d: None if cache is None else _cache_path(cache, d, tag, quality, name, seed)
        for d in detectors
    }
    done = {d: np.load(p) for d, p in paths.items() if p is not None and p.exists()}
    missing = tuple(d for d in detectors if d not in done)
    if not missing:
        return done
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
    parts: dict[str, list[np.ndarray]] = {d: [] for d in missing}
    with mp.get_context("fork").Pool() as pool:
        for start in range(0, len(_PATHS), CHUNK):
            # Each chunk is saved as it completes, so a run killed halfway
            # resumes from the last chunk instead of from the first image.
            chunk_files = {
                d: None
                if paths[d] is None
                else paths[d].with_name(f"{paths[d].stem}.part{start}.npy")
                for d in missing
            }
            if all(f is not None and f.exists() for f in chunk_files.values()):
                for d in missing:
                    parts[d].append(np.load(chunk_files[d]))
                continue
            stop = min(start + CHUNK, len(_PATHS))
            rows = pool.map(
                _worker,
                [(i, strategy, payload, seed, missing) for i in range(start, stop)],
                chunksize=8,
            )
            for j, d in enumerate(missing):
                parts[d].append(np.stack([r[j] for r in rows]))
                if chunk_files[d] is not None:
                    np.save(chunk_files[d], parts[d][-1])
            print(f"    {name}: {stop}/{len(_PATHS)} images", flush=True)
    for d in missing:
        done[d] = np.concatenate(parts[d])
        if paths[d] is not None:
            np.save(paths[d], done[d])
            for part in paths[d].parent.glob(f"{paths[d].stem}.part*.npy"):
                part.unlink()
    return done


def feature_matrix(
    strategy: str, payload: str, seed: int, cache: Path | None, quality: int
) -> np.ndarray:
    """DCTR features only (kept for callers of the first version)."""
    return feature_matrices(strategy, payload, seed, cache, quality)["dctr"]


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
    parser.add_argument("--rerun", action="store_true", help="measure again what is stored")
    parser.add_argument(
        "--detectors", default="dctr", help="comma-separated: " + ", ".join(DETECTORS)
    )
    parser.add_argument(
        "--tag",
        default="",
        help="name of the cover set, e.g. 'alaska'; kept apart in data and cache",
    )
    parser.add_argument(
        "--dataset-name", default="BOSSbase 1.01, 512x512, JPEG", help="description in the data"
    )
    args = parser.parse_args(argv)
    detectors = tuple(d.strip() for d in args.detectors.split(",") if d.strip())
    unknown = [d for d in detectors if d not in DETECTORS]
    if unknown:
        raise SystemExit(f"unknown detectors: {', '.join(unknown)}")

    global _PATHS, _STEP
    _PATHS = sorted(args.covers.glob("*.jpg"))[: args.limit]
    _STEP = features.dctr_step(args.quality)
    if not _PATHS:
        raise SystemExit("no JPEG covers found")
    stem = f"jpeg_benchmark_{args.tag}" if args.tag else "jpeg_benchmark"
    data_path = args.data / f"{stem}_q{args.quality}.json"
    scores_path = data_path.with_suffix(".scores.npz")
    results = json.loads(data_path.read_text("utf-8")) if data_path.exists() else {}
    if results.get("images") != len(_PATHS):
        results = {}
    results.update(
        {
            "dataset": args.dataset_name,
            "quality": args.quality,
            "images": len(_PATHS),
            "seed": args.seed,
            "detector": "ensemble classifier on "
            + ", ".join(DETECTORS[d][1] for d in sorted({*detectors, *_detectors_in(results)})),
            "strategies": STRATEGIES,
        }
    )
    rows = results.setdefault("rows", [])
    scores = dict(np.load(scores_path)) if scores_path.exists() else {}
    train_idx, test_idx = split(len(_PATHS), args.seed)

    start = time.time()
    clean = feature_matrices(
        args.strategy, "clean", args.seed, args.cache, args.quality, detectors, args.tag
    )
    print(
        f"{len(_PATHS)} covers at quality {args.quality}; cover features in "
        f"{time.time() - start:.0f} s",
        flush=True,
    )
    for payload in [p.strip() for p in args.payloads.split(",") if p.strip()]:
        todo = tuple(
            d
            for d in detectors
            if args.rerun
            or f"{d}@{args.strategy}@{payload}" not in scores
            or not any(_matches(r, d, args.strategy, payload) for r in rows)
        )
        if not todo:
            print(f"  {args.strategy:6s} {payload:6s}: already measured, skipped", flush=True)
            continue
        start = time.time()
        dirty = feature_matrices(
            args.strategy, payload, args.seed, args.cache, args.quality, todo, args.tag
        )
        for d in todo:
            model = ensemble.train(clean[d][train_idx], dirty[d][train_idx], seed=args.seed)
            v0, v1 = model.votes(clean[d][test_idx]), model.votes(dirty[d][test_idx])
            row = {
                "detector": d,
                "strategy": args.strategy,
                "payload": payload,
                **_summary(v0, v1, 0.5),
            }
            rows[:] = [r for r in rows if not _matches(r, d, args.strategy, payload)]
            rows.append(row)
            scores["test_index"] = test_idx
            scores[f"{d}@{args.strategy}@{payload}"] = np.stack([v0, v1]).astype(np.float32)
            data_path.parent.mkdir(parents=True, exist_ok=True)
            data_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
            np.savez_compressed(scores_path, **scores)
            print(
                f"  {d:4s} {args.strategy:6s} {payload:6s}: P_E {row['p_e']:.3f} "
                f"[{row['p_e_low']:.3f}, {row['p_e_high']:.3f}], AUC {row['auc']:.3f} "
                f"({time.time() - start:.0f} s)",
                flush=True,
            )
    return 0


def _matches(row: dict, detector: str, strategy: str, payload: str) -> bool:
    """Rows written before GFR have no 'detector' field: they are DCTR."""
    return (row.get("detector", "dctr"), row["strategy"], row["payload"]) == (
        detector,
        strategy,
        payload,
    )


def _detectors_in(results: dict) -> set[str]:
    return {r.get("detector", "dctr") for r in results.get("rows", [])}


if __name__ == "__main__":
    raise SystemExit(main())

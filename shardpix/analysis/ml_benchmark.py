"""Trained steganalysis: can a machine-learning detector find a vault share?

The classical benchmark (:mod:`.benchmark`) runs attacks that need no
training. This one trains detectors on thousands of cover/stego pairs, the
way modern steganalysis is evaluated, and measures their error on images they
have never seen:

* SPAM features + ensemble classifier (Pevný et al. 2010; Kodovský et al. 2012)
* SRM-lite features + ensemble classifier (a subset of the spatial rich model)
* a convolutional network of the Xu-Net / Yedroudj-Net family (needs PyTorch)

Every detector sees the *same* covers and the *same* stego images, embedded
with shardpix's own strategy (LSB matching on samples 2-253, keyed positions,
random bits), at a sweep of embedding rates and at the exact rate of one vault
share. The detectors are trained and tested at each rate separately - the
attacker is assumed to know the rate, which is the most favourable setting
for them.

Usage::

    pip install -e ".[bench,ml]"
    python -m shardpix.analysis.ml_benchmark BOSSbase_1.01/ --size 512
    python -m shardpix.analysis.ml_benchmark BOSSbase_1.01/ --detectors cnn

Results are merged into ``--data`` (default ``docs/data/ml_benchmark_<size>.json``):
rates already measured by the feature-based detectors are skipped, so a run
can be extended with more rates, and the charts can be redrawn from the file
with ``--plot-only``.

The reported error is P_E = (P_FA + P_MD) / 2 on the test half: 0.5 means the
detector is guessing, 0 means it is never wrong.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import numpy as np
from PIL import Image

from .. import stego, vault
from ..images import Carrier
from . import ensemble, features
from .benchmark import SCENARIO_BY_KEY, THEMES, _finish, _style_axes, embed_random

SWEEP = (0.4, 0.2, 0.1, 0.05, 0.02, 0.01, 0.005)
SUFFIXES = {".pgm", ".png", ".tif", ".tiff", ".bmp", ".ppm"}
FEATURE_DETECTORS = ("spam", "srm_lite")
LABELS = {
    "spam": "SPAM + ensemble classifier",
    "srm_lite": "SRM-lite + ensemble classifier",
    "cnn": "CNN (Xu-Net / Yedroudj-Net family)",
}

# --------------------------------------------------------------------------- data


def _image_paths(sources: Sequence[Path]) -> list[Path]:
    paths: list[Path] = []
    for source in sources:
        if source.is_dir():
            paths += sorted(p for p in source.rglob("*") if p.suffix.lower() in SUFFIXES)
        else:
            paths.append(source)
    return paths


def _load_one(args: tuple[Path, int, str]) -> np.ndarray:
    path, size, how = args
    with Image.open(path) as image:
        image = image.convert("L")
        if image.size != (size, size):
            if how == "resize":
                image = image.resize((size, size), Image.Resampling.BICUBIC)
            else:
                w, h = image.size
                left, top = (w - size) // 2, (h - size) // 2
                image = image.crop((left, top, left + size, top + size))
        return np.array(image, dtype=np.uint8)


def load_covers(
    sources: Sequence[Path], size: int, how: str = "resize", limit: int | None = None
) -> np.ndarray:
    """Greyscale ``size`` x ``size`` covers, as an ``N x size x size`` uint8 array."""
    paths = _image_paths(sources)[:limit]
    if not paths:
        raise SystemExit("no cover images found")
    with mp.get_context("fork").Pool() as pool:
        images = pool.map(_load_one, [(p, size, how) for p in paths], chunksize=64)
    return np.stack(images)


def share_rate(size: int) -> float:
    """Embedding rate of one vault share in a ``size`` x ``size`` greyscale image."""
    rng = np.random.default_rng(0)
    pixels = rng.integers(16, 240, (size, size, 1), dtype=np.uint8)
    carrier = Carrier(pixels=pixels, mode="L")
    _, report = stego.embed(carrier, bytes(vault.SHARE_BYTES), "benchmark passphrase")
    return report.embedding_rate


STRATEGIES = {
    "shardpix": "format 3: LSB matching on samples 2-253, keyed positions, random bits",
    "adaptive": "format 4: HiLL costs and syndrome-trellis codes, via stego.embed",
}
STRATEGY = "shardpix"
"""Embedding under test; set by :func:`main` before any worker is forked."""


def embed(cover: np.ndarray, rate: float, rng: np.random.Generator) -> np.ndarray:
    """``cover`` (``H x W``) with ``rate`` of its samples carrying payload bits.

    ``shardpix`` writes random bits at keyed positions as format 3 does.
    ``adaptive`` calls :func:`shardpix.stego.embed` itself with a random
    payload sized so that the image carries ``rate`` bits per sample, as the
    tool would for a share or a file of that size.
    """
    carrier = Carrier(pixels=cover[..., np.newaxis], mode="L")
    if STRATEGY == "shardpix":
        return embed_random(carrier, rate, SCENARIO_BY_KEY["shardpix"], rng)[..., 0]
    payload = int(round(rate * cover.size / 8)) - stego.PUBLIC_BYTES - stego.FRAME_OVERHEAD
    if payload < 0:
        raise ValueError(f"rate {rate:.3%} is below the frame overhead for this size")
    # A few covers are mostly clipped and cannot hold high rates; like the
    # format-3 strategy, they carry as much as fits.
    payload = min(payload, stego.carrier_capacity(carrier))
    out, _ = stego.embed(carrier, rng.bytes(payload), "benchmark", stego.Method.ADAPTIVE, rng.bytes)
    return out.pixels[..., 0]


def stego_rng(seed: int, index: int, rate: float) -> np.random.Generator:
    """The randomness for image ``index`` at ``rate``: identical for every detector."""
    return np.random.default_rng([seed, index, int(round(rate * 1e7))])


def stego_image(covers: np.ndarray, index: int, rate: float, seed: int) -> np.ndarray:
    return embed(covers[index], rate, stego_rng(seed, index, rate))


# --------------------------------------------------------------------------- features

_COVERS: np.ndarray | None = None


def _features_worker(args: tuple[int, float, int]) -> np.ndarray:
    index, rate, seed = args
    if _COVERS is None:
        raise RuntimeError("feature workers started without covers")
    image = _COVERS[index] if rate == 0 else stego_image(_COVERS, index, rate, seed)
    return np.concatenate([features.extract(image, name) for name in FEATURE_DETECTORS])


CACHE: Path | None = None
"""Directory where feature matrices are kept between runs; set by :func:`main`."""


def _cache_path(covers: np.ndarray, rate: float, seed: int) -> Path | None:
    if CACHE is None:
        return None
    kind = "clean" if rate == 0 else STRATEGY
    shape = f"{len(covers)}x{covers.shape[1]}"
    return CACHE / f"features-{kind}-{shape}-seed{seed}-rate{rate:.10f}.npy"


def feature_matrix(covers: np.ndarray, rate: float, seed: int) -> np.ndarray:
    """SPAM and SRM-lite features of every cover (``rate == 0``) or its stego.

    With :data:`CACHE` set, a matrix computed once is read back from disk.
    """
    path = _cache_path(covers, rate, seed)
    if path is not None and path.exists():
        return np.load(path)
    matrix = _compute_features(covers, rate, seed)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        np.save(path, matrix)
    return matrix


def _compute_features(covers: np.ndarray, rate: float, seed: int) -> np.ndarray:
    global _COVERS
    _COVERS = covers
    try:
        with mp.get_context("fork").Pool() as pool:
            rows = pool.map(
                _features_worker, [(i, rate, seed) for i in range(len(covers))], chunksize=32
            )
    finally:
        _COVERS = None
    return np.stack(rows)


def _columns(name: str) -> slice:
    start = 0
    for other in FEATURE_DETECTORS:
        if other == name:
            return slice(start, start + features.DIMENSIONS[name])
        start += features.DIMENSIONS[other]
    raise KeyError(name)


# --------------------------------------------------------------------------- evaluation


def _summary(cover_scores: np.ndarray, stego_scores: np.ndarray, threshold: float) -> dict:
    """Test error at the detector's own threshold, its 95% interval, and the AUC."""
    p_e = ensemble.decision_error(cover_scores > threshold, stego_scores > threshold)
    n = cover_scores.size + stego_scores.size
    half_width = 1.96 * np.sqrt(max(p_e * (1 - p_e), 1e-12) / n)
    return {
        "p_e": p_e,
        "p_e_low": max(0.0, p_e - half_width),
        "p_e_high": min(1.0, p_e + half_width),
        "auc": ensemble.auc(cover_scores, stego_scores),
        "test_pairs": int(cover_scores.size),
    }


def split(n: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Half of the images for training, half for testing, by image (pairs never straddle)."""
    order = np.random.default_rng(seed).permutation(n)
    return np.sort(order[: n // 2]), np.sort(order[n // 2 :])


def run_features(
    covers: np.ndarray,
    rates: Sequence[float],
    seed: int,
    on_rate: Callable[[dict[str, list[dict]]], None] | None = None,
    scores: dict[str, np.ndarray] | None = None,
) -> dict[str, list[dict]]:
    """Train and test both feature-based detectors at every rate.

    ``on_rate`` is called with the rows so far after each rate, so a long run
    can save its progress and survive an interruption. If ``scores`` is
    given, the votes of every test image are stored in it under
    ``"<detector>@<rate>"`` as a ``2 x n`` array (covers, then their stegos,
    in the order of ``scores["test_index"]``): what :mod:`.pooled` needs.
    """
    train_idx, test_idx = split(len(covers), seed)
    start = time.time()
    clean = feature_matrix(covers, 0.0, seed)
    print(f"  cover features: {clean.shape[1]} per image ({time.time() - start:.0f} s)")
    results: dict[str, list[dict]] = {name: [] for name in FEATURE_DETECTORS}
    for rate in rates:
        start = time.time()
        dirty = feature_matrix(covers, rate, seed)
        for name in FEATURE_DETECTORS:
            cols = _columns(name)
            model = ensemble.train(clean[train_idx, cols], dirty[train_idx, cols], seed=seed)
            v0, v1 = model.votes(clean[test_idx, cols]), model.votes(dirty[test_idx, cols])
            if scores is not None:
                scores["test_index"] = test_idx
                scores[f"{name}@{rate:.10f}"] = np.stack([v0, v1]).astype(np.float32)
            row = {
                "rate": rate,
                **_summary(v0, v1, 0.5),
                "oob_error": model.oob_error,
                "subspace_dim": model.subspace_dim,
            }
            results[name].append(row)
            print(
                f"  {name:9s} rate {rate:7.3%}: P_E {row['p_e']:.3f} "
                f"[{row['p_e_low']:.3f}, {row['p_e_high']:.3f}], AUC {row['auc']:.3f}"
            )
        print(f"    ({time.time() - start:.0f} s)")
        if on_rate is not None:
            on_rate(results)
    return results


def run_cnn(
    covers: np.ndarray,
    rates: Sequence[float],
    seed: int,
    *,
    first_epochs: int,
    fine_epochs: int,
    crop: int,
    checkpoint: Path | None = None,
) -> list[dict]:
    """Curriculum training from the highest rate down, testing at every rate.

    With ``checkpoint``, the model and the results are saved after every rate
    (``<checkpoint>.pt`` and ``<checkpoint>.json``), and a run with the same
    settings resumes after the last rate completed.
    """
    import torch

    from . import cnn

    torch.set_num_threads(max(1, mp.cpu_count()))
    train_idx, test_idx = split(len(covers), seed)
    n_valid = max(1, len(train_idx) // 5)
    valid_idx, fit_idx = train_idx[:n_valid], train_idx[n_valid:]
    test_covers = covers[test_idx]

    schedule = sorted(rates, reverse=True)
    settings = {
        "rates": schedule,
        "seed": seed,
        "first_epochs": first_epochs,
        "fine_epochs": fine_epochs,
        "crop": crop,
        "images": len(covers),
        "size": int(covers.shape[1]),
    }
    model = None
    results: list[dict] = []
    if checkpoint is not None:
        weights, saved = checkpoint.with_suffix(".pt"), checkpoint.with_suffix(".json")
        if weights.exists() and saved.exists():
            state = json.loads(saved.read_text("utf-8"))
            if state.get("settings") == settings:
                results = state["results"]
                model = cnn.StegoNet()
                model.load_state_dict(torch.load(weights, weights_only=True))
                print(f"  cnn: resuming after {len(results)} of {len(schedule)} rates")
    for step, rate in enumerate(schedule):
        if step < len(results):
            continue
        print(f"  cnn: training at rate {rate:.3%}")
        start = time.time()

        def embed_fn(cover: np.ndarray, rng: np.random.Generator, rate: float = rate):
            return embed(cover, rate, rng)

        model, log = cnn.train(
            covers[fit_idx],
            covers[valid_idx],
            embed_fn,
            epochs=first_epochs if step == 0 else fine_epochs,
            learning_rate=1e-3 if step == 0 else 5e-4,
            crop=crop,
            init=model,
            seed=seed + step,
        )
        test_stegos = np.stack([stego_image(covers, i, rate, seed) for i in test_idx])
        p0 = cnn.scores(model, test_covers)
        p1 = cnn.scores(model, test_stegos)
        row = {
            "rate": rate,
            **_summary(p0, p1, 0.5),
            "validation_error": log.validation_error,
            "best_epoch": log.best_epoch,
            "epochs": log.epochs,
            "minutes": (time.time() - start) / 60,
        }
        results.append(row)
        if checkpoint is not None:
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            torch.save(model.state_dict(), checkpoint.with_suffix(".pt"))
            checkpoint.with_suffix(".json").write_text(
                json.dumps({"settings": settings, "results": results}), encoding="utf-8"
            )
        print(
            f"  cnn       rate {rate:7.3%}: P_E {row['p_e']:.3f} "
            f"[{row['p_e_low']:.3f}, {row['p_e_high']:.3f}], AUC {row['auc']:.3f} "
            f"({row['minutes']:.0f} min)"
        )
    return sorted(results, key=lambda r: r["rate"])


# --------------------------------------------------------------------------- reporting


def plot(results: dict, out: Path, mode: str) -> Path:
    import matplotlib.pyplot as plt
    from matplotlib.ticker import NullLocator

    theme = THEMES[mode]
    colours = {
        "spam": theme["series"]["replacement"],
        "srm_lite": theme["series"]["matching"],
        "cnn": theme["series"]["shardpix"],
    }
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.subplots_adjust(left=0.1, right=0.95, top=0.8, bottom=0.13)
    _style_axes(ax, theme)
    ax.set_xscale("log")
    share = results["share_rate"]
    ax.axhline(50, color=theme["axis"], linewidth=1, linestyle="--", zorder=1)
    ax.axvline(share * 100, color=theme["axis"], linewidth=1, zorder=1)
    ax.text(
        share * 100 * 1.06,
        3,
        f"one vault share ({share:.2%})",
        color=theme["muted"],
        fontsize=8.5,
        rotation=90,
        va="bottom",
    )
    for key in ("spam", "srm_lite", "cnn"):
        rows = results["detectors"].get(key)
        if not rows:
            continue
        rates = np.array([r["rate"] for r in rows]) * 100
        p_e = np.array([r["p_e"] for r in rows]) * 100
        low = np.array([r["p_e_low"] for r in rows]) * 100
        high = np.array([r["p_e_high"] for r in rows]) * 100
        ax.fill_between(rates, low, high, color=colours[key], alpha=0.15, linewidth=0, zorder=2)
        ax.plot(
            rates,
            p_e,
            color=colours[key],
            linewidth=2,
            marker="o",
            markersize=5,
            markeredgecolor=theme["surface"],
            label=LABELS[key],
            zorder=3,
        )
    measured = [r["rate"] * 100 for rows in results["detectors"].values() for r in rows]
    left = min([*measured, share * 100]) * 0.8
    ax.set_xlim(left, 45)
    ax.set_ylim(0, 56)
    ticks = [t for t in (0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 40) if t >= left]
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{t:g}%" for t in ticks])
    ax.xaxis.set_minor_locator(NullLocator())
    ax.text(left * 1.06, 51.5, "guessing", color=theme["muted"], fontsize=8.5)
    ax.set_xlabel(
        "Samples carrying payload bits (log scale)", color=theme["secondary"], fontsize=9.5
    )
    ax.set_ylabel(
        "Detection error P_E on unseen images (%)", color=theme["secondary"], fontsize=9.5
    )
    adaptive = results.get("strategy", "").startswith("adaptive")
    suffix = "-adaptive" if adaptive else ""
    path = out / f"ml-detection-{results['size']}{suffix}-{mode}.png"
    _finish(
        fig,
        ax,
        theme,
        "Adaptive embedding (format 4) against trained detectors"
        if adaptive
        else "Trained detectors: strong on heavy embedding, weak on a vault share",
        f"{results['dataset']}: {results['images']} images at {results['size']}x"
        f"{results['size']}, half for training, half for testing. Shaded: 95% interval.",
        path,
        legend_at="upper right",
    )
    plt.close(fig)
    return path


def plot_comparison(legacy: dict, adaptive: dict, out: Path, mode: str) -> Path:
    """Format 3 against format 4: the same detectors, the same images."""
    import matplotlib.pyplot as plt
    from matplotlib.ticker import NullLocator

    theme = THEMES[mode]
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.subplots_adjust(left=0.1, right=0.95, top=0.8, bottom=0.13)
    _style_axes(ax, theme)
    ax.set_xscale("log")
    share = adaptive["share_rate"]
    ax.axhline(50, color=theme["axis"], linewidth=1, linestyle="--", zorder=1)
    ax.axvline(share * 100, color=theme["axis"], linewidth=1, zorder=1)
    ax.text(
        share * 100 * 1.06,
        14,
        f"one vault share ({share:.2%})",
        color=theme["muted"],
        fontsize=8.5,
        rotation=90,
        va="bottom",
    )
    series = (
        (legacy, "srm_lite", "format 3 (matching), SRM-lite", theme["series"]["replacement"], "-"),
        (legacy, "spam", "format 3 (matching), SPAM", theme["series"]["replacement"], ":"),
        (adaptive, "srm_lite", "format 4 (adaptive), SRM-lite", theme["series"]["shardpix"], "-"),
        (adaptive, "spam", "format 4 (adaptive), SPAM", theme["series"]["shardpix"], ":"),
    )
    for results, key, label, colour, style in series:
        rows = results["detectors"].get(key)
        if not rows:
            continue
        rates = np.array([r["rate"] for r in rows]) * 100
        p_e = np.array([r["p_e"] for r in rows]) * 100
        low = np.array([r["p_e_low"] for r in rows]) * 100
        high = np.array([r["p_e_high"] for r in rows]) * 100
        ax.fill_between(rates, low, high, color=colour, alpha=0.12, linewidth=0, zorder=2)
        ax.plot(
            rates,
            p_e,
            color=colour,
            linestyle=style,
            linewidth=2,
            marker="o",
            markersize=5,
            markeredgecolor=theme["surface"],
            label=label,
            zorder=3,
        )
    ax.set_xlim(0.08, 45)
    ax.set_ylim(0, 56)
    ticks = [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 40]
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{t:g}%" for t in ticks])
    ax.xaxis.set_minor_locator(NullLocator())
    ax.text(0.085, 51.5, "guessing", color=theme["muted"], fontsize=8.5)
    ax.set_xlabel(
        "Samples carrying payload bits (log scale)", color=theme["secondary"], fontsize=9.5
    )
    ax.set_ylabel(
        "Detection error P_E on unseen images (%)", color=theme["secondary"], fontsize=9.5
    )
    path = out / f"ml-format-comparison-{adaptive['size']}-{mode}.png"
    _finish(
        fig,
        ax,
        theme,
        "Adaptive embedding: a share at chance, 10% as visible as format 3 at 0.5%",
        f"{adaptive['dataset']}: {adaptive['images']} images at {adaptive['size']}x"
        f"{adaptive['size']}, half for training, half for testing. Shaded: 95% interval.",
        path,
        legend_at="lower left",
    )
    plt.close(fig)
    return path


def markdown_table(results: dict) -> str:
    detectors = [k for k in ("spam", "srm_lite", "cnn") if results["detectors"].get(k)]
    rates = sorted({r["rate"] for k in detectors for r in results["detectors"][k]})
    share = results["share_rate"]
    header = "| Embedding rate | " + " | ".join(LABELS[k] for k in detectors) + " |"
    rows = [header, "| ---: |" + " ---: |" * len(detectors)]
    for rate in rates:
        name = f"**{rate:.2%} (one share)**" if abs(rate - share) < 1e-9 else f"{rate * 100:g}%"
        cells = []
        for k in detectors:
            row = next((r for r in results["detectors"][k] if abs(r["rate"] - rate) < 1e-9), None)
            cells.append("—" if row is None else f"{row['p_e']:.1%} (AUC {row['auc']:.2f})")
        rows.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(rows)


def _has(detectors: dict, name: str, rate: float) -> bool:
    return any(abs(r["rate"] - rate) < 1e-12 for r in detectors.get(name, []))


def _merge(old: list[dict], new: list[dict]) -> list[dict]:
    """Rows of ``old`` and ``new`` by rate, ``new`` winning, in increasing rate."""
    rows = {round(r["rate"], 12): r for r in old}
    rows.update({round(r["rate"], 12): r for r in new})
    return [rows[k] for k in sorted(rows)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("covers", nargs="*", type=Path, help="cover images or directories")
    parser.add_argument("--size", type=int, default=256)
    parser.add_argument("--how", choices=("resize", "crop"), default="resize")
    parser.add_argument("--limit", type=int, default=None, help="use only the first N images")
    parser.add_argument("--dataset", default="BOSSbase 1.01")
    parser.add_argument("--detectors", default="spam,srm_lite,cnn")
    parser.add_argument("--rates", default=",".join(str(r) for r in SWEEP))
    parser.add_argument("--first-epochs", type=int, default=20)
    parser.add_argument("--fine-epochs", type=int, default=6)
    parser.add_argument("--crop", type=int, default=128, help="CNN training window")
    parser.add_argument(
        "--checkpoint", type=Path, default=None, help="CNN: save after each rate, resume"
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, default=Path("assets"))
    parser.add_argument(
        "--data", type=Path, default=None, help="default: docs/data/ml_benchmark_<size>.json"
    )
    parser.add_argument("--strategy", choices=sorted(STRATEGIES), default="shardpix")
    parser.add_argument(
        "--cache", type=Path, default=None, help="keep feature matrices here between runs"
    )
    parser.add_argument(
        "--rerun",
        action="store_true",
        help="measure the requested rates again even if the data file has them",
    )
    parser.add_argument("--plot-only", action="store_true")
    args = parser.parse_args(argv)
    suffix = "" if args.strategy == "shardpix" else f"_{args.strategy}"
    if args.data is None:
        args.data = Path(f"docs/data/ml_benchmark_{args.size}{suffix}.json")
    global STRATEGY, CACHE
    STRATEGY = args.strategy
    CACHE = args.cache
    if args.strategy == "adaptive":
        # Key derivation cost has no effect on the pixels; keep the run short.
        stego.SCRYPT_LOG_N = min(stego.SCRYPT_LOG_N_ACCEPTED)

    results = json.loads(args.data.read_text("utf-8")) if args.data.exists() else {}
    if not args.plot_only:
        covers = load_covers(args.covers, args.size, args.how, args.limit)
        share = share_rate(args.size)
        rates = sorted({float(r) for r in args.rates.split(",")} | {share}, reverse=True)
        print(f"{len(covers)} covers at {args.size}x{args.size}; one share = {share:.3%}")
        config = {
            "dataset": args.dataset,
            "images": len(covers),
            "size": args.size,
            "preprocessing": args.how,
            "share_rate": share,
            "seed": args.seed,
            "strategy": f"{args.strategy}: {STRATEGIES[args.strategy]}",
        }

        def same_experiment(old: dict) -> bool:
            # The strategy is compared by name: its description may be reworded.
            keys = [k for k in config if k != "strategy"]
            name = str(old.get("strategy", "")).split(":")[0]
            return name == args.strategy and all(old.get(k) == config[k] for k in keys)

        if results and not same_experiment(results):
            results = {}  # a different experiment: start over
        results.update(config)
        results.setdefault("detectors", {})
        chosen = [d.strip() for d in args.detectors.split(",") if d.strip()]
        detectors = results["detectors"]
        wanted = [d for d in chosen if d in FEATURE_DETECTORS]
        todo = [r for r in rates if args.rerun or any(not _has(detectors, d, r) for d in wanted)]

        scores_path = args.data.with_suffix(".scores.npz")
        scores: dict[str, np.ndarray] = dict(np.load(scores_path)) if scores_path.exists() else {}

        def save(rows_by_name: dict[str, list[dict]]) -> None:
            for name, rows in rows_by_name.items():
                if name in chosen:
                    detectors[name] = _merge(detectors.get(name, []), rows)
            args.data.parent.mkdir(parents=True, exist_ok=True)
            args.data.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
            np.savez_compressed(scores_path, **scores)

        if todo:
            save(run_features(covers, todo, args.seed, on_rate=save, scores=scores))
        if "cnn" in chosen:
            # Curriculum training depends on the whole sequence: always redone.
            detectors["cnn"] = run_cnn(
                covers,
                rates,
                args.seed,
                first_epochs=args.first_epochs,
                fine_epochs=args.fine_epochs,
                crop=args.crop,
                checkpoint=args.checkpoint,
            )
            results["cnn_training"] = {
                "first_epochs": args.first_epochs,
                "fine_epochs": args.fine_epochs,
                "crop": args.crop,
                "curriculum": "highest rate first, each rate fine-tuned from the previous",
            }
        args.data.parent.mkdir(parents=True, exist_ok=True)
        args.data.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"  wrote {args.data}")

    import matplotlib

    matplotlib.use("Agg")
    args.out.mkdir(parents=True, exist_ok=True)
    legacy_path = args.data.with_name(f"ml_benchmark_{args.size}.json")
    for mode in THEMES:
        print(f"  wrote {plot(results, args.out, mode)}")
        if args.strategy == "adaptive" and legacy_path.exists():
            legacy = json.loads(legacy_path.read_text("utf-8"))
            print(f"  wrote {plot_comparison(legacy, results, args.out, mode)}")
    print()
    print(markdown_table(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

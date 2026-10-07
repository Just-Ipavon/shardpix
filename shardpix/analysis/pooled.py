"""Pooled steganalysis: what an adversary gains from several images of one vault.

Steganalysis is usually evaluated one image at a time. A shardpix vault is
not one image: its n shares sit in n photos, and an adversary who seizes
several of them - or the photos of several holders - can combine the
evidence. Ker called this *pooled steganalysis*. This module measures it
for shardpix, from the per-image scores that
:mod:`shardpix.analysis.ml_benchmark` stores for its test images.

The adversary receives a group of ``g`` photographs, all different, and
must say whether they are a vault (every one carries a share) or ``g``
innocent photos. Two ways of combining the per-image scores are measured:

* **mean**: the average detector vote over the group, the obvious choice;
* **likelihood ratio**: the sum over the group of log P(score | stego) /
  P(score | cover), estimated on calibration images by a logistic
  regression on the score and its square. For independent images the
  likelihood ratio is the most powerful test there is (Neyman-Pearson), so
  this approximates the best any pooling of these scores can do.

The test images are split in two halves by image: one half calibrates the
likelihood ratio and the decision threshold, the other is used only for
evaluation, so no group is ever judged by a threshold fitted on it. The
split is repeated 40 times; the spread over splits is the interval.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

from . import ensemble
from .benchmark import THEMES, _finish, _style_axes

GROUP_SIZES = (1, 2, 3, 5, 10, 20, 50)
TRIALS = 10_000
SPLITS = 40


@dataclass
class PooledResult:
    group: int
    method: str
    p_e: float
    p_e_low: float
    p_e_high: float
    auc: float


def _llr_model(cal0: np.ndarray, cal1: np.ndarray, ridge: float = 1e-3) -> np.ndarray:
    """Logistic regression of the class on (1, score, score^2), fitted on calibration.

    With balanced classes the fitted log-odds is the log-likelihood ratio of
    a score. A quadratic in the score captures a shift and a change of
    spread between the two distributions, which is what ensemble votes
    show; it is far less noisy than a histogram of the vote levels.
    """
    x = np.concatenate([cal0, cal1]).astype(float)
    y = np.concatenate([np.zeros(cal0.size), np.ones(cal1.size)])
    centre, scale = x.mean(), x.std() or 1.0
    z = (x - centre) / scale
    design = np.stack([np.ones_like(z), z, z * z], axis=1)
    w = np.zeros(3)
    for _ in range(50):
        p = 1 / (1 + np.exp(-design @ w))
        gradient = design.T @ (p - y) + ridge * w
        hessian = (design * (p * (1 - p))[:, None]).T @ design + ridge * np.eye(3)
        step = np.linalg.solve(hessian, gradient)
        w -= step
        if np.max(np.abs(step)) < 1e-10:
            break
    return np.array([*w, centre, scale])


def _llr(scores: np.ndarray, model: np.ndarray) -> np.ndarray:
    w0, w1, w2, centre, scale = model
    z = (scores.astype(float) - centre) / scale
    return w0 + w1 * z + w2 * z * z


def _groups(n: int, g: int, trials: int, rng: np.random.Generator) -> np.ndarray:
    """``trials`` groups of ``g`` distinct indices below ``n``.

    Each random permutation is cut into ``n // g`` disjoint groups, so the
    cost is proportional to ``trials * g`` and no group repeats an image.
    """
    per = n // g
    if per == 0:
        raise ValueError("group is larger than the number of images")
    reps = -(-trials // per)
    cuts = [rng.permutation(n)[: per * g].reshape(per, g) for _ in range(reps)]
    return np.concatenate(cuts)[:trials]


def _statistic(values: np.ndarray, groups: np.ndarray) -> np.ndarray:
    return values[groups].sum(axis=1)


def _threshold(stat0: np.ndarray, stat1: np.ndarray) -> float:
    """Threshold with the lowest (P_FA + P_MD) / 2 on calibration groups."""
    candidates = np.unique(np.concatenate([stat0, stat1]))
    best, best_error = candidates[0], 1.0
    s0, s1 = np.sort(stat0), np.sort(stat1)
    for t in candidates:
        false_alarm = 1 - np.searchsorted(s0, t, side="left") / s0.size
        missed = np.searchsorted(s1, t, side="left") / s1.size
        error = (false_alarm + missed) / 2
        if error < best_error:
            best, best_error = t, error
    return float(best)


def _once(
    covers: np.ndarray,
    stegos: np.ndarray,
    group: int,
    method: str,
    trials: int,
    rng: np.random.Generator,
) -> tuple[float, float]:
    """One calibration/evaluation split: ``(P_E, AUC)`` on the evaluation half."""
    n = covers.size
    order = rng.permutation(n)
    cal, ev = order[: n // 2], order[n // 2 :]
    if method == "llr":
        model = _llr_model(covers[cal], stegos[cal])

        def transform(x: np.ndarray) -> np.ndarray:
            return _llr(x, model)
    else:

        def transform(x: np.ndarray) -> np.ndarray:
            return x.astype(float)

    def statistics(images: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        # Cover groups and stego groups are drawn from disjoint images.
        half = images.size // 2
        pick0 = _groups(half, group, trials, rng)
        pick1 = _groups(images.size - half, group, trials, rng)
        stat0 = _statistic(transform(covers[images[:half]]), pick0)
        stat1 = _statistic(transform(stegos[images[half:]]), pick1)
        return stat0, stat1

    threshold = _threshold(*statistics(cal))
    stat0, stat1 = statistics(ev)
    p_e = ensemble.decision_error(stat0 >= threshold, stat1 >= threshold)
    return p_e, ensemble.auc(stat0, stat1)


def pooled(
    covers: np.ndarray,
    stegos: np.ndarray,
    group: int,
    method: str,
    seed: int = 0,
    trials: int = TRIALS,
    splits: int = SPLITS,
) -> PooledResult:
    """Error of an adversary deciding on groups of ``group`` images.

    ``covers[i]`` and ``stegos[i]`` are the scores of test image ``i`` and of
    its stego version. Each of ``splits`` random splits calibrates on half
    the images (likelihood model and threshold) and evaluates on the other
    half; the result is the median over splits, with the 2.5-97.5
    percentile range as the interval.
    """
    if method not in ("mean", "llr"):
        raise ValueError("method must be 'mean' or 'llr'")
    if group > covers.size // 4:
        raise ValueError("group is too large for the number of test images")
    rng = np.random.default_rng(seed)
    runs = np.array([_once(covers, stegos, group, method, trials, rng) for _ in range(splits)])
    low, mid, high = np.percentile(runs[:, 0], [2.5, 50, 97.5])
    return PooledResult(
        group, method, float(mid), float(low), float(high), float(np.median(runs[:, 1]))
    )


# --------------------------------------------------------------------------- reporting


def _load(path: Path, detector: str, rate: float) -> tuple[np.ndarray, np.ndarray]:
    data = np.load(path)
    key = f"{detector}@{rate:.10f}"
    if key not in data:
        raise SystemExit(f"{path} has no scores for {key}: run ml_benchmark first")
    covers, stegos = data[key]
    return covers, stegos


def run(sources: dict[str, Path], rate: float, groups=GROUP_SIZES, seed: int = 0) -> dict:
    """Pooled error for every strategy, detector, method and group size."""
    results: dict = {"rate": rate, "groups": list(groups), "strategies": {}}
    for strategy, path in sources.items():
        per_detector = {}
        for detector in ("spam", "srm_lite"):
            covers, stegos = _load(path, detector, rate)
            rows = []
            for method in ("mean", "llr"):
                for g in groups:
                    r = pooled(covers, stegos, g, method, seed=seed)
                    rows.append(asdict(r))
                    print(
                        f"  {strategy:9s} {detector:9s} {method:4s} g={g:3d}: "
                        f"P_E {r.p_e:.3f} [{r.p_e_low:.3f}, {r.p_e_high:.3f}] AUC {r.auc:.3f}"
                    )
            per_detector[detector] = rows
        results["strategies"][strategy] = per_detector
    return results


LABELS = {"shardpix": "format 3 (matching)", "adaptive": "format 4 (adaptive)"}


def plot(results: dict, out: Path, mode: str, size: int) -> Path:
    import matplotlib.pyplot as plt
    from matplotlib.ticker import NullLocator

    theme = THEMES[mode]
    colours = {"shardpix": theme["series"]["replacement"], "adaptive": theme["series"]["shardpix"]}
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.subplots_adjust(left=0.1, right=0.95, top=0.8, bottom=0.13)
    _style_axes(ax, theme)
    ax.set_xscale("log")
    ax.axhline(50, color=theme["axis"], linewidth=1, linestyle="--", zorder=1)
    for strategy, per_detector in results["strategies"].items():
        rows = [r for r in per_detector["srm_lite"] if r["method"] == "llr"]
        g = np.array([r["group"] for r in rows])
        p_e = np.array([r["p_e"] for r in rows]) * 100
        low = np.array([r["p_e_low"] for r in rows]) * 100
        high = np.array([r["p_e_high"] for r in rows]) * 100
        colour = colours[strategy]
        ax.fill_between(g, low, high, color=colour, alpha=0.15, linewidth=0, zorder=2)
        ax.plot(
            g,
            p_e,
            color=colour,
            linewidth=2,
            marker="o",
            markersize=5,
            markeredgecolor=theme["surface"],
            label=LABELS[strategy],
            zorder=3,
        )
    ax.set_xticks(results["groups"])
    ax.set_xticklabels([str(g) for g in results["groups"]])
    ax.xaxis.set_minor_locator(NullLocator())
    ax.set_ylim(0, 56)
    ax.text(results["groups"][0] * 1.05, 51.5, "guessing", color=theme["muted"], fontsize=8.5)
    ax.set_xlabel(
        "Images of the same vault in the adversary's hands (log scale)",
        color=theme["secondary"],
        fontsize=9.5,
    )
    ax.set_ylabel("Detection error P_E (%)", color=theme["secondary"], fontsize=9.5)
    path = out / f"pooled-{size}-{mode}.png"
    _finish(
        fig,
        ax,
        theme,
        "Several images of one vault: pooled steganalysis",
        f"SRM-lite scores combined by likelihood ratio; one share per image, "
        f"{size}x{size} BOSSbase. Shaded: 2.5-97.5% over 40 splits.",
        path,
        legend_at="lower left",
    )
    plt.close(fig)
    return path


def markdown_table(results: dict, method: str = "llr") -> str:
    strategies = list(results["strategies"])
    header = (
        "| Images | "
        + " | ".join(f"{LABELS[s]}, {d}" for s in strategies for d in ("SPAM", "SRM-lite"))
        + " |"
    )
    rows = [header, "| ---: |" + " ---: |" * (2 * len(strategies))]
    for g in results["groups"]:
        cells = []
        for s in strategies:
            for d in ("spam", "srm_lite"):
                r = next(
                    r
                    for r in results["strategies"][s][d]
                    if r["group"] == g and r["method"] == method
                )
                cells.append(f"{r['p_e']:.1%} [{r['p_e_low']:.1%}, {r['p_e_high']:.1%}]")
        rows.append(f"| {g} | " + " | ".join(cells) + " |")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--size", type=int, default=512)
    parser.add_argument("--rate", type=float, default=None, help="default: one vault share")
    parser.add_argument("--data", type=Path, default=Path("docs/data"))
    parser.add_argument("--out", type=Path, default=Path("assets"))
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    sources = {
        "shardpix": args.data / f"ml_benchmark_{args.size}.scores.npz",
        "adaptive": args.data / f"ml_benchmark_{args.size}_adaptive.scores.npz",
    }
    sources = {k: v for k, v in sources.items() if v.exists()}
    if not sources:
        raise SystemExit("no score files: run ml_benchmark first")
    rate = args.rate
    if rate is None:
        meta = json.loads((args.data / f"ml_benchmark_{args.size}.json").read_text("utf-8"))
        rate = meta["share_rate"]
    results = run(sources, rate, seed=args.seed)
    results["size"] = args.size
    path = args.data / f"pooled_{args.size}.json"
    path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {path}")

    import matplotlib

    matplotlib.use("Agg")
    for mode in THEMES:
        print(f"  wrote {plot(results, args.out, mode, args.size)}")
    print()
    print(markdown_table(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

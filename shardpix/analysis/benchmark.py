"""Detectability benchmark: how visible is each embedding strategy to steganalysis?

Runs the chi-square and RS attacks against a set of cover photographs embedded
with four strategies at increasing embedding rates, measures the operating
point of a real vault share, and renders the charts and tables used in the
documentation.

Usage::

    pip install -e ".[bench]"
    python -m shardpix.analysis.benchmark            # scikit-image sample photos
    python -m shardpix.analysis.benchmark photos/*.png --out results/

The payload bits are random in every scenario, as they are in shardpix where
the payload is ciphertext.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

from .. import stego, vault
from ..images import Carrier, from_pil, load_image
from . import chi_square, rs

RATES = (0.0, 0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.75)
CHI_SQUARE_RATE = 0.5
SAMPLE_COVERS = (
    "astronaut",
    "chelsea",
    "coffee",
    "rocket",
    "hubble_deep_field",
    "immunohistochemistry",
    "camera",
    "brick",
    "grass",
    "gravel",
)
"""scikit-image sample images, all public domain or CC0."""


@dataclass(frozen=True)
class Scenario:
    key: str
    label: str
    method: stego.Method
    keyed: bool
    aware: bool


SCENARIOS = (
    Scenario(
        "shardpix",
        "shardpix (LSB matching, skips clipped samples)",
        stego.Method.MATCHING,
        keyed=True,
        aware=True,
    ),
    Scenario(
        "replacement",
        "LSB replacement, scattered",
        stego.Method.REPLACEMENT,
        keyed=True,
        aware=False,
    ),
    Scenario("matching", "LSB matching, naive", stego.Method.MATCHING, keyed=True, aware=False),
    Scenario(
        "sequential",
        "LSB replacement, sequential",
        stego.Method.REPLACEMENT,
        keyed=False,
        aware=False,
    ),
)
SCENARIO_BY_KEY = {s.key: s for s in SCENARIOS}


def load_covers(paths: Sequence[Path]) -> list[tuple[str, Carrier]]:
    """Load covers from disk, or the scikit-image sample photos when none are given."""
    if paths:
        return [(Path(p).stem, load_image(p)) for p in paths]
    try:
        from PIL import Image
        from skimage import data
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise SystemExit(
            "install the bench extra (pip install -e '.[bench]') or pass covers"
        ) from exc
    return [(name, from_pil(Image.fromarray(getattr(data, name)()))) for name in SAMPLE_COVERS]


def embed_random(
    carrier: Carrier, rate: float, scenario: Scenario, rng: np.random.Generator
) -> np.ndarray:
    """Embed random bits in ``rate`` of the samples following ``scenario``; return the pixels."""
    samples = carrier.samples()
    eligible = stego.eligible_mask(samples) if scenario.aware else None
    if scenario.keyed:
        order = stego.SampleOrder(rng.bytes(32), samples.size, eligible)
        count = min(int(round(rate * samples.size)), order.n_samples)
        positions = order.first(count)
    else:
        count = int(round(rate * samples.size))
        positions = np.arange(count)
    bits = rng.integers(0, 2, positions.size).astype(np.uint8)
    bounds = {"low": stego.ELIGIBLE_MIN, "high": stego.ELIGIBLE_MAX} if scenario.aware else {}
    out, _ = stego.write_bits(
        samples, positions, bits, scenario.method, lambda n: rng.bytes(n), **bounds
    )
    return carrier.with_samples(out).pixels


def rs_rate(pixels: np.ndarray, channels: int) -> float:
    return rs.mean_rate(rs.estimate(pixels, channels))


@dataclass
class OperatingPoint:
    """What a real vault share does to one cover."""

    cover: str
    width: int
    height: int
    channels: int
    share_rate: float
    rs_clean: float
    rs_share: float
    chi_prefix_clean: float
    chi_prefix_share: float


def operating_point(name: str, carrier: Carrier) -> OperatingPoint:
    share = bytes(vault.SHARE_BYTES)  # content is irrelevant: the frame is ciphertext
    stego_carrier, report = stego.embed(carrier, share, "benchmark passphrase")
    channels = carrier.colour_channels
    height, width, _ = carrier.geometry
    return OperatingPoint(
        cover=name,
        width=width,
        height=height,
        channels=channels,
        share_rate=report.embedding_rate,
        rs_clean=rs_rate(carrier.pixels, channels),
        rs_share=rs_rate(stego_carrier.pixels, channels),
        chi_prefix_clean=chi_square.sequential_attack(carrier.samples(), 50).detected_prefix(),
        chi_prefix_share=chi_square.sequential_attack(
            stego_carrier.samples(), 50
        ).detected_prefix(),
    )


def run(covers: list[tuple[str, Carrier]], seed: int = 0) -> dict:
    """Run every experiment and return the raw results as plain data."""
    rng = np.random.default_rng(seed)
    sweep: dict[str, dict[str, list[float]]] = {s.key: {} for s in SCENARIOS}
    for name, carrier in covers:
        channels = carrier.colour_channels
        for scenario in SCENARIOS:
            sweep[scenario.key][name] = [
                rs_rate(embed_random(carrier, rate, scenario, rng), channels) for rate in RATES
            ]
        print(f"  RS sweep: {name}")

    reference_name, reference = next(((n, c) for n, c in covers if n == "coffee"), covers[0])
    curves = {"clean": chi_square.sequential_attack(reference.samples(), 100).p_values.tolist()}
    for key in ("sequential", "replacement", "shardpix"):
        pixels = embed_random(reference, CHI_SQUARE_RATE, SCENARIO_BY_KEY[key], rng)
        flat = pixels[..., : reference.colour_channels].reshape(-1)
        curves[key] = chi_square.sequential_attack(flat, 100).p_values.tolist()

    points = [asdict(operating_point(name, carrier)) for name, carrier in covers]
    return {
        "rates": list(RATES),
        "rs_sweep": sweep,
        "chi_square": {"cover": reference_name, "rate": CHI_SQUARE_RATE, "curves": curves},
        "operating_points": points,
        "covers": [name for name, _ in covers],
    }


# --------------------------------------------------------------------------- rendering

THEMES: dict[str, dict] = {
    "light": {
        "surface": "#fcfcfb",
        "ink": "#0b0b0b",
        "secondary": "#52514e",
        "muted": "#898781",
        "grid": "#e1e0d9",
        "axis": "#c3c2b7",
        "series": {
            "shardpix": "#2a78d6",
            "replacement": "#eb6834",
            "matching": "#1baf7a",
            "sequential": "#eda100",
            "clean": "#898781",
        },
    },
    "dark": {
        "surface": "#1a1a19",
        "ink": "#ffffff",
        "secondary": "#c3c2b7",
        "muted": "#898781",
        "grid": "#2c2c2a",
        "axis": "#383835",
        "series": {
            "shardpix": "#3987e5",
            "replacement": "#d95926",
            "matching": "#199e70",
            "sequential": "#c98500",
            "clean": "#898781",
        },
    },
}


def _style_axes(ax, theme: dict) -> None:
    ax.set_facecolor(theme["surface"])
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(theme["axis"])
        ax.spines[side].set_linewidth(1)
    ax.tick_params(colors=theme["muted"], labelcolor=theme["secondary"], length=0, pad=6)
    ax.grid(True, color=theme["grid"], linewidth=1, linestyle="-")
    ax.set_axisbelow(True)


def _finish(
    fig, ax, theme: dict, title: str, subtitle: str, path: Path, legend_at: str = "upper left"
) -> None:
    fig.patch.set_facecolor(theme["surface"])
    fig.text(0.06, 0.95, title, color=theme["ink"], fontsize=13, fontweight="bold", va="top")
    fig.text(0.06, 0.895, subtitle, color=theme["secondary"], fontsize=9.5, va="top")
    legend = ax.legend(
        loc=legend_at,
        frameon=False,
        fontsize=9,
        labelcolor=theme["secondary"],
        handlelength=1.6,
    )
    legend.set_zorder(5)
    fig.savefig(path, dpi=200, facecolor=theme["surface"])


def _rs_axes(theme: dict, rates: np.ndarray):
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.subplots_adjust(left=0.1, right=0.86, top=0.8, bottom=0.13)
    _style_axes(ax, theme)
    ax.plot(rates, rates, color=theme["axis"], linewidth=1, zorder=1)
    ax.text(
        rates[-1] * 0.62,
        rates[-1] * 0.62 + 4,
        "perfect estimate",
        color=theme["muted"],
        fontsize=8.5,
        rotation=33,
        rotation_mode="anchor",
        ha="center",
    )
    ax.set_xlim(0, rates[-1])
    ax.set_ylim(-10, 85)
    ax.set_xlabel("Samples carrying payload bits (%)", color=theme["secondary"], fontsize=9.5)
    ax.set_ylabel("Embedding rate estimated by RS (%)", color=theme["secondary"], fontsize=9.5)
    return fig, ax


def _rs_series(
    ax, theme: dict, rates: np.ndarray, values: np.ndarray, key: str, *, label_end: bool
) -> None:
    """One line (the mean over covers), its min-max wash, and an optional end label."""
    colour = theme["series"][key]
    mean = values.mean(axis=0)
    if values.shape[0] > 1:
        ax.fill_between(
            rates,
            values.min(axis=0),
            values.max(axis=0),
            color=colour,
            alpha=0.10,
            linewidth=0,
            zorder=2,
        )
    ax.plot(
        rates,
        mean,
        color=colour,
        linewidth=2,
        solid_capstyle="round",
        zorder=3,
        label=SCENARIO_BY_KEY[key].label,
    )
    ax.plot(
        rates[-1],
        mean[-1],
        "o",
        color=colour,
        markersize=8,
        markeredgecolor=theme["surface"],
        markeredgewidth=2,
        zorder=4,
        clip_on=False,
    )
    if label_end:
        ax.annotate(
            f"{mean[-1]:.0f}%",
            (rates[-1], mean[-1]),
            xytext=(10, 0),
            textcoords="offset points",
            va="center",
            color=theme["ink"],
            fontsize=9,
            annotation_clip=False,
        )


def plot_rs(results: dict, out: Path, mode: str) -> Path:
    import matplotlib.pyplot as plt

    theme = THEMES[mode]
    rates = np.array(results["rates"]) * 100
    fig, ax = _rs_axes(theme, rates)
    for key in ("replacement", "shardpix"):
        values = np.array(list(results["rs_sweep"][key].values())) * 100
        _rs_series(ax, theme, rates, values, key, label_end=True)
    path = out / f"rs-estimate-{mode}.png"
    _finish(
        fig,
        ax,
        theme,
        "RS steganalysis measures LSB replacement, not shardpix",
        f"Mean over {len(results['covers'])} photographs, shaded from min to max. "
        "A vault share uses 0.05-0.5% of the samples.",
        path,
    )
    plt.close(fig)
    return path


def plot_rs_clipped(results: dict, out: Path, mode: str, cover: str = "astronaut") -> Path:
    import matplotlib.pyplot as plt

    theme = THEMES[mode]
    rates = np.array(results["rates"]) * 100
    fig, ax = _rs_axes(theme, rates)
    for key in ("replacement", "matching", "shardpix"):
        values = np.array([results["rs_sweep"][key][cover]]) * 100
        _rs_series(ax, theme, rates, values, key, label_end=True)
    path = out / f"rs-clipped-{mode}.png"
    _finish(
        fig,
        ax,
        theme,
        "On clipped photos, naive LSB matching leaks",
        f"'{cover}': pure-black samples can only move up, which RS reads as replacement.",
        path,
    )
    plt.close(fig)
    return path


def plot_chi_square(results: dict, out: Path, mode: str) -> Path:
    import matplotlib.pyplot as plt

    theme = THEMES[mode]
    data = results["chi_square"]
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.subplots_adjust(left=0.1, right=0.8, top=0.8, bottom=0.13)
    _style_axes(ax, theme)
    labels = {
        "sequential": "LSB replacement, sequential",
        "replacement": "LSB replacement, scattered",
        "shardpix": "shardpix",
        "clean": "clean cover",
    }
    for key in ("sequential", "replacement", "shardpix", "clean"):
        values = np.array(data["curves"][key])
        x = np.linspace(1, 100, values.size)
        colour = theme["series"][key]
        ax.plot(
            x,
            values,
            color=colour,
            linewidth=2,
            solid_capstyle="round",
            label=labels[key],
            zorder=3 if key != "clean" else 2,
        )
    ax.axvline(data["rate"] * 100, color=theme["axis"], linewidth=1, zorder=1)
    ax.text(
        data["rate"] * 100,
        1.04,
        " end of the sequential payload",
        color=theme["muted"],
        fontsize=8.5,
        va="bottom",
    )
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.03, 1.1)
    ax.set_xlabel(
        "Share of the image scanned, from the top (%)", color=theme["secondary"], fontsize=9.5
    )
    ax.set_ylabel("Chi-square probability of embedding", color=theme["secondary"], fontsize=9.5)
    _finish(
        fig,
        ax,
        theme,
        "The chi-square attack catches sequential embedding",
        f"'{data['cover']}' with {data['rate']:.0%} of the samples carrying random bits.",
        out / f"chi-square-{mode}.png",
        legend_at="center right",
    )
    plt.close(fig)
    return out / f"chi-square-{mode}.png"


def plot_lsb_planes(covers: list[tuple[str, Carrier]], out: Path, seed: int = 0) -> Path:
    """The visual attack: least significant bit plane of the red channel, side by side."""
    import matplotlib.pyplot as plt

    rng = np.random.default_rng(seed)
    name, carrier = next(((n, c) for n, c in covers if n == "camera"), covers[0])
    sequential = embed_random(carrier, 0.5, SCENARIO_BY_KEY["sequential"], rng)
    shardpix, _ = stego.embed(carrier, bytes(vault.SHARE_BYTES), "benchmark passphrase")
    panels = [
        ("Clean cover", carrier.pixels),
        ("Naive tool: 50% sequential", sequential),
        ("shardpix: one vault share", shardpix.pixels),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(10, 3.9))
    fig.patch.set_facecolor("#fcfcfb")
    for ax, (title, pixels) in zip(axes, panels, strict=True):
        plane = (pixels[..., 0] & 1).astype(np.uint8) * 255
        ax.imshow(plane, cmap="gray", vmin=0, vmax=255, interpolation="nearest")
        ax.set_title(title, color="#0b0b0b", fontsize=10.5, pad=8)
        ax.axis("off")
    height, width, _ = carrier.geometry
    fig.text(
        0.5,
        0.03,
        f"Least significant bit plane of '{name}' ({width} x {height}), black = 0, white = 1.",
        ha="center",
        color="#52514e",
        fontsize=9,
    )
    fig.subplots_adjust(left=0.01, right=0.99, top=0.88, bottom=0.1, wspace=0.04)
    path = out / "lsb-planes.png"
    fig.savefig(path, dpi=150, facecolor="#fcfcfb")
    plt.close(fig)
    return path


def markdown_table(results: dict) -> str:
    """Operating-point table in Markdown, as used in the security analysis document."""
    rows = [
        "| Cover | Size | Share embedding rate | RS, clean | RS, with share | Change |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for p in results["operating_points"]:
        kind = "RGB" if p["channels"] == 3 else "grey"
        rows.append(
            f"| {p['cover']} | {p['width']}x{p['height']} {kind} | {p['share_rate']:.3%} "
            f"| {p['rs_clean']:+.2%} | {p['rs_share']:+.2%} "
            f"| {p['rs_share'] - p['rs_clean']:+.2%} |"
        )
    return "\n".join(rows)


def sweep_table(results: dict) -> str:
    """Mean RS estimate per scenario and rate, in Markdown."""
    picked = [0.0, 0.05, 0.1, 0.2, 0.5, 0.75]
    index = [results["rates"].index(r) for r in picked]
    header = "| Strategy | " + " | ".join(f"{r:.0%}" for r in picked) + " |"
    rows = [header, "| --- |" + " ---: |" * len(picked)]
    for key in ("replacement", "matching", "shardpix"):
        values = np.array(list(results["rs_sweep"][key].values()))
        mean = values.mean(axis=0)
        cells = " | ".join(f"{mean[i]:+.1%}" for i in index)
        rows.append(f"| {SCENARIO_BY_KEY[key].label} | {cells} |")
    return "\n".join(rows)


def per_cover_table(results: dict, rate: float = 0.5) -> str:
    """RS estimate for every cover at one embedding rate, naive matching vs shardpix."""
    i = results["rates"].index(rate)
    rows = [
        "| Cover | Clean | LSB replacement | LSB matching, naive | shardpix |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for cover in results["covers"]:
        sweep = results["rs_sweep"]
        rows.append(
            f"| {cover} | {sweep['shardpix'][cover][0]:+.1%} "
            f"| {sweep['replacement'][cover][i]:+.1%} "
            f"| {sweep['matching'][cover][i]:+.1%} "
            f"| {sweep['shardpix'][cover][i]:+.1%} |"
        )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("covers", nargs="*", type=Path, help="cover images (default: samples)")
    parser.add_argument("--out", type=Path, default=Path("assets"), help="where charts go")
    parser.add_argument(
        "--data", type=Path, default=Path("docs/data/benchmark.json"), help="raw results (JSON)"
    )
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    covers = load_covers(args.covers)
    print(f"Benchmarking {len(covers)} covers")
    results = run(covers, seed=args.seed)

    import matplotlib

    matplotlib.use("Agg")
    args.out.mkdir(parents=True, exist_ok=True)
    for mode in THEMES:
        print(f"  wrote {plot_rs(results, args.out, mode)}")
        print(f"  wrote {plot_rs_clipped(results, args.out, mode)}")
        print(f"  wrote {plot_chi_square(results, args.out, mode)}")
    print(f"  wrote {plot_lsb_planes(covers, args.out, seed=args.seed)}")

    args.data.parent.mkdir(parents=True, exist_ok=True)
    args.data.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {args.data}\n")
    print(sweep_table(results))
    print()
    print(per_cover_table(results))
    print()
    print(markdown_table(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

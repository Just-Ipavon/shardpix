"""Command line interface."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__, shamir, stego
from .analysis import chi_square
from .errors import ShardpixError, ShareError, ShareFormatError
from .images import load_image, save_png

DESCRIPTION = "Hide authenticated, encrypted payloads in ordinary-looking PNG images."

CHI_SQUARE_ALERT = 0.10
"""Detected prefix (fraction of the image) above which the chi-square attack is reported."""


# --------------------------------------------------------------------------- helpers


def make_console(*, stderr: bool = False) -> Console:
    """Console used for every message: no syntax highlighting, no hard wrapping."""
    return Console(stderr=stderr, highlight=False, soft_wrap=True)


def read_passphrase(args: argparse.Namespace, *, confirm: bool) -> str | None:
    """Return the passphrase selected on the command line, or ``None``.

    Passphrases are never accepted as plain arguments: they would end up in
    shell history and in the process list.
    """
    if getattr(args, "passphrase_file", None):
        path: Path = args.passphrase_file
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ShardpixError(f"cannot read passphrase file {path}: {exc.strerror}") from exc
        if not lines or not lines[0]:
            raise ShardpixError(f"passphrase file {path} is empty")
        return lines[0]
    if getattr(args, "passphrase", False):
        first = getpass.getpass("Passphrase: ")
        if not first:
            raise ShardpixError("empty passphrase")
        if confirm and getpass.getpass("Repeat passphrase: ") != first:
            raise ShardpixError("passphrases do not match")
        return first
    return None


def check_output(path: Path, *, force: bool, inputs: tuple[Path, ...] = ()) -> None:
    """Refuse to overwrite an input, or an existing file without ``--force``."""
    resolved = path.resolve()
    if any(resolved == p.resolve() for p in inputs):
        raise ShardpixError(f"{path} is also an input; choose a different output path")
    if path.exists() and not force:
        raise ShardpixError(f"{path} already exists; use --force to overwrite it")


def format_bytes(size: int) -> str:
    """Human-readable size: ``1536`` -> ``1.5 KiB``."""
    value = float(size)
    for unit in ("B", "KiB", "MiB"):
        if value < 1024 or unit == "MiB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def _key_value_table(title: str, rows: list[tuple[str, str]]) -> Table:
    table = Table(title=title, show_header=False, title_justify="left", box=None, padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column()
    for key, value in rows:
        table.add_row(key, value)
    return table


def positive_int(value: str) -> int:
    """argparse type for strictly positive integers."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an integer: {value}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def read_secret(args: argparse.Namespace) -> bytes:
    """Return the bytes given with ``--text`` or ``--input``."""
    if args.input is not None:
        try:
            return args.input.read_bytes()
        except OSError as exc:
            raise ShardpixError(f"cannot read {args.input}: {exc.strerror}") from exc
    return args.text.encode("utf-8")


def read_shares(sources: list[str]) -> tuple[list[shamir.Share], list[tuple[str, str]]]:
    """Parse shares from files (or ``-`` for stdin), one share per line.

    Blank lines and lines starting with ``#`` are ignored. Malformed shares are
    returned as ``(origin, reason)`` pairs instead of aborting the whole run:
    one damaged share should not hide the others.
    """
    shares: list[shamir.Share] = []
    problems: list[tuple[str, str]] = []
    for source in sources:
        try:
            text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ShardpixError(f"cannot read shares from {source}: {exc}") from exc
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            origin = "stdin" if source == "-" else source
            try:
                shares.append(shamir.Share.from_text(line))
            except ShareFormatError as exc:
                problems.append((f"{origin}:{number}", str(exc)))
    return shares, problems


def _share_label(share: shamir.Share) -> str:
    return f"#{share.index} ({share.group})"


def _add_passphrase_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--passphrase", action="store_true", help="prompt for a passphrase")
    group.add_argument(
        "--passphrase-file",
        type=Path,
        metavar="FILE",
        help="read the passphrase from the first line of FILE",
    )


# --------------------------------------------------------------------------- commands


def cmd_capacity(args: argparse.Namespace, console: Console) -> int:
    carrier = load_image(args.image)
    height, width, channels = carrier.geometry
    room = stego.capacity(carrier.n_samples)
    console.print(
        _key_value_table(
            str(args.image),
            [
                ("Dimensions", f"{width} x {height}"),
                (
                    "Mode",
                    f"{carrier.mode} ({channels} colour channel{'s' if channels > 1 else ''})",
                ),
                ("Carrier samples", f"{carrier.n_samples:,}"),
                ("Capacity", f"{room:,} bytes ({format_bytes(room)})"),
            ],
        )
    )
    return 0


def cmd_embed(args: argparse.Namespace, console: Console) -> int:
    check_output(args.output, force=args.force, inputs=(args.cover,))
    payload = read_secret(args)
    carrier = load_image(args.cover)
    passphrase = read_passphrase(args, confirm=True)
    stego_carrier, report = stego.embed(carrier, payload, passphrase, stego.Method(args.method))
    save_png(stego_carrier, args.output)

    console.print(
        _key_value_table(
            f"Embedded into {args.output}",
            [
                ("Payload", f"{report.payload_bytes:,} bytes"),
                (
                    "Frame",
                    f"{report.frame_bytes:,} bytes (payload + {stego.FRAME_OVERHEAD} overhead)",
                ),
                ("Capacity", f"{report.capacity_bytes:,} bytes"),
                ("Method", args.method),
                ("Embedding rate", f"{report.embedding_rate:.4%} of samples"),
                ("Samples changed", f"{report.samples_changed:,} ({report.change_rate:.4%})"),
                ("Passphrase", "yes" if passphrase else "no"),
            ],
        )
    )
    if not passphrase:
        console.print(
            "[yellow]warning:[/] no passphrase - anyone running shardpix can locate and "
            "read this payload"
        )
    return 0


def cmd_extract(args: argparse.Namespace, console: Console) -> int:
    if args.output is not None:
        check_output(args.output, force=args.force, inputs=(args.image,))
    carrier = load_image(args.image)
    payload = stego.extract(carrier, read_passphrase(args, confirm=False))
    if args.output is None:
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        return 0
    args.output.write_bytes(payload)
    console.print(f"Extracted {len(payload):,} bytes to [bold]{escape(str(args.output))}[/]")
    return 0


def cmd_analyze(args: argparse.Namespace, console: Console) -> int:
    carrier = load_image(args.image)
    samples = carrier.samples()
    whole = chi_square.pair_test(samples)
    curve = chi_square.sequential_attack(samples, steps=args.steps)
    prefix = curve.detected_prefix()

    rows = [
        ("Samples analysed", f"{samples.size:,}"),
        (
            "Chi-square, whole image",
            f"p = {whole.p_value:.4f} (statistic {whole.statistic:.1f}, {whole.dof} dof)",
        ),
        ("Chi-square, sequential", f"embedding signature over the first {prefix:.0%} of the image"),
    ]
    console.print(_key_value_table(f"Steganalysis of {args.image}", rows))
    if prefix >= CHI_SQUARE_ALERT:
        console.print(
            f"[bold red]Sequential LSB replacement detected[/] in roughly the first {prefix:.0%} "
            "of the image."
        )
    else:
        console.print(
            "[green]No sequential LSB replacement detected.[/] A negative result is not proof "
            "that the image is clean."
        )
    return 0


def cmd_split(args: argparse.Namespace, console: Console) -> int:
    secret = read_secret(args)
    if not secret:
        raise ShardpixError("the secret is empty")
    if len(secret) > shamir.MAX_SECRET_BYTES:
        raise ShardpixError(
            f"secret is {len(secret):,} bytes; split handles at most {shamir.MAX_SECRET_BYTES:,}. "
            "Use 'shardpix seal' for files: it encrypts the file and splits only its key"
        )
    if not 2 <= args.threshold <= args.shares:
        raise ShardpixError("the threshold must be at least 2 and at most the number of shares")
    shares = shamir.split(secret, args.threshold, args.shares)

    if args.directory is None:
        sys.stdout.write("".join(share.to_text() + "\n" for share in shares))
        return 0

    args.directory.mkdir(parents=True, exist_ok=True)
    paths = [args.directory / f"share-{s.group}-{s.index}.txt" for s in shares]
    for path in paths:
        check_output(path, force=args.force)
    for share, path in zip(shares, paths, strict=True):
        path.write_text(share.to_text() + "\n", encoding="utf-8")

    console.print(
        f"Split {len(secret):,} bytes into {len(shares)} shares; "
        f"any {args.threshold} recover the secret."
    )
    for path in paths:
        console.print(f"  {escape(str(path))}")
    return 0


def cmd_combine(args: argparse.Namespace, console: Console) -> int:
    if args.output is not None:
        check_output(args.output, force=args.force)
    shares, problems = read_shares(args.shares)
    report = console if args.output is not None else make_console(stderr=True)
    for origin, reason in problems:
        report.print(f"[yellow]skipped[/] {escape(origin)}: {escape(reason)}")

    recovery = shamir.combine(shares)

    used = ", ".join(_share_label(s) for s in recovery.used)
    report.print(
        f"Recovered {len(recovery.secret):,} bytes with threshold {recovery.threshold} "
        f"from shares {used}"
    )
    if recovery.confirmed:
        confirmed = ", ".join(_share_label(s) for s in recovery.confirmed)
        report.print(f"[green]also verified[/] {confirmed}")
    for rejection in recovery.rejected:
        report.print(
            f"[red]rejected[/] {_share_label(rejection.share)}: {escape(rejection.reason)}"
        )

    if args.output is None:
        sys.stdout.buffer.write(recovery.secret)
        sys.stdout.buffer.flush()
    else:
        args.output.write_bytes(recovery.secret)
        report.print(f"Secret written to [bold]{escape(str(args.output))}[/]")
    return 0


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shardpix", description=DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"shardpix {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("capacity", help="show how many bytes an image can hide")
    p.add_argument("image", type=Path)
    p.set_defaults(handler=cmd_capacity)

    p = sub.add_parser("embed", help="hide a message or a file in an image")
    p.add_argument("cover", type=Path, help="cover image (PNG, JPEG, BMP, ...)")
    p.add_argument("-o", "--output", type=Path, required=True, help="stego image to write (.png)")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("-t", "--text", help="text message to hide")
    source.add_argument("-i", "--input", type=Path, metavar="FILE", help="file to hide")
    p.add_argument(
        "-m",
        "--method",
        choices=[m.value for m in stego.Method],
        default=stego.Method.MATCHING.value,
        help="how samples are changed (default: matching)",
    )
    _add_passphrase_options(p)
    p.add_argument("-f", "--force", action="store_true", help="overwrite the output file")
    p.set_defaults(handler=cmd_embed)

    p = sub.add_parser("extract", help="recover a message or a file from an image")
    p.add_argument("image", type=Path)
    p.add_argument("-o", "--output", type=Path, help="write the payload here instead of stdout")
    _add_passphrase_options(p)
    p.add_argument("-f", "--force", action="store_true", help="overwrite the output file")
    p.set_defaults(handler=cmd_extract)

    p = sub.add_parser("analyze", help="run steganalysis attacks against an image")
    p.add_argument("image", type=Path)
    p.add_argument(
        "--steps", type=positive_int, default=100, help="prefixes tested by the sequential attack"
    )
    p.set_defaults(handler=cmd_analyze)

    p = sub.add_parser("split", help="split a secret into shares (Shamir, k of n)")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("-t", "--text", help="text secret to split")
    source.add_argument("-i", "--input", type=Path, metavar="FILE", help="file to split")
    p.add_argument(
        "-k", "--threshold", type=positive_int, required=True, help="shares needed to recover"
    )
    p.add_argument("-n", "--shares", type=positive_int, required=True, help="shares to create")
    p.add_argument(
        "-d", "--directory", type=Path, help="write one file per share here instead of stdout"
    )
    p.add_argument("-f", "--force", action="store_true", help="overwrite existing share files")
    p.set_defaults(handler=cmd_split)

    p = sub.add_parser("combine", help="recover a secret from its shares")
    p.add_argument(
        "shares", nargs="+", metavar="FILE", help="files holding shares, one per line ('-' = stdin)"
    )
    p.add_argument("-o", "--output", type=Path, help="write the secret here instead of stdout")
    p.add_argument("-f", "--force", action="store_true", help="overwrite the output file")
    p.set_defaults(handler=cmd_combine)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = make_console()
    errors = make_console(stderr=True)
    handler: Callable[[argparse.Namespace, Console], int] = args.handler
    try:
        return handler(args, console)
    except ShardpixError as exc:
        if isinstance(exc, ShareError):
            for rejection in exc.rejected:
                errors.print(
                    f"[red]rejected[/] {_share_label(rejection.share)}: {escape(rejection.reason)}"
                )
        errors.print(f"[bold red]error:[/] {escape(str(exc))}")
        return 1
    except KeyboardInterrupt:
        errors.print("interrupted")
        return 130

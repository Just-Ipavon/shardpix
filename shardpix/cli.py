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

from . import __version__, shamir, stego, vault
from .analysis import chi_square, rs
from .errors import ShardpixError, ShareError, ShareFormatError, VaultError
from .images import load_image, save_png, write_new

DESCRIPTION = (
    "Encrypt a file and split its key into shares hidden in ordinary-looking images: "
    "any k of n images open it."
)

CHI_SQUARE_ALERT = 0.10
"""Detected prefix (fraction of the image) above which the chi-square attack is reported."""

JPEG_WARNING = (
    "[yellow]warning:[/] {names} decoded from JPEG. Changing a decoded JPEG by +-1 breaks its "
    "8x8 block structure, which JPEG-compatibility steganalysis can detect at any rate; "
    "prefer covers that were never JPEG-compressed (PNG screenshots, RAW exports)."
)

REPLACEMENT_WARNING = (
    "[yellow]warning:[/] --method replacement is detectable by chi-square and RS analysis; "
    "it exists for comparisons, use the default for anything real."
)

RS_ALERT = 0.10
"""RS estimate above which LSB replacement is reported; clean photos measured -2.5% to +8.3%."""

_STATUS_STYLE = {
    vault.Status.USED: "green",
    vault.Status.VERIFIED: "green",
    vault.Status.UNVERIFIED: "yellow",
    vault.Status.REJECTED: "red",
    vault.Status.DUPLICATE: "yellow",
    vault.Status.NO_PAYLOAD: "yellow",
    vault.Status.OTHER_VAULT: "yellow",
    vault.Status.UNREADABLE: "red",
}


# --------------------------------------------------------------------------- helpers


def make_console(*, stderr: bool = False) -> Console:
    """Console used for every message.

    Word-wrapped in a terminal; unwrapped when piped, so output stays greppable.
    """
    stream = sys.stderr if stderr else sys.stdout
    return Console(stderr=stderr, highlight=False, soft_wrap=not stream.isatty())


def read_passphrase(args: argparse.Namespace, *, confirm: bool) -> str | None:
    """Return the passphrase selected on the command line, or ``None``.

    Passphrases are never accepted as plain arguments: they would end up in
    shell history and in the process list.
    """
    if getattr(args, "passphrase_file", None):
        path: Path = args.passphrase_file
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except OSError as exc:
            raise ShardpixError(f"cannot read passphrase file {path}: {exc.strerror}") from exc
        except UnicodeDecodeError as exc:
            raise ShardpixError(f"passphrase file {path} is not valid UTF-8") from exc
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
    if path.is_dir():
        raise ShardpixError(f"{path} is a directory; give a file name")
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
    table = Table(
        title=escape(title), show_header=False, title_justify="left", box=None, padding=(0, 2)
    )
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
    room = stego.carrier_capacity(carrier)
    usable = int(stego.eligible_mask(carrier.samples()).sum())
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
                (
                    "Usable samples",
                    f"{usable:,} (values {stego.ELIGIBLE_MIN}-{stego.ELIGIBLE_MAX})",
                ),
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
    save_png(stego_carrier, args.output, overwrite=args.force)

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
    if carrier.from_jpeg:
        console.print(JPEG_WARNING.format(names=f"{escape(str(args.cover))} was"))
    if args.method == stego.Method.REPLACEMENT.value:
        console.print(REPLACEMENT_WARNING)
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
    write_new(args.output, payload, overwrite=args.force)
    console.print(f"Extracted {len(payload):,} bytes to [bold]{escape(str(args.output))}[/]")
    return 0


def cmd_analyze(args: argparse.Namespace, console: Console) -> int:
    carrier = load_image(args.image)
    samples = carrier.samples()
    whole = chi_square.pair_test(samples)
    curve = chi_square.sequential_attack(samples, steps=args.steps)
    prefix = curve.detected_prefix()
    height, width, _ = carrier.geometry
    if width >= rs.GROUP_SIZE:
        channels = rs.estimate(carrier.pixels, carrier.colour_channels)
        rate = rs.mean_rate(channels)
        names = "RGB" if len(channels) == 3 else "L"
        per_channel = ", ".join(f"{n} {r.rate:+.1%}" for n, r in zip(names, channels, strict=True))
        rs_text = f"estimated embedding rate {rate:+.1%} ({per_channel})"
    else:
        rate, rs_text = 0.0, "not applicable (image narrower than 4 pixels)"

    rows = [
        ("Samples analysed", f"{samples.size:,}"),
        (
            "Chi-square, whole image",
            f"p = {whole.p_value:.4f} (statistic {whole.statistic:.1f}, {whole.dof} dof)",
        ),
        ("Chi-square, sequential", f"signature over the first {prefix:.0%} of the image"),
        ("RS analysis", rs_text),
    ]
    console.print(_key_value_table(f"Steganalysis of {args.image}", rows))

    findings = []
    if rate >= RS_ALERT:
        findings.append(f"RS suggests LSB replacement in about {rate:.0%} of the samples")
    if prefix >= CHI_SQUARE_ALERT:
        findings.append(
            f"chi-square suggests sequential LSB replacement over the first {prefix:.0%}"
        )
    if findings:
        console.print("[bold red]Suspicious:[/] " + "; ".join(findings) + ".")
    else:
        console.print("[green]No LSB replacement detected.[/]")
        console.print(
            "A negative result is not proof of a clean image: LSB matching, which shardpix "
            "uses, is built to evade both attacks."
        )
    return 0


def _outcome_table(outcomes: tuple[vault.ImageOutcome, ...]) -> Table:
    table = Table(title_justify="left", box=None, padding=(0, 2))
    table.add_column("Image", style="bold")
    table.add_column("Share", justify="right")
    table.add_column("Status")
    table.add_column("Detail")
    for outcome in outcomes:
        style = _STATUS_STYLE.get(outcome.status, "")
        table.add_row(
            escape(str(outcome.path)),
            "" if outcome.share_index is None else f"#{outcome.share_index}",
            f"[{style}]{outcome.status}[/]" if style else outcome.status,
            escape(outcome.detail),
        )
    return table


def cmd_seal(args: argparse.Namespace, console: Console) -> int:
    passphrase = read_passphrase(args, confirm=True)
    result = vault.seal(
        args.file,
        args.covers,
        args.threshold,
        args.directory,
        passphrase,
        method=stego.Method(args.method),
        vault_name=args.name,
        force=args.force,
    )
    header = result.header
    console.print(
        f"Sealed [bold]{escape(str(args.file))}[/] ({format_bytes(result.plaintext_bytes)}) "
        f"into [bold]{escape(str(result.vault_path))}[/]"
    )
    console.print(
        f"Vault {header.group}: any {header.threshold} of these {header.shares} images open it"
    )
    table = Table(box=None, padding=(0, 2))
    table.add_column("Image", style="bold")
    table.add_column("Share", justify="right")
    table.add_column("Embedding rate", justify="right")
    table.add_column("Samples changed", justify="right")
    for image in result.images:
        table.add_row(
            escape(str(image.output)),
            f"#{image.share_index}",
            f"{image.report.embedding_rate:.3%}",
            f"{image.report.samples_changed:,} ({image.report.change_rate:.3%})",
        )
    console.print(table)
    if not passphrase:
        console.print(
            "[yellow]warning:[/] no passphrase - anyone with shardpix can read the share in an "
            "image; the vault still needs "
            f"{header.threshold} of them"
        )
    jpegs = [image.cover.name for image in result.images if image.from_jpeg]
    if jpegs:
        verb = "was" if len(jpegs) == 1 else "were"
        console.print(JPEG_WARNING.format(names=f"{escape(', '.join(jpegs))} {verb}"))
    if args.method == stego.Method.REPLACEMENT.value:
        console.print(REPLACEMENT_WARNING)
    console.print("Keep the vault file anywhere; give each image to a different holder.")
    console.print("Never publish the original covers next to the images.")
    return 0


def cmd_unseal(args: argparse.Namespace, console: Console) -> int:
    inputs = (args.vault, *args.images)
    if args.output is not None:
        check_output(args.output, force=args.force, inputs=inputs)
    passphrase = read_passphrase(args, confirm=False)
    result = vault.unseal(args.vault, args.images, passphrase)
    console.print(_outcome_table(result.outcomes))
    output = args.output if args.output is not None else Path(result.filename)
    check_output(output, force=args.force, inputs=inputs)
    write_new(output, result.data, overwrite=args.force)
    console.print(
        f"Recovered [bold]{escape(result.filename)}[/] ({format_bytes(len(result.data))}) "
        f"to [bold]{escape(str(output))}[/]"
    )
    return 0


def cmd_inspect(args: argparse.Namespace, console: Console) -> int:
    payload = stego.extract(load_image(args.image), read_passphrase(args, confirm=False))
    try:
        share = shamir.Share.from_bytes(payload)
    except ShareFormatError:
        console.print(f"{escape(str(args.image))}: payload of {len(payload):,} bytes (not a share)")
        return 0
    console.print(
        _key_value_table(
            str(args.image),
            [
                ("Content", "shardpix share"),
                ("Vault / split", share.group),
                ("Share index", f"#{share.index}"),
                ("Threshold", f"{share.threshold} shares needed"),
                ("Secret length", f"{share.secret_length} bytes"),
            ],
        )
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
    if args.shares > shamir.MAX_SHARES:
        raise ShardpixError(f"at most {shamir.MAX_SHARES} shares are supported")
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
        write_new(path, (share.to_text() + "\n").encode("utf-8"), overwrite=args.force)

    console.print(
        f"Split {len(secret):,} bytes into {len(shares)} shares; "
        f"any {args.threshold} recover the secret."
    )
    for path in paths:
        console.print(f"  {escape(str(path))}")
    return 0


def cmd_combine(args: argparse.Namespace, console: Console) -> int:
    if args.output is not None:
        inputs = tuple(Path(s) for s in args.shares if s != "-")
        check_output(args.output, force=args.force, inputs=inputs)
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
        write_new(args.output, recovery.secret, overwrite=args.force)
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
        default=stego.Method.ADAPTIVE.value,
        help="how samples are changed (default: adaptive)",
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

    p = sub.add_parser("seal", help="encrypt a file and hide its key shares in images (k of n)")
    p.add_argument("file", type=Path, help="file to seal")
    p.add_argument(
        "covers", type=Path, nargs="+", metavar="COVER", help="cover images, one per share"
    )
    p.add_argument(
        "-k", "--threshold", type=positive_int, required=True, help="images needed to unseal"
    )
    p.add_argument(
        "-d",
        "--directory",
        type=Path,
        default=Path("sealed"),
        help="where to write the vault and the images (default: ./sealed)",
    )
    p.add_argument("--name", help="vault file name (default: <file>.spx)")
    p.add_argument(
        "-m",
        "--method",
        choices=[m.value for m in stego.Method],
        default=stego.Method.ADAPTIVE.value,
        help="how samples are changed (default: adaptive)",
    )
    _add_passphrase_options(p)
    p.add_argument("-f", "--force", action="store_true", help="overwrite existing outputs")
    p.set_defaults(handler=cmd_seal)

    p = sub.add_parser("unseal", help="open a vault with k of its images")
    p.add_argument("vault", type=Path, help="vault file (.spx)")
    p.add_argument("images", type=Path, nargs="+", metavar="IMAGE", help="images holding shares")
    p.add_argument(
        "-o", "--output", type=Path, help="where to write the file (default: its original name)"
    )
    _add_passphrase_options(p)
    p.add_argument("-f", "--force", action="store_true", help="overwrite the output file")
    p.set_defaults(handler=cmd_unseal)

    p = sub.add_parser("inspect", help="show what an image holds")
    p.add_argument("image", type=Path)
    _add_passphrase_options(p)
    p.set_defaults(handler=cmd_inspect)

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
        if isinstance(exc, VaultError) and exc.outcomes:
            errors.print(_outcome_table(exc.outcomes))
        if isinstance(exc, ShareError):
            for rejection in exc.rejected:
                errors.print(
                    f"[red]rejected[/] {_share_label(rejection.share)}: {escape(rejection.reason)}"
                )
        errors.print(f"[bold red]error:[/] {escape(str(exc))}")
        return 1
    except OSError as exc:
        target = f"{exc.filename}: " if exc.filename else ""
        errors.print(f"[bold red]error:[/] {escape(target + (exc.strerror or str(exc)))}")
        return 1
    except KeyboardInterrupt:
        errors.print("interrupted")
        return 130

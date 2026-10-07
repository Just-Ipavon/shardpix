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

from . import __version__, jpeg, media, shamir, stego, vault
from .analysis import chi_square, rs
from .errors import ShardpixError, ShareError, ShareFormatError, VaultError
from .images import load_image, write_new

DESCRIPTION = (
    "Encrypt a file and split its key into shares hidden in ordinary-looking images: "
    "any k of n images open it."
)

OVERVIEW = """\
Encrypt a file and split its key into shares hidden in ordinary-looking
images: any k of n images open it, fewer reveal nothing.

  file  --AES-256-GCM, random key K------->  file.spx   (store it anywhere)
  K     --Shamir, k of n------------------>  n shares
  share --adaptive +-1 changes------------>  one image per holder

Covers are embedded the way their file is stored: phone JPEGs stay JPEG
(format 5, same quality and metadata), PNG/TIFF/BMP become PNG (format 4).
Run 'shardpix COMMAND -h' for the details and examples of each command."""

EPILOG = """\
quick start:
  shardpix seal notes.pdf a.jpg b.jpg c.jpg d.jpg e.jpg -k 3 -p
      encrypt notes.pdf, hide one share in each photo; any 3 open it
  shardpix unseal sealed/notes.pdf.spx sealed/a.jpg sealed/c.jpg sealed/e.jpg -p
      open the vault with three of its images
  shardpix embed photo.jpg -o out.jpg -t "meet at noon" -p
      hide a short message in one image
  shardpix analyze suspicious.png
      look for the fingerprints of naive LSB embedding

good covers:
  Your own phone photos, as taken: colour, 2 megapixels or more, textured
  (trees, streets, fabric), never shared online. Send the results as files,
  not as photos in a messaging app, which recompresses them. HEIC is not
  supported: set the iPhone camera to 'Most Compatible' (JPEG).

options used by several commands:
  -k N    how many images (or shares) are needed to open; with -k 3 any 3 do
  -p      ask for a passphrase; without it anyone with shardpix reads the data
  -o F    the file to write
  -d DIR  the folder to write into
  -t / -i the data as text in quotes (-t) or as a file (-i)
  -f      allow replacing files that already exist
  Every command lists all its options with 'shardpix COMMAND -h'.

passphrases:
  -p prompts for one, --passphrase-file reads it from a file. Passphrases are
  never accepted on the command line, where the shell history would keep
  them. Without one, anyone running shardpix can find and read a payload.

documentation: https://github.com/Just-Ipavon/shardpix#readme"""

KEYING_NOTE = """\
passphrase:
  The passphrase picks the hidden positions and encrypts the payload; the
  same one is needed to read it back. Without -p or --passphrase-file the
  payload is still encrypted, but anyone running shardpix can read it."""

CHI_SQUARE_ALERT = 0.10
"""Detected prefix (fraction of the image) above which the chi-square attack is reported."""

JPEG_WARNING = (
    "[yellow]warning:[/] {names} decoded from JPEG. Changing a decoded JPEG by +-1 breaks its "
    "8x8 block structure, which JPEG-compatibility steganalysis can detect at any rate; "
    "prefer photos that were never JPEG-compressed, such as RAW exports (docs/07)."
)

OUTPUT_SUFFIXES = {".jpg": {".jpg", ".jpeg"}, ".png": {".png"}}
"""Extensions accepted for the stego file, by the kind of cover."""

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
    group.add_argument(
        "-p",
        "--passphrase",
        action="store_true",
        help="ask for a passphrase at the prompt (typed twice when hiding, hidden as you "
        "type). It chooses where the data hides and encrypts it: the same passphrase is "
        "needed to read it back. Without -p or --passphrase-file, no passphrase is used "
        "and anyone running shardpix can read the payload",
    )
    group.add_argument(
        "--passphrase-file",
        type=Path,
        metavar="FILE",
        help="read the passphrase from the first line of FILE instead of asking, for "
        "scripts. Passphrases are never accepted as plain arguments, which would leave "
        "them in the shell history",
    )


# --------------------------------------------------------------------------- commands


def cmd_capacity(args: argparse.Namespace, console: Console) -> int:
    cover = media.open_cover(args.image)
    room = cover.capacity()
    if cover.coefficients is not None:
        height, width = cover.coefficients.geometry()
        coefficients = cover.coefficients.coefficients()
        usable = int(jpeg.eligible_mask(coefficients).sum())
        rows = [
            ("Dimensions", f"{width} x {height}"),
            ("Format", cover.format_name),
            ("Luminance coefficients", f"{coefficients.size:,}"),
            ("Usable coefficients", f"{usable:,} (non-zero AC)"),
        ]
    else:
        carrier = cover._pixels()
        height, width, channels = carrier.geometry
        usable = int(stego.eligible_mask(carrier.samples()).sum())
        rows = [
            ("Dimensions", f"{width} x {height}"),
            ("Format", cover.format_name),
            ("Mode", f"{carrier.mode} ({channels} colour channel{'s' if channels > 1 else ''})"),
            ("Carrier samples", f"{carrier.n_samples:,}"),
            ("Usable samples", f"{usable:,} (values {stego.ELIGIBLE_MIN}-{stego.ELIGIBLE_MAX})"),
        ]
    rows.append(("Capacity", f"{room:,} bytes ({format_bytes(room)})"))
    console.print(_key_value_table(str(args.image), rows))
    return 0


def cmd_embed(args: argparse.Namespace, console: Console) -> int:
    check_output(args.output, force=args.force, inputs=(args.cover,))
    payload = read_secret(args)
    cover = media.open_cover(args.cover)
    if args.output.suffix.lower() not in OUTPUT_SUFFIXES[cover.suffix]:
        raise ShardpixError(
            f"{args.output.name}: a {'JPEG' if cover.is_jpeg else 'non-JPEG'} cover gives a "
            f"{cover.suffix} file; name the output something{cover.suffix}"
        )
    passphrase = read_passphrase(args, confirm=True)
    stego_file, report = media.hide(cover, payload, passphrase)
    write_new(args.output, stego_file, overwrite=args.force)

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
                ("Format", cover.format_name),
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
    if cover.pixels is not None and cover.pixels.from_jpeg:
        console.print(JPEG_WARNING.format(names=f"{escape(str(args.cover))} was"))
    return 0


def cmd_extract(args: argparse.Namespace, console: Console) -> int:
    if args.output is not None:
        check_output(args.output, force=args.force, inputs=(args.image,))
    payload = media.reveal(args.image, read_passphrase(args, confirm=False))
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
    payload = media.reveal(args.image, read_passphrase(args, confirm=False))
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


def _command(
    sub: argparse._SubParsersAction, name: str, summary: str, details: str, examples: str
) -> argparse.ArgumentParser:
    """A subcommand whose -h shows ``details`` and ``examples`` as written."""
    return sub.add_parser(
        name,
        help=summary,
        description=f"{summary[0].upper()}{summary[1:]}.\n\n{details}",
        epilog=f"examples:\n{examples}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shardpix",
        description=OVERVIEW,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"shardpix {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND", title="commands")

    p = _command(
        sub,
        "capacity",
        "show how many bytes an image can hide",
        "Reports the format the image would be embedded with and the largest\n"
        "payload it holds. A vault share needs about 110 bytes, so any photo of a\n"
        "useful size has room to spare; capacity matters for 'embed'.",
        "  shardpix capacity photo.jpg",
    )
    p.add_argument("image", type=Path, help="image to measure (JPEG, PNG, TIFF, BMP, ...)")
    p.set_defaults(handler=cmd_capacity)

    p = _command(
        sub,
        "embed",
        "hide a message or a file in an image",
        "Hides one payload, encrypted and authenticated, in a single image. A JPEG\n"
        "cover gives a JPEG (format 5: same quantisation tables and metadata);\n"
        "anything else gives a PNG (format 4). The changes are placed where the\n"
        "image is textured, by syndrome-trellis codes. Use 'capacity' to see how\n"
        "much fits. The cover itself is never modified.\n\n" + KEYING_NOTE,
        '  shardpix embed photo.jpg -o out.jpg -t "meet at noon" -p\n'
        "  shardpix embed scan.png -o out.png -i contract.pdf --passphrase-file pw.txt",
    )
    p.add_argument("cover", type=Path, help="cover image (JPEG from a phone, PNG, TIFF, ...)")
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="(required) the image to write with the payload inside. It must end in .jpg "
        "or .jpeg for a JPEG cover and in .png for any other cover. Never the cover itself",
    )
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("-t", "--text", help="the message to hide, in quotes (use either -t or -i)")
    source.add_argument(
        "-i",
        "--input",
        type=Path,
        metavar="FILE",
        help="a file to hide, of any type, up to the capacity of the cover (use either -t or -i)",
    )
    _add_passphrase_options(p)
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace the output file if it already exists (without -f shardpix refuses)",
    )
    p.set_defaults(handler=cmd_embed)

    p = _command(
        sub,
        "extract",
        "recover a message or a file from an image",
        "Reads back what 'embed' hid. Without -o the payload is written to\n"
        "standard output as it is. Fails with 'no shardpix payload found' if the\n"
        "passphrase is wrong, the image holds nothing, or it was edited or\n"
        "recompressed after embedding.\n\n" + KEYING_NOTE,
        "  shardpix extract out.jpg -p\n"
        "  shardpix extract out.png -o contract.pdf --passphrase-file pw.txt",
    )
    p.add_argument("image", type=Path, help="the image written by 'embed'")
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        help="save the payload to this file; use it whenever the payload is a file. "
        "Without -o it is printed on the terminal",
    )
    _add_passphrase_options(p)
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace the -o file if it already exists (without -f shardpix refuses)",
    )
    p.set_defaults(handler=cmd_extract)

    p = _command(
        sub,
        "seal",
        "encrypt a file and hide its key shares in images (k of n)",
        "Encrypts FILE with a random key into a vault file (.spx), splits the key\n"
        "with Shamir's scheme into one share per cover, and hides each share in\n"
        "its cover. n is the number of covers (at least 2) and 2 <= k <= n; any k\n"
        "images open the vault, k-1 reveal nothing about the key. Outputs go to\n"
        "the directory given by -d: the vault plus one image per cover, keeping\n"
        "its name and kind (.jpg stays .jpg, anything else becomes .png).\n\n"
        "Give each image to a different holder, keep the vault anywhere, and never\n"
        "publish the original covers.\n\n" + KEYING_NOTE,
        "  shardpix seal notes.pdf a.jpg b.jpg c.jpg d.jpg e.jpg -k 3 -p\n"
        "  shardpix seal keys.txt photos/*.jpg -k 2 -d out --name keys.spx -p",
    )
    p.add_argument("file", type=Path, help="the file to protect, of any type and size")
    p.add_argument(
        "covers",
        type=Path,
        nargs="+",
        metavar="COVER",
        help="the images that will carry the key, at least 2: each gets one share. Their "
        "number is n, the total number of shares. The originals are never modified",
    )
    p.add_argument(
        "-k",
        "--threshold",
        type=positive_int,
        required=True,
        help="(required) how many images are needed to open the vault, from 2 to the "
        "number of covers. With -k 3 and 5 covers, any 3 of the 5 images open it and 2 "
        "reveal nothing, so up to 2 images can be lost or stolen",
    )
    p.add_argument(
        "-d",
        "--directory",
        type=Path,
        default=Path("sealed"),
        help="folder where the vault and the new images are written, created if needed "
        "(default: ./sealed)",
    )
    p.add_argument(
        "--name",
        help="file name of the vault, the encrypted copy of FILE (default: FILE's name "
        "followed by .spx, e.g. notes.pdf.spx)",
    )
    _add_passphrase_options(p)
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace a vault or images already in the output folder (without -f "
        "shardpix refuses and writes nothing)",
    )
    p.set_defaults(handler=cmd_seal)

    p = _command(
        sub,
        "unseal",
        "open a vault with k of its images",
        "Reads the share in each image, checks it against the vault, and rebuilds\n"
        "the key once k valid shares are found. Extra, damaged or foreign images\n"
        "are fine: a table reports what happened to every image (used, no\n"
        "payload, other vault, rejected, ...), so a failed recovery still tells\n"
        "you which holder to call. The file is written under its original name\n"
        "unless -o is given.\n\n" + KEYING_NOTE,
        "  shardpix unseal notes.pdf.spx a.jpg c.jpg e.jpg -p\n"
        "  shardpix unseal vault.spx received/*.jpg -o notes.pdf -p",
    )
    p.add_argument("vault", type=Path, help="the vault file (.spx) written by 'seal'")
    p.add_argument(
        "images",
        type=Path,
        nargs="+",
        metavar="IMAGE",
        help="images from 'seal', at least as many as the threshold; extra or unrelated "
        "images are allowed and reported",
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        help="where to save the recovered file (default: its original name, in the current folder)",
    )
    _add_passphrase_options(p)
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace the output file if it already exists (without -f shardpix refuses)",
    )
    p.set_defaults(handler=cmd_unseal)

    p = _command(
        sub,
        "inspect",
        "show what an image holds",
        "Reads the payload of an image and tells whether it is a vault share and,\n"
        "if so, which vault it belongs to, its share number and how many shares\n"
        "the vault needs; for any other payload, its size. Nothing is written.\n\n" + KEYING_NOTE,
        "  shardpix inspect sealed/a.jpg -p",
    )
    p.add_argument("image", type=Path, help="image to inspect")
    _add_passphrase_options(p)
    p.set_defaults(handler=cmd_inspect)

    p = _command(
        sub,
        "analyze",
        "run steganalysis attacks against an image",
        "Runs two classical attacks that detect naive LSB embedding: the\n"
        "chi-square attack (Westfeld-Pfitzmann), which finds data written\n"
        "sequentially, and RS analysis (Fridrich), which estimates the fraction of\n"
        "pixels carrying LSB replacement. Useful to check suspicious images and to\n"
        "see that shardpix outputs do not trigger them. Modern trained detectors\n"
        "are stronger; their results are in docs/05.",
        "  shardpix analyze suspicious.png\n  shardpix analyze photo.png --steps 200",
    )
    p.add_argument("image", type=Path, help="image to analyse")
    p.add_argument(
        "--steps",
        type=positive_int,
        default=100,
        help="how many portions of the image the sequential chi-square attack tests, from "
        "the first 1%% to the whole image; more steps, finer result (default: 100)",
    )
    p.set_defaults(handler=cmd_analyze)

    p = _command(
        sub,
        "split",
        "split a secret into shares (Shamir, k of n)",
        "Plain Shamir secret sharing, without images: prints n printable,\n"
        "authenticated shares, one per line, or writes one file per share with\n"
        "-d. Any k recover the secret with 'combine'; k-1 reveal nothing.",
        '  shardpix split -t "correct horse battery staple" -k 2 -n 3\n'
        "  shardpix split -i seed.txt -k 3 -n 5 -d shares/",
    )
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("-t", "--text", help="the secret to split, in quotes (use either -t or -i)")
    source.add_argument(
        "-i",
        "--input",
        type=Path,
        metavar="FILE",
        help="a small file to split, such as a key or a seed phrase (use either -t or -i; "
        "for large files use 'seal')",
    )
    p.add_argument(
        "-k",
        "--threshold",
        type=positive_int,
        required=True,
        help="(required) how many shares are needed to recover the secret, from 2 to n",
    )
    p.add_argument(
        "-n",
        "--shares",
        type=positive_int,
        required=True,
        help="(required) how many shares to create in total",
    )
    p.add_argument(
        "-d",
        "--directory",
        type=Path,
        help="save each share in its own file in this folder (share-<id>-<n>.txt) instead "
        "of printing them",
    )
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace share files already in the folder (without -f shardpix refuses)",
    )
    p.set_defaults(handler=cmd_split)

    p = _command(
        sub,
        "combine",
        "recover a secret from its shares",
        "Reads shares written by 'split' from files (one per line, '-' for\n"
        "standard input) and rebuilds the secret from any k of them. Shares that\n"
        "are malformed, forged or from another secret are reported and left out.",
        "  shardpix combine shares/*.txt\n  shardpix combine - -o seed.txt < shares.txt",
    )
    p.add_argument(
        "shares", nargs="+", metavar="FILE", help="files holding shares, one per line ('-' = stdin)"
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        help="save the recovered secret to this file instead of printing it",
    )
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace the -o file if it already exists (without -f shardpix refuses)",
    )
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

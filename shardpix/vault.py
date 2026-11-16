"""Seal a file so that any k of n ordinary-looking images can open it.

::

    file   --AES-256-GCM, random 256-bit key K-->  vault file (.spx)
    K      --Shamir, k of n------------------->  n authenticated shares
    share  --adaptive embedding--------------->  one image per share (JPEG or PNG)

Only the key is split, never the file: shares stay about a hundred bytes
whatever the file size, which keeps the embedding rate - and so the
statistical footprint in each image - tiny. The vault file itself is plain
ciphertext and can be stored anywhere.

Vault file layout, format 2 (big-endian), the one written::

    magic        4  b"SPXV"
    version      1  2
    group id    16  same identifier as the shares
    nonce       12  AES-256-GCM nonce
    ciphertext   *  AES-256-GCM(K, nonce, plaintext, aad = every field above)

    plaintext = threshold k (1) || shares n (1) || content length (8)
                || name length (2) || original file name (UTF-8) || file contents
                || zero padding

The threshold and the share count are inside the ciphertext, so the vault
file does not tell how many images open it. The plaintext is padded to the
Padmé length of at least 4 KiB (:func:`padded_length`): the file size then
reveals O(log log n) bits of the content length instead of all of it, at a
cost of at most 12 % (and 4 KiB for small files).

Format 1, still read, kept *k* and *n* in clear after the group id and did
not pad: ``magic || 1 || group id || k || n || nonce || ciphertext`` with
``plaintext = name length (2) || name || contents``. The version byte is
part of the associated data, so a format-2 vault rewritten as format 1 (or
the reverse) fails authentication instead of being read the other way.
"""

from __future__ import annotations

import os
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import media, shamir, stego
from .errors import (
    PayloadNotFoundError,
    ShardpixError,
    ShareError,
    ShareFormatError,
    UnsupportedImageError,
    VaultError,
)
from .images import write_new
from .progress import Progress, span

MAGIC = b"SPXV"
VERSION = 2
"""Vault format written by :func:`seal`."""
LEGACY_VERSION = 1
KEY_BYTES = 32
NONCE_BYTES = 12
HEADER_BYTES_V1 = len(MAGIC) + 1 + shamir.GROUP_ID_BYTES + 1 + 1 + NONCE_BYTES
HEADER_BYTES_V2 = len(MAGIC) + 1 + shamir.GROUP_ID_BYTES + NONCE_BYTES
HEADER_BYTES = HEADER_BYTES_V1
"""Format-1 header size (kept for callers of the old constant)."""
MAX_NAME_BYTES = 255
GCM_LIMIT = 2**31 - 1
"""AES-GCM as exposed by ``cryptography`` takes at most 2 GiB per call."""
INNER_BYTES = 1 + 1 + 8 + 2
"""Format-2 plaintext fields before the name: k, n, content length, name length."""
MAX_FILE_BYTES = GCM_LIMIT - INNER_BYTES - MAX_NAME_BYTES
MIN_PADDED_BYTES = 4096
VAULT_SUFFIX = ".spx"
FALLBACK_NAME = "unsealed.bin"
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "CLOCK$",
    *(f"COM{i}" for i in (*"123456789", "¹", "²", "³")),
    *(f"LPT{i}" for i in (*"123456789", "¹", "²", "³")),
}
_UNSAFE_CHARACTERS = str.maketrans(dict.fromkeys(':<>|?*"', "_"))

SHARE_BYTES = shamir.share_size(KEY_BYTES)
"""Size of the share hidden in each image."""

PAYLOAD_FRAME_BYTES = stego.PUBLIC_BYTES + SHARE_BYTES + stego.FRAME_OVERHEAD
"""Bytes actually written into each image: salt and cost, then the sealed and framed share."""

RandomBytes = Callable[[int], bytes]

Passphrases = str | None | Sequence[str | None]
"""For :func:`seal`: one passphrase for every image, or one per cover, in order."""
PassphraseLookup = str | None | Mapping[Path, str | None] | Callable[[Path], str | None]
"""For opening: one passphrase for every image, or each image's own (per holder)."""


def _per_cover(passphrase: Passphrases, count: int) -> list[str | None]:
    if passphrase is None or isinstance(passphrase, str):
        return [passphrase] * count
    per_cover = list(passphrase)
    if len(per_cover) != count:
        raise VaultError(
            f"one passphrase per cover is needed: {count} covers, {len(per_cover)} passphrases"
        )
    given = [unicodedata.normalize("NFC", p) for p in per_cover if p]
    if len(set(given)) != len(given):
        raise VaultError(
            "two holders were given the same passphrase; with per-holder passphrases "
            "each holder needs their own"
        )
    return per_cover


def _lookup(passphrase: PassphraseLookup, path: Path) -> str | None:
    if passphrase is None or isinstance(passphrase, str):
        return passphrase
    if callable(passphrase):
        return passphrase(path)
    return passphrase.get(path)


def padded_length(length: int) -> int:
    """Padmé (Nikitin et al., PETS 2019) of ``max(length, MIN_PADDED_BYTES)``,
    capped at what one AES-GCM call takes: keep the top bits of the length
    and round the low ones up, leaking O(log log n) bits at most 12 % cost."""
    length = max(length, MIN_PADDED_BYTES)
    exponent = length.bit_length() - 1
    mantissa_bits = exponent.bit_length()
    mask = (1 << (exponent - mantissa_bits)) - 1
    return min((length + mask) & ~mask, GCM_LIMIT)


@dataclass(frozen=True)
class VaultHeader:
    group_id: bytes
    threshold: int | None
    """k; ``None`` in a format-2 vault until it is opened."""
    shares: int | None
    nonce: bytes
    version: int = VERSION

    def to_bytes(self) -> bytes:
        """The header as stored, which is also the AES-GCM associated data."""
        if self.version == LEGACY_VERSION:
            return (
                MAGIC
                + bytes([LEGACY_VERSION])
                + self.group_id
                + bytes([self.threshold, self.shares])
                + self.nonce
            )
        return MAGIC + bytes([VERSION]) + self.group_id + self.nonce

    @property
    def size(self) -> int:
        return HEADER_BYTES_V1 if self.version == LEGACY_VERSION else HEADER_BYTES_V2

    @classmethod
    def from_bytes(cls, data: bytes) -> VaultHeader:
        if len(data) < len(MAGIC) + 1 or data[: len(MAGIC)] != MAGIC:
            raise VaultError("not a shardpix vault file")
        version = data[len(MAGIC)]
        if version not in (VERSION, LEGACY_VERSION):
            raise VaultError(f"unsupported vault version {version}")
        if len(data) < (HEADER_BYTES_V1 if version == LEGACY_VERSION else HEADER_BYTES_V2):
            raise VaultError("not a shardpix vault file")
        offset = len(MAGIC) + 1
        group_id = data[offset : offset + shamir.GROUP_ID_BYTES]
        offset += shamir.GROUP_ID_BYTES
        threshold = shares = None
        if version == LEGACY_VERSION:
            threshold, shares = data[offset], data[offset + 1]
            offset += 2
        return cls(
            group_id=group_id,
            threshold=threshold,
            shares=shares,
            nonce=data[offset : offset + NONCE_BYTES],
            version=version,
        )

    def described(self) -> str:
        """ "k of n" when known."""
        if self.threshold is None:
            return "unknown until opened"
        return f"{self.threshold} of {self.shares}"

    @property
    def group(self) -> str:
        return self.group_id.hex()[:8]


@dataclass(frozen=True)
class SealedImage:
    cover: Path
    output: Path
    share_index: int
    report: stego.EmbedReport
    format: str = "PNG (format 8)"
    jpeg_quality: int | None = None
    """Estimated quality of a JPEG cover; ``None`` for pixel covers."""


@dataclass(frozen=True)
class SealResult:
    vault_path: Path
    header: VaultHeader
    plaintext_bytes: int
    images: tuple[SealedImage, ...]


class Status:
    """What happened to an image while opening a vault."""

    USED = "used"
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    NO_PAYLOAD = "no payload"
    OTHER_VAULT = "other vault"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class ImageOutcome:
    path: Path
    status: str
    detail: str = ""
    share_index: int | None = None


@dataclass(frozen=True)
class UnsealResult:
    filename: str
    data: bytes
    header: VaultHeader
    outcomes: tuple[ImageOutcome, ...]


def _identity(path: Path) -> str:
    """Comparable form of a path: resolved and case-folded.

    Case is folded everywhere, not only on case-insensitive file systems, so
    two outputs that would collide on macOS or Windows are refused on Linux
    too.
    """
    return os.path.normcase(str(path.resolve())).casefold()


def _check_new_file(path: Path, force: bool, protected: set[str]) -> None:
    if _identity(path) in protected:
        raise VaultError(f"{path} would overwrite one of the inputs; choose another directory")
    if path.exists() and not force:
        raise VaultError(f"{path} already exists; use --force to overwrite it")


def _write(path: Path, write: Callable[[], object]) -> None:
    try:
        write()
    except OSError as exc:
        raise VaultError(f"cannot write {path}: {exc.strerror or exc}") from exc


def seal(
    source: Path,
    covers: Sequence[Path],
    threshold: int,
    out_dir: Path,
    passphrase: Passphrases = None,
    *,
    method: stego.Method = stego.Method.ADAPTIVE,
    vault_name: str | None = None,
    force: bool = False,
    random_bytes: RandomBytes = os.urandom,
    progress: Progress | None = None,
    check: bool = True,
    vault_version: int = VERSION,
) -> SealResult:
    """Encrypt ``source`` and hide one share of its key in each cover image.

    Every check - readable covers, enough capacity, no overwrites - runs
    before anything is written, so a failure leaves the output directory as
    it was. With ``check`` (the default) every image is read back from disk
    and must give its share, and the vault file must decrypt to the source,
    before success is reported; this doubles the key derivations.
    ``vault_version=1`` writes the old, unpadded format with *k* and *n* in
    clear (tests and reproducible benchmarks only).
    ``passphrase`` is one passphrase for every image, or a sequence with one
    per cover (per-holder passphrases: each holder can read only their own
    image's share; they must differ).
    """
    if vault_version not in (VERSION, LEGACY_VERSION):
        raise VaultError(f"cannot write vault format {vault_version}")
    source, out_dir = Path(source), Path(out_dir)
    covers = [Path(c) for c in covers]
    count = len(covers)
    if count < 2:
        raise VaultError("a vault needs at least 2 cover images")
    if count > shamir.MAX_SHARES:
        raise VaultError(f"a vault supports at most {shamir.MAX_SHARES} cover images")
    if not 2 <= threshold <= count:
        raise VaultError(f"the threshold must be between 2 and the number of covers ({count})")
    if len({_identity(c) for c in covers}) != count:
        raise VaultError("each cover image must be a different file")
    if out_dir.exists() and not out_dir.is_dir():
        raise VaultError(f"{out_dir} exists and is not a directory")
    per_cover = _per_cover(passphrase, count)

    try:
        if source.stat().st_size > MAX_FILE_BYTES:
            raise VaultError("files larger than 2 GiB are not supported")
        data = source.read_bytes()
    except OSError as exc:
        raise VaultError(f"cannot read {source}: {exc.strerror}") from exc
    if len(data) > MAX_FILE_BYTES:  # the file grew after stat()
        raise VaultError("files larger than 2 GiB are not supported")
    name = source.name.encode("utf-8")
    if len(name) > MAX_NAME_BYTES:
        raise VaultError("the file name is too long to store in the vault")

    # Each image keeps its kind: a phone JPEG gives a JPEG, anything else a PNG.
    outputs = [out_dir / f"{cover.stem}{media.kind_suffix(cover)}" for cover in covers]
    if vault_name is not None and not is_bare_name(vault_name):
        raise VaultError(f"the vault name {vault_name!r} must be a file name, not a path")
    vault_path = out_dir / (vault_name or f"{source.name}{VAULT_SUFFIX}")
    if len({_identity(p) for p in [*outputs, vault_path]}) != count + 1:
        raise VaultError(
            "output names collide (covers with the same name, or a vault name equal to an "
            "image name); rename the covers or choose another --name"
        )
    protected = {_identity(p) for p in [source, *covers]}
    for path in [*outputs, vault_path]:
        _check_new_file(path, force, protected)

    report = span(progress, 0.0, 1.0)
    opened: list[media.Cover] = []
    for i, cover in enumerate(covers):
        report(0.05 * i / count, f"opening {cover.name}")
        opened_cover = media.open_cover(cover)
        room = opened_cover.capacity()
        if room < SHARE_BYTES:
            raise VaultError(
                f"{cover} is too small: it holds {room} bytes, a share needs {SHARE_BYTES}"
            )
        opened.append(opened_cover)

    key = random_bytes(KEY_BYTES)
    header = VaultHeader(
        group_id=random_bytes(shamir.GROUP_ID_BYTES),
        threshold=threshold,
        shares=count,
        nonce=random_bytes(NONCE_BYTES),
        version=vault_version,
    )
    plaintext = _plaintext(header, name, data)
    ciphertext = AESGCM(key).encrypt(header.nonce, plaintext, header.to_bytes())
    shares = shamir.split(
        key, threshold, count, group_id=header.group_id, random_bytes=random_bytes
    )

    _write(out_dir, lambda: out_dir.mkdir(parents=True, exist_ok=True))
    sealed = []
    for i, (cover, opened_cover, share, output, image_passphrase) in enumerate(
        zip(covers, opened, shares, outputs, per_cover, strict=True)
    ):
        image_progress = span(
            progress, 0.05 + 0.95 * i / count, 0.05 + 0.95 * (i + 1) / count, f"{cover.name}: "
        )
        stego_file, embed_report = media.hide(
            opened_cover, share.to_bytes(), image_passphrase, random_bytes, method, image_progress
        )
        write_new(output, stego_file, overwrite=force)
        if check:
            _check_share_written(output, share, image_passphrase)
        sealed.append(
            SealedImage(
                cover,
                output,
                share.index,
                embed_report,
                opened_cover.format_name,
                None if opened_cover.coefficients is None else opened_cover.coefficients.quality,
            )
        )
    report(1.0, f"writing {vault_path.name}")
    write_new(vault_path, header.to_bytes() + ciphertext, overwrite=force)
    if check:
        written_header, written = read_vault(vault_path)
        try:
            ok = AESGCM(key).decrypt(header.nonce, written, written_header.to_bytes()) == plaintext
        except (InvalidTag, ValueError):
            ok = False
        if not ok:
            raise VaultError(
                f"self-check failed: {vault_path} does not decrypt to the source "
                "as written; do not rely on this vault"
            )

    return SealResult(vault_path, header, len(data), tuple(sealed))


def _plaintext(header: VaultHeader, name: bytes, data: bytes) -> bytes:
    if header.version == LEGACY_VERSION:
        return len(name).to_bytes(2, "big") + name + data
    inner = (
        bytes([header.threshold, header.shares])
        + len(data).to_bytes(8, "big")
        + len(name).to_bytes(2, "big")
        + name
        + data
    )
    return inner + bytes(padded_length(len(inner)) - len(inner))


def _parse_plaintext(header: VaultHeader, plaintext: bytes) -> tuple[VaultHeader, bytes, bytes]:
    """(header with k and n, name, contents) from an authenticated plaintext."""
    if header.version == LEGACY_VERSION:
        name_length = int.from_bytes(plaintext[:2], "big")
        return header, plaintext[2 : 2 + name_length], plaintext[2 + name_length :]
    if len(plaintext) < INNER_BYTES:
        raise VaultError("the vault's contents are malformed")
    threshold, shares = plaintext[0], plaintext[1]
    content_length = int.from_bytes(plaintext[2:10], "big")
    name_length = int.from_bytes(plaintext[10:12], "big")
    end = INNER_BYTES + name_length + content_length
    if end > len(plaintext) or any(plaintext[end:]) or not 2 <= threshold <= shares:
        raise VaultError("the vault's contents are malformed")
    name = plaintext[INNER_BYTES : INNER_BYTES + name_length]
    opened = VaultHeader(header.group_id, threshold, shares, header.nonce, header.version)
    return opened, name, plaintext[INNER_BYTES + name_length : end]


def _check_share_written(path: Path, share: shamir.Share, passphrase: str | None) -> None:
    """Read ``path`` back from disk; it must give exactly ``share``."""
    try:
        payload = media.reveal(path, passphrase)
    except ShardpixError as exc:
        raise VaultError(
            f"self-check failed: {path} does not give back its share ({exc}); "
            "do not rely on this image"
        ) from exc
    if payload != share.to_bytes():
        raise VaultError(
            f"self-check failed: {path} gives back a different share; do not rely on this image"
        )


def read_vault(path: Path) -> tuple[VaultHeader, bytes]:
    """Read a vault file and return its header and ciphertext."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise VaultError(f"cannot read {path}: {exc.strerror}") from exc
    header = VaultHeader.from_bytes(data)
    return header, data[header.size :]


def is_bare_name(name: str) -> bool:
    """Whether ``name`` names a file in the current directory, on any system."""
    return name not in {"", ".", ".."} and PurePath(name.replace("\\", "/")).name == name


def safe_filename(name: str) -> str:
    """Reduce a stored file name to a bare, harmless file name.

    The name comes from inside an authenticated vault, but whoever made the
    vault may not be trustworthy: the restored name must never point outside
    the chosen directory, carry control characters (terminal escape
    sequences, NUL), be a hidden file (``.bashrc``, ``.envrc``) or look like
    an option (``-rf``), name an NTFS alternate data stream, or be a reserved
    device name on Windows, which ignores trailing dots and spaces.
    """
    base = PurePath(name.replace("\\", "/")).name
    base = "".join(c for c in base if unicodedata.category(c) not in {"Cc", "Cf"})
    base = base.translate(_UNSAFE_CHARACTERS)
    while True:
        trimmed = base.strip().rstrip(". ").lstrip(".-")
        if trimmed == base:
            break
        base = trimmed
    stem = base.split(".")[0].strip().upper()
    if not base or stem in _WINDOWS_RESERVED:
        return FALLBACK_NAME
    return base


def _read_share(path: Path, passphrase: str | None) -> shamir.Share | ImageOutcome:
    try:
        payload = media.reveal(path, passphrase)
    except UnsupportedImageError as exc:
        return ImageOutcome(path, Status.UNREADABLE, str(exc))
    except PayloadNotFoundError:
        return ImageOutcome(path, Status.NO_PAYLOAD, "no share: wrong passphrase or edited image")
    try:
        return shamir.Share.from_bytes(payload)
    except ShareFormatError as exc:
        return ImageOutcome(path, Status.REJECTED, str(exc))


def unseal(
    vault_path: Path,
    images: Sequence[Path],
    passphrase: PassphraseLookup = None,
    progress: Progress | None = None,
) -> UnsealResult:
    """Recover the file sealed in ``vault_path`` from (some of) its images.

    ``passphrase`` is the vault's passphrase, or with per-holder passphrases a
    mapping (or function) from each image path to its own.
    """
    header, plaintext, outcomes = _open(vault_path, images, passphrase, progress)
    header, name, data = _parse_plaintext(header, plaintext)
    return UnsealResult(
        filename=safe_filename(name.decode("utf-8", errors="replace")),
        data=data,
        header=header,
        outcomes=outcomes,
    )


@dataclass(frozen=True)
class VerifyResult:
    """Whether a set of images opens a vault, image by image; no plaintext."""

    header: VaultHeader
    opens: bool
    outcomes: tuple[ImageOutcome, ...]
    detail: str = ""


def verify(
    vault_path: Path,
    images: Sequence[Path],
    passphrase: PassphraseLookup = None,
    progress: Progress | None = None,
) -> VerifyResult:
    """Check which images hold a valid share of ``vault_path`` and whether they open it.

    The key is rebuilt and the vault trial-decrypted in memory, so a share that
    authenticates but belongs to a forged set is still caught; the plaintext is
    discarded, never returned or written.
    """
    header, _ciphertext = read_vault(vault_path)
    try:
        header, plaintext, outcomes = _open(vault_path, images, passphrase, progress)
    except VaultError as exc:
        return VerifyResult(header, False, exc.outcomes, str(exc))
    header, _name, _data = _parse_plaintext(header, plaintext)
    return VerifyResult(header, True, outcomes)


def _open(
    vault_path: Path,
    images: Sequence[Path],
    passphrase: PassphraseLookup,
    progress: Progress | None,
) -> tuple[VaultHeader, bytes, tuple[ImageOutcome, ...]]:
    header, ciphertext = read_vault(vault_path)
    images = list(dict.fromkeys(Path(p) for p in images))
    report = span(progress, 0.0, 1.0)

    outcomes: dict[Path, ImageOutcome] = {}
    origin: dict[bytes, Path] = {}
    shares: list[shamir.Share] = []
    for i, path in enumerate(images):
        report(i / len(images), f"reading {path.name}")
        result = _read_share(path, _lookup(passphrase, path))
        if isinstance(result, ImageOutcome):
            outcomes[path] = result
            continue
        share = result
        encoded = share.to_bytes()
        if share.group_id != header.group_id:
            outcomes[path] = ImageOutcome(
                path, Status.OTHER_VAULT, f"share belongs to vault {share.group}", share.index
            )
        elif encoded in origin:
            outcomes[path] = ImageOutcome(
                path, Status.DUPLICATE, f"same share as {origin[encoded].name}", share.index
            )
        else:
            origin[encoded] = path
            shares.append(share)

    def ordered() -> tuple[ImageOutcome, ...]:
        return tuple(outcomes[p] for p in images if p in outcomes)

    report(1.0, "rebuilding the key")
    if not shares:
        raise VaultError(
            f"cannot open the vault: none of the {len(images)} images holds a share of it "
            "(wrong or missing passphrase, edited images, or images of another vault)",
            ordered(),
        )
    try:
        recoveries = shamir.recover_all(shares)
    except ShareError as exc:
        for rejection in exc.rejected:
            path = origin[rejection.share.to_bytes()]
            outcomes[path] = ImageOutcome(
                path, Status.REJECTED, rejection.reason, rejection.share.index
            )
        for share in shares:
            path = origin[share.to_bytes()]
            outcomes.setdefault(
                path,
                ImageOutcome(
                    path, Status.UNVERIFIED, "readable share, not enough to verify", share.index
                ),
            )
        needed = (
            header.described()
            if header.threshold is not None
            else (f"{shares[0].threshold} of the images")
        )
        raise VaultError(
            f"cannot open the vault: {exc} (threshold is {needed})",
            ordered(),
        ) from exc

    # Several clusters only arise if someone fabricated mutually consistent
    # shares. The vault's AES-GCM tag tells the genuine one apart.
    for recovery in recoveries:
        try:
            plaintext = AESGCM(recovery.secret).decrypt(header.nonce, ciphertext, header.to_bytes())
        except (InvalidTag, ValueError):
            continue
        break
    else:
        for recovery in recoveries:
            for share in (*recovery.used, *recovery.confirmed):
                path = origin[share.to_bytes()]
                outcomes[path] = ImageOutcome(
                    path,
                    Status.REJECTED,
                    "consistent shares, but not this vault's key",
                    share.index,
                )
        raise VaultError(
            "no set of shares opens the vault: either the vault file was modified or the "
            "shares that authenticate each other were forged",
            ordered(),
        )

    for share in recovery.used:
        path = origin[share.to_bytes()]
        outcomes[path] = ImageOutcome(path, Status.USED, "", share.index)
    for share in recovery.confirmed:
        path = origin[share.to_bytes()]
        outcomes[path] = ImageOutcome(path, Status.VERIFIED, "", share.index)
    for rejection in recovery.rejected:
        path = origin[rejection.share.to_bytes()]
        outcomes[path] = ImageOutcome(
            path, Status.REJECTED, rejection.reason, rejection.share.index
        )

    return header, plaintext, ordered()

"""Seal a file so that any k of n ordinary-looking images can open it.

::

    file   --AES-256-GCM, random 256-bit key K-->  vault file (.spx)
    K      --Shamir, k of n------------------->  n authenticated shares
    share  --keyed LSB embedding-------------->  one PNG per share

Only the key is split, never the file: shares stay about a hundred bytes
whatever the file size, which keeps the embedding rate - and so the
statistical footprint in each image - tiny. The vault file itself is plain
ciphertext and can be stored anywhere.

Vault file layout (big-endian)::

    magic        4  b"SPXV"
    version      1  1
    group id    16  same identifier as the shares
    threshold    1  k
    shares       1  n
    nonce       12  AES-256-GCM nonce
    ciphertext   *  AES-256-GCM(K, nonce, plaintext, aad = every field above)

    plaintext = name length (2 bytes) || original file name (UTF-8) || file contents
"""

from __future__ import annotations

import os
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import media, shamir, stego
from .errors import (
    PayloadNotFoundError,
    ShareError,
    ShareFormatError,
    UnsupportedImageError,
    VaultError,
)
from .images import write_new

MAGIC = b"SPXV"
VERSION = 1
KEY_BYTES = 32
NONCE_BYTES = 12
HEADER_BYTES = len(MAGIC) + 1 + shamir.GROUP_ID_BYTES + 1 + 1 + NONCE_BYTES
MAX_NAME_BYTES = 255
MAX_FILE_BYTES = 2**31 - 1 - 2 - MAX_NAME_BYTES
"""AES-GCM as exposed by ``cryptography`` takes at most 2 GiB per call."""
VAULT_SUFFIX = ".spx"
FALLBACK_NAME = "unsealed.bin"
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

SHARE_BYTES = shamir.share_size(KEY_BYTES)
"""Size of the share hidden in each image."""

PAYLOAD_FRAME_BYTES = stego.PUBLIC_BYTES + SHARE_BYTES + stego.FRAME_OVERHEAD
"""Bytes actually written into each image: salt and cost, then the sealed and framed share."""

RandomBytes = Callable[[int], bytes]


@dataclass(frozen=True)
class VaultHeader:
    group_id: bytes
    threshold: int
    shares: int
    nonce: bytes

    def to_bytes(self) -> bytes:
        return (
            MAGIC
            + bytes([VERSION])
            + self.group_id
            + bytes([self.threshold, self.shares])
            + self.nonce
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> VaultHeader:
        if len(data) < HEADER_BYTES or data[: len(MAGIC)] != MAGIC:
            raise VaultError("not a shardpix vault file")
        if data[len(MAGIC)] != VERSION:
            raise VaultError(f"unsupported vault version {data[len(MAGIC)]}")
        offset = len(MAGIC) + 1
        group_id = data[offset : offset + shamir.GROUP_ID_BYTES]
        offset += shamir.GROUP_ID_BYTES
        threshold, shares = data[offset], data[offset + 1]
        offset += 2
        return cls(
            group_id=group_id,
            threshold=threshold,
            shares=shares,
            nonce=data[offset : offset + NONCE_BYTES],
        )

    @property
    def group(self) -> str:
        return self.group_id.hex()[:8]


@dataclass(frozen=True)
class SealedImage:
    cover: Path
    output: Path
    share_index: int
    report: stego.EmbedReport
    from_jpeg: bool = False
    """The cover was a JPEG decoded to pixels (only for formats Pillow reads as JPEG
    but that are not baseline JPEG files); JPEG files are embedded natively."""
    format: str = "PNG (format 4)"


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
    passphrase: str | None = None,
    *,
    method: stego.Method = stego.Method.ADAPTIVE,
    vault_name: str | None = None,
    force: bool = False,
    random_bytes: RandomBytes = os.urandom,
) -> SealResult:
    """Encrypt ``source`` and hide one share of its key in each cover image.

    Every check - readable covers, enough capacity, no overwrites - runs
    before anything is written, so a failure leaves the output directory as
    it was.
    """
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

    try:
        if source.stat().st_size > MAX_FILE_BYTES:
            raise VaultError("files larger than 2 GiB are not supported")
        data = source.read_bytes()
    except OSError as exc:
        raise VaultError(f"cannot read {source}: {exc.strerror}") from exc
    name = source.name.encode("utf-8")
    if len(name) > MAX_NAME_BYTES:
        raise VaultError("the file name is too long to store in the vault")

    # Each image keeps its kind: a phone JPEG gives a JPEG, anything else a PNG.
    outputs = [out_dir / f"{cover.stem}{media.kind_suffix(cover)}" for cover in covers]
    vault_path = out_dir / (vault_name or f"{source.name}{VAULT_SUFFIX}")
    if len({_identity(p) for p in [*outputs, vault_path]}) != count + 1:
        raise VaultError(
            "output names collide (covers with the same name, or a vault name equal to an "
            "image name); rename the covers or choose another --name"
        )
    protected = {_identity(p) for p in [source, *covers]}
    for path in [*outputs, vault_path]:
        _check_new_file(path, force, protected)

    opened: list[media.Cover] = []
    for cover in covers:
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
    )
    plaintext = len(name).to_bytes(2, "big") + name + data
    ciphertext = AESGCM(key).encrypt(header.nonce, plaintext, header.to_bytes())
    shares = shamir.split(
        key, threshold, count, group_id=header.group_id, random_bytes=random_bytes
    )

    _write(out_dir, lambda: out_dir.mkdir(parents=True, exist_ok=True))
    sealed = []
    for cover, opened_cover, share, output in zip(covers, opened, shares, outputs, strict=True):
        stego_file, report = media.hide(
            opened_cover, share.to_bytes(), passphrase, random_bytes, method
        )
        write_new(output, stego_file, overwrite=force)
        decoded_jpeg = opened_cover.pixels is not None and opened_cover.pixels.from_jpeg
        sealed.append(
            SealedImage(cover, output, share.index, report, decoded_jpeg, opened_cover.format_name)
        )
    write_new(vault_path, header.to_bytes() + ciphertext, overwrite=force)

    return SealResult(vault_path, header, len(data), tuple(sealed))


def read_vault(path: Path) -> tuple[VaultHeader, bytes]:
    """Read a vault file and return its header and ciphertext."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise VaultError(f"cannot read {path}: {exc.strerror}") from exc
    header = VaultHeader.from_bytes(data)
    return header, data[HEADER_BYTES:]


def safe_filename(name: str) -> str:
    """Reduce a stored file name to a bare, harmless file name.

    The name comes from inside an authenticated vault, but whoever made the
    vault may not be trustworthy: the restored name must never point outside
    the chosen directory, carry control characters (terminal escape
    sequences, NUL), or be a reserved device name on Windows.
    """
    base = PurePath(name.replace("\\", "/")).name
    base = "".join(c for c in base if unicodedata.category(c) not in {"Cc", "Cf"})
    base = base.strip().rstrip(".")
    stem = base.split(".")[0].upper()
    if base in {"", ".", ".."} or stem in _WINDOWS_RESERVED:
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


def unseal(vault_path: Path, images: Sequence[Path], passphrase: str | None = None) -> UnsealResult:
    """Recover the file sealed in ``vault_path`` from (some of) its images."""
    header, ciphertext = read_vault(vault_path)
    images = list(dict.fromkeys(Path(p) for p in images))

    outcomes: dict[Path, ImageOutcome] = {}
    origin: dict[bytes, Path] = {}
    shares: list[shamir.Share] = []
    for path in images:
        result = _read_share(path, passphrase)
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
        raise VaultError(
            f"cannot open the vault: {exc} (threshold is {header.threshold} of {header.shares})",
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

    name_length = int.from_bytes(plaintext[:2], "big")
    name = plaintext[2 : 2 + name_length].decode("utf-8", errors="replace")
    return UnsealResult(
        filename=safe_filename(name),
        data=plaintext[2 + name_length :],
        header=header,
        outcomes=ordered(),
    )

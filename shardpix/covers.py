"""Whether an image is a suitable cover: the one place that decides it.

docs/07 explains which covers hide a share well. ``assess`` turns that advice
into findings, used by ``shardpix lint`` and checked by ``seal`` and ``embed``
before anything is written:

* ``refused`` - the image cannot carry the payload at all (unreadable,
  truncated, 16-bit, several frames, too small). Never overridden.
* ``unsuitable`` - it can, but the result is weaker or visibly altered:
  a recompressed JPEG (quality below ``jpeg.SAFE_QUALITY``), a progressive
  JPEG or one with restart markers (written back as baseline), a palette
  image (becomes 24-bit). Refused by ``seal`` and ``embed`` unless
  ``--allow-unsuitable``.
* ``note`` - worth knowing, nothing to change (extra images after the first
  in a phone JPEG, kept as they are).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PIL import Image

from . import jpeg, media
from .errors import ShardpixError

REFUSED = "refused"
UNSUITABLE = "unsuitable"
NOTE = "note"

_PROGRESSIVE_SOF = frozenset({0xC2, 0xC6, 0xCA, 0xCE})
_DRI = 0xDD
_EOI = b"\xff\xd9"


@dataclass(frozen=True)
class Finding:
    level: str
    code: str
    message: str


@dataclass(frozen=True)
class Assessment:
    path: Path
    findings: tuple[Finding, ...]
    cover: media.Cover | None = None

    @property
    def refused(self) -> bool:
        return any(f.level == REFUSED for f in self.findings)

    @property
    def unsuitable(self) -> bool:
        return any(f.level == UNSUITABLE for f in self.findings)

    @property
    def suitable(self) -> bool:
        return not self.refused and not self.unsuitable


def assess(path: str | Path, need_bytes: int = 0) -> Assessment:
    """Every finding about ``path`` as a cover for ``need_bytes`` of payload."""
    path = Path(path)
    try:
        cover = media.open_cover(path)
    except ShardpixError as exc:
        return Assessment(path, (Finding(REFUSED, "unreadable", str(exc)),))
    findings: list[Finding] = []
    room = cover.capacity()
    if room < need_bytes:
        findings.append(
            Finding(REFUSED, "too_small", f"holds {room} bytes, {need_bytes} are needed")
        )
    if cover.is_jpeg:
        findings += _jpeg_findings(path, cover)
    else:
        findings += _pixel_findings(path)
    return Assessment(path, tuple(findings), cover)


def _jpeg_findings(path: Path, cover: media.Cover) -> list[Finding]:
    findings = []
    data = path.read_bytes()
    try:
        segments, scan = jpeg._segments(data)
    except ShardpixError:
        return findings  # open_cover already accepted it
    markers = {marker for marker, _ in segments}
    if markers & _PROGRESSIVE_SOF:
        findings.append(
            Finding(
                UNSUITABLE,
                "progressive",
                "progressive JPEG: written back as baseline, unlike "
                "the other photos from the same camera",
            )
        )
    if _DRI in markers:
        findings.append(
            Finding(UNSUITABLE, "restart_markers", "restart markers: written back without them")
        )
    quality = cover.coefficients.quality if cover.coefficients is not None else None
    if quality is not None and quality < jpeg.SAFE_QUALITY:
        findings.append(
            Finding(
                UNSUITABLE,
                "low_quality",
                f"JPEG quality about {quality}, below {jpeg.SAFE_QUALITY}: "
                "a recompressed photo; shares become detectable when "
                "several images of a vault are pooled",
            )
        )
    eoi = scan.find(_EOI)
    if eoi >= 0 and eoi + 2 < len(scan):
        findings.append(
            Finding(
                NOTE,
                "extra_images",
                f"{len(scan) - eoi - 2:,} bytes after the first image "
                "(MPO frame, gain map or trailer)",
            )
        )
    return findings


def _pixel_findings(path: Path) -> list[Finding]:
    findings = []
    try:
        with Image.open(path) as image:
            mode = image.mode
    except (OSError, SyntaxError, ValueError):
        return findings
    if mode in {"P", "PA"}:
        findings.append(
            Finding(
                UNSUITABLE,
                "palette",
                "palette image: written back as 24-bit colour with "
                "noise, which a palette image never has",
            )
        )
    return findings

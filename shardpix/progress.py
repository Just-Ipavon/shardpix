"""Progress of long operations, reported without tying the library to a display.

A callback receives the fraction done, from 0 to 1, and a short label of the
current step. Library functions take ``progress=None`` and pass each step a
:func:`span` of their own range, so a caller sees one bar that moves from 0
to 1 across every image, step and trellis block.
"""

from __future__ import annotations

from collections.abc import Callable

Progress = Callable[[float, str], None]


def _ignore(fraction: float, label: str) -> None:
    """The callback used when nobody listens."""


def span(progress: Progress | None, start: float, stop: float, prefix: str = "") -> Progress:
    """``progress`` restricted to ``[start, stop]`` of its range.

    ``prefix`` is put before every label, e.g. the name of the image being
    worked on.
    """
    if progress is None:
        return _ignore
    report = progress

    def scaled(fraction: float, label: str) -> None:
        fraction = min(max(fraction, 0.0), 1.0)
        report(start + (stop - start) * fraction, f"{prefix}{label}")

    return scaled

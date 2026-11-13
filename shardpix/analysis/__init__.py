"""Steganalysis: statistical attacks used to measure how detectable an embedding is."""

from __future__ import annotations

import argparse
from pathlib import Path


def default_data_dir(parser: argparse.ArgumentParser) -> Path:
    """``docs/data`` of a repository checkout, or a usage error asking for ``--data``.

    The benchmarks read and write the published results there. Outside a
    checkout (an installed package) a relative default would silently write
    into whatever directory the command runs in, so ``--data`` is required.
    """
    path = Path("docs/data")
    if not path.is_dir():
        parser.error(
            "no docs/data directory here: run from a shardpix repository checkout, or give --data"
        )
    return path

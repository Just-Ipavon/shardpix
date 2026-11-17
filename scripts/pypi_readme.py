"""Rewrite README.md's relative links as absolute GitHub URLs, for PyPI.

PyPI renders the README on its own page, where `assets/demo.svg` or
`docs/README.md` lead nowhere. The release workflow runs this script on
the checkout before the build, so the published long description points at
the tagged files on GitHub; README.md in the repository stays relative.

Usage: python scripts/pypi_readme.py REF [README]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = "Just-Ipavon/shardpix"

# The target of a Markdown link or image, nested ones included:
# [![badge](img)](LICENSE) has two.
MD_TARGET = re.compile(r"\]\(([^)\s]+)\)")
IMAGE = re.compile(r"\.(svg|png|jpe?g|gif|webp)$", re.IGNORECASE)
# HTML attributes used by <img> and <picture><source>.
HTML_ATTR = re.compile(r'\b(src|srcset)="([^"]+)"')


def is_relative(target: str) -> bool:
    return not re.match(r"^([a-z][a-z0-9+.-]*:|#|/)", target, re.IGNORECASE)


def absolute(target: str, ref: str) -> str:
    if not is_relative(target):
        return target
    path = target.removeprefix("./")
    if IMAGE.search(path):
        return f"https://raw.githubusercontent.com/{REPO}/{ref}/{path}"
    return f"https://github.com/{REPO}/blob/{ref}/{path}"


def rewrite(text: str, ref: str) -> str:
    def md(m: re.Match[str]) -> str:
        return f"]({absolute(m.group(1), ref)})"

    def html(m: re.Match[str]) -> str:
        attr, target = m.groups()
        return f'{attr}="{absolute(target, ref)}"'

    return HTML_ATTR.sub(html, MD_TARGET.sub(md, text))


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    ref = argv[1]
    readme = Path(argv[2] if len(argv) == 3 else "README.md")
    readme.write_text(rewrite(readme.read_text(encoding="utf-8"), ref), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

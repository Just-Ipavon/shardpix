"""Passphrase strength and a diceware generator.

A passphrase protects every image of a vault: whoever guesses it reads the
shares, and with k of them the file. Argon2id makes each guess cost about
half a second and 256 MiB, which is ample against a guess drawn from 2^60
possibilities and worthless against "summer2024". :func:`estimate_bits` is a
deliberately pessimistic estimate used to refuse weak passphrases at seal
time; :func:`generate` draws a diceware passphrase from the EFF large word
list (7,776 words, 12.9 bits each).

The estimate is a heuristic, not a measurement: it cannot know that a
passphrase is a quote, a name or something its owner wrote elsewhere. What
it does is refuse the obviously short and the obviously patterned, and give
generated passphrases their true value.

Word list: EFF large wordlist for random passphrases, by the Electronic
Frontier Foundation, CC BY 3.0 US
(https://www.eff.org/dice; ``shardpix/data/README``).
"""

from __future__ import annotations

import math
import re
import secrets
import unicodedata
from functools import cache
from importlib import resources

MIN_BITS = 50
"""Below this, sealing refuses the passphrase unless told otherwise."""
DEFAULT_WORDS = 6
"""Words in a generated passphrase: 6 x 12.9 = 77.5 bits."""
WORDLIST_SIZE = 7776
WORD_BITS = math.log2(WORDLIST_SIZE)
_SEPARATORS = re.compile(r"[\s\-_.,;:+/]+")


@cache
def wordlist() -> tuple[str, ...]:
    text = (
        resources.files("shardpix")
        .joinpath("data/eff_large_wordlist.txt")
        .read_text(encoding="utf-8")
    )
    words = tuple(w for w in text.split() if w)
    if len(words) != WORDLIST_SIZE or len(set(words)) != WORDLIST_SIZE:
        raise RuntimeError("the bundled word list is damaged")
    return words


@cache
def _wordset() -> frozenset[str]:
    return frozenset(wordlist())


def generate(words: int = DEFAULT_WORDS, separator: str = " ") -> str:
    """A diceware passphrase of ``words`` words drawn with the OS CSPRNG.

    Words are separated by spaces: four words of the list contain a hyphen
    (``t-shirt``), so a hyphen would make the word count ambiguous to a reader.
    """
    if not 4 <= words <= 20:
        raise ValueError("a generated passphrase has 4 to 20 words")
    pool = wordlist()
    return separator.join(secrets.choice(pool) for _ in range(words))


def _list_words(tokens: list[str]) -> int | None:
    """Fewest list words that ``tokens`` (split on separators) can be read as,
    rejoining neighbours with ``-`` for the four hyphenated words of the list
    (``t-shirt``); ``None`` if they cannot all be read as list words."""
    words = _wordset()
    best: list[int | None] = [0] + [None] * len(tokens)
    for end in range(1, len(tokens) + 1):
        for start in (end - 1, end - 2):
            before = best[start] if start >= 0 else None
            if before is None:
                continue
            if "-".join(tokens[start:end]) in words:
                candidate = before + 1
                current = best[end]
                if current is None or candidate < current:
                    best[end] = candidate
    return best[-1]


def _effective_length(text: str) -> int:
    """Characters that count: repeats and runs (aaa, abc, 321) count once."""
    count, previous, step = 0, None, None
    for c in text:
        if previous is None:
            count += 1
        else:
            delta = ord(c) - ord(previous)
            if delta in (-1, 0, 1) and (step is None or delta == step):
                step = delta
            else:
                count += 1
                step = None
        previous = c
    return count


def _chosen_bits(length: int, mixed: bool) -> float:
    """Entropy of a passphrase a person chose, by the length rule of NIST SP
    800-63-1 (appendix A): 4 bits for the first character, 2 for the next 7,
    1.5 for the 9th to 20th, 1 after that; 6 more for mixed character classes.
    People choose words and patterns, so the count is low on purpose."""
    bits = 0.0
    for position in range(1, length + 1):
        bits += 4 if position == 1 else 2 if position <= 8 else 1.5 if position <= 20 else 1
    return bits + (6 if mixed and length else 0)


def estimate_bits(passphrase: str) -> float:
    """A pessimistic estimate of the passphrase's entropy in bits.

    A passphrase made only of words from the bundled list counts 12.9 bits per
    word, which is what the generator gives (a person choosing the words gets
    less). Anything else is treated as chosen by a person: repeats and runs
    count once, and the length rule of :func:`_chosen_bits` applies, so a
    random string scores less than it is worth; generate one instead, or
    pass --allow-weak-passphrase.
    """
    text = unicodedata.normalize("NFC", passphrase).strip()
    if not text:
        return 0.0
    tokens = [t for t in _SEPARATORS.split(text.lower()) if t]
    count = _list_words(tokens)
    if count is not None and count >= 2:
        return count * WORD_BITS
    mixed = any(c.isupper() for c in text) and any(not c.isalpha() for c in text)
    return _chosen_bits(_effective_length(text), mixed)


def check(passphrase: str, minimum: float | None = None) -> str | None:
    """``None`` if the passphrase is strong enough, else the reason."""
    minimum = MIN_BITS if minimum is None else minimum
    bits = estimate_bits(passphrase)
    if bits >= minimum:
        return None
    return (
        f"the passphrase looks weak (about {bits:.0f} bits, at least {minimum} wanted): "
        "anyone holding an image could guess it. Use 'shardpix passphrase' to generate "
        "one, or pass --allow-weak-passphrase if you know better"
    )

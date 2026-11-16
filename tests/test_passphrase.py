"""Passphrase strength estimate and diceware generator."""

from __future__ import annotations

import hashlib
import math
from importlib import resources

import pytest

from shardpix import passphrase
from shardpix.cli import main


@pytest.fixture(autouse=True)
def real_minimum(monkeypatch):
    monkeypatch.setattr(passphrase, "MIN_BITS", 50)


def test_bundled_word_list_is_the_eff_large_list():
    words = passphrase.wordlist()
    assert len(words) == len(set(words)) == 7776
    assert words[0] == "abacus" and words[-1] == "zoom"
    # The EFF file is "<dice>\t<word>" per line; rebuild it and compare digests.
    rebuilt = "".join(
        f"{a}{b}{c}{d}{e}\t{w}\n"
        for (a, b, c, d, e), w in zip(
            (
                (a, b, c, d, e)
                for a in range(1, 7)
                for b in range(1, 7)
                for c in range(1, 7)
                for d in range(1, 7)
                for e in range(1, 7)
            ),
            words,
            strict=True,
        )
    )
    assert hashlib.sha256(rebuilt.encode()).hexdigest() == (
        "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
    )
    notice = resources.files("shardpix").joinpath("data/README").read_text()
    assert "CC BY 3.0" in notice


def test_generated_passphrases():
    seen = {passphrase.generate() for _ in range(50)}
    assert len(seen) == 50
    for phrase in seen:
        parts = phrase.split("-")
        assert len(parts) == 6 and all(p in passphrase.wordlist() for p in parts)
        assert passphrase.estimate_bits(phrase) == pytest.approx(6 * math.log2(7776))
        assert passphrase.check(phrase) is None
    assert passphrase.generate(4, " ").count(" ") == 3
    with pytest.raises(ValueError):
        passphrase.generate(3)


@pytest.mark.parametrize(
    "weak",
    [
        "pw",
        "password",
        "summer2024",
        "Summer2024!",
        "Tr0ub4dor&3",
        "a" * 40,
        "abcdefghijklmnopqrstuvwxyz",
        "1234567890123456",
        "abacus abdomen",
        "",
        "   ",
    ],
)
def test_weak_passphrases_are_refused(weak):
    assert passphrase.check(weak) is not None


@pytest.mark.parametrize(
    "strong",
    [
        "la mia nonna aveva un gatto nero di nome Pippo",
        "abacus-abdomen-zoom-yodel",
        "correct horse battery staple and a few more words here",
    ],
)
def test_long_or_generated_passphrases_pass(strong):
    assert passphrase.check(strong) is None


def test_unicode_is_normalised():
    composed, decomposed = "café " * 8, "café " * 8
    assert passphrase.estimate_bits(composed) == passphrase.estimate_bits(decomposed)


def test_cli_generates_passphrases(capsys):
    assert main(["passphrase", "--words", "8", "-n", "3"]) == 0
    lines = capsys.readouterr().out.split()
    assert len(lines) == 3 and all(len(line.split("-")) == 8 for line in lines)


def test_cli_seal_refuses_a_weak_passphrase(tmp_path, capsys):
    from PIL import Image

    from .conftest import processed_image

    covers = []
    for i in range(2):
        path = tmp_path / f"c{i}.png"
        Image.fromarray(processed_image(64, 80, seed=i)).save(path)
        covers.append(str(path))
    secret = tmp_path / "s.txt"
    secret.write_text("x")
    weak = tmp_path / "pw.txt"
    weak.write_text("summer2024\n")
    argv = [
        "seal",
        str(secret),
        *covers,
        "-k",
        "2",
        "-d",
        str(tmp_path / "out"),
        "--passphrase-file",
        str(weak),
    ]
    assert main(argv) != 0
    assert "looks weak" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
    assert main([*argv, "--allow-weak-passphrase"]) == 0

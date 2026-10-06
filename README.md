# shardpix

[![CI](https://github.com/Just-Ipavon/shardpix/actions/workflows/ci.yml/badge.svg)](https://github.com/Just-Ipavon/shardpix/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**English** · [Italiano](README.it.md)

Encrypt a file and hide the key in ordinary-looking photos: split it into
*n* shares, one per image, so that any *k* images open the file and fewer
reveal nothing. The images carry no visible change and pass classical
steganalysis — and the attacks that check it, chi-square and RS analysis,
are built in.

> **Learning project: internally reviewed, not independently audited.** The
> cryptography comes from the `cryptography` library; secret sharing, the
> embedding and the steganalysis are implemented here. The code has been
> through static analysis, fuzzing, mutation testing and a manual review
> against OWASP ASVS — see the [security review](docs/06-security-review.md) —
> but no third party has audited it. For secrets you cannot afford to lose,
> use established tools such as [age](https://age-encryption.org).

![shardpix sealing a file behind 3 of 5 photos, opening it with three of them, and analysing one image](assets/demo.svg)

## How it works

```text
notes.pdf ──AES-256-GCM, random key K──────────►  notes.pdf.spx      store it anywhere
K ─────────Shamir over GF(256), 3 of 5─────────►  5 authenticated shares
share i ───keyed LSB matching, ~0.2% of pixels─►  photo_i.png        one per holder
```

- **The vault file** is ciphertext. It can sit on a shared drive or in an
  e-mail: without the key it is useless.
- **The key** exists only as shares. Any 3 of the 5 rebuild it; 2 say nothing
  about it, not even with unlimited computing power.
- **Each share** is hidden in a photo, scattered over positions only the
  passphrase can find, and encrypted so the hidden bits look like noise.

## Features

| Command | What it does |
| --- | --- |
| `seal` | Encrypts a file and hides one key share in each cover image |
| `unseal` | Opens a vault from any *k* of its images and reports on every image |
| `embed` / `extract` | Hides or recovers a message or file in a single image |
| `split` / `combine` | Shamir secret sharing with printable, authenticated shares |
| `inspect` | Shows whether an image holds a share, and of which vault |
| `analyze` | Runs the chi-square and RS attacks against any image |
| `capacity` | Shows how many bytes an image can hold |

Damaged images are identified rather than silently breaking the recovery, and
a forged set of shares can never pass for the real key.

## Install

```bash
git clone https://github.com/Just-Ipavon/shardpix.git
cd shardpix
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Seal a file behind 3 of 5 photos (prompts for a passphrase)
shardpix seal minutes.pdf photos/*.png -k 3 -p

# Open it with any three of the images
shardpix unseal sealed/minutes.pdf.spx sealed/beach.png sealed/cat.png sealed/street.png -p

# Hide a short message in one image, and read it back
shardpix embed photo.png -o holiday.png -t "meet me at noon" -p
shardpix extract holiday.png -p

# Split a secret into printable shares, any 2 of 3 recover it
shardpix split -t "safe code 4815" -k 2 -n 3 -d shares/
shardpix combine shares/share-*-1.txt shares/share-*-3.txt

# Look for the statistical fingerprints of LSB embedding
shardpix analyze suspicious.png
```

### Options

| Flag | Meaning |
| --- | --- |
| `-k, --threshold` | Images (or shares) needed to recover |
| `-n, --shares` | Shares to create (`split`) |
| `-d, --directory` | Output directory (`seal`: default `./sealed`; `split`: one file per share) |
| `-p, --passphrase` | Prompt for a passphrase |
| `--passphrase-file` | Read the passphrase from the first line of a file |
| `-m, --method` | `matching` (default) or `replacement`, for comparisons |
| `-o, --output` | Output file |
| `--name` | Vault file name (`seal`) |
| `-f, --force` | Overwrite existing outputs (inputs are never overwritten) |

Passphrases are never accepted as command line arguments, which would leave
them in the shell history and the process list.

### When something is wrong

`unseal` reports what happened to every image — here one holder cropped their
photo and another sent the wrong one — so even a failed recovery tells you
which holder to call:

```text
  Image                Share    Status        Detail
  sealed/cat.png          #3    used
  sealed/street.png       #5    used
  sealed/beach.png        #2    used
  sealed/rocket.png             no payload    no share: wrong passphrase or edited image
  old/photo.png                 no payload    no share: wrong passphrase or edited image
Recovered minutes.pdf (47.1 KiB) to minutes.pdf
```

## Detectability

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/rs-estimate-dark.png">
  <img alt="RS steganalysis estimate against true embedding rate: LSB replacement is measured almost exactly, shardpix stays near zero at every rate" src="assets/rs-estimate-light.png">
</picture>

RS analysis measures classic LSB replacement almost exactly and does not see
shardpix at any rate. At the rate a vault actually uses — 0.05% to 0.5% of the
samples — the median change in the RS estimate over ten photographs is 0.07
points. The least significant bit plane tells the same story to the naked eye:

![Least significant bit plane: clean photo, a naive tool after embedding 50% sequentially, and shardpix after embedding a vault share](assets/lsb-planes.png)

The full results, the chi-square attack and the known limitations are in
[docs/05-security-analysis.md](docs/05-security-analysis.md). Reproduce them
with `pip install -e ".[bench]"` and `python -m shardpix.analysis.benchmark`.

## Design notes

**Split the key, not the file.** Only the 32-byte key is shared, so every
image carries about 160 bytes however large the file is. A small payload is
what keeps the images statistically indistinguishable from the originals.

**Shares check each other without leaking anything.** Plain Shamir silently
returns garbage if one share is damaged. Each share here carries a MAC, but the
MAC key is shared together with the secret: fewer than *k* shares stay
independent of the secret even if it is a short password, which would not be
true with a MAC keyed by the secret itself.

**A forged set of shares cannot win.** The vault's group id is public, so
anyone can fabricate shares that authenticate each other. Recovery looks for
every cluster of mutually consistent shares and lets the vault's AES-GCM tag
decide which one is real.

**Measured, then fixed.** The first version used plain LSB matching. The
benchmark showed RS reading 22% on a photo with large black areas: a sample at
0 can only move up, and a one-way move looks exactly like LSB replacement.
Samples outside 2–253 are now never used, and the reading dropped to 4.5%.

**Positions cost what the payload costs.** Positions come from a
rejection-sampled ChaCha20 walk keyed by the passphrase and a per-image salt.
Placing a share in a 48-megapixel photo takes as long as in a thumbnail, and
two images sealed with the same passphrase share nothing.

**Every format is pinned.** Known-answer tests fix the walk, the share bytes,
the stego pixels and the vault bytes, so a refactor or a library upgrade that
would make existing images unreadable fails the build first.

## Architecture

```text
shardpix/
├── cli.py              commands, passphrase input, overwrite protection, exit codes
├── vault.py            seal and unseal: AES-256-GCM + Shamir + steganography
├── stego.py            key derivation, keyed walk, LSB matching, framing
├── shamir.py           secret sharing, share format, MACs, robust recovery
├── gf256.py            GF(2^8) arithmetic and Lagrange interpolation
├── images.py           any image in, lossless PNG out
├── errors.py           exception hierarchy
└── analysis/
    ├── chi_square.py   Westfeld–Pfitzmann chi-square attack
    ├── rs.py           Fridrich–Goljan–Du RS analysis
    └── benchmark.py    detectability experiments and charts
```

## Documentation

Full technical documentation lives in [docs/](docs/README.md): architecture
and design decisions, use case specifications, a function-by-function
reference, the runtime behaviour, a security analysis and an internal
security review — with UML diagrams throughout. To report a vulnerability,
see [SECURITY.md](SECURITY.md).

| Document | Contents |
| --- | --- |
| [01 — Architecture](docs/01-architecture.md) | Context, packages, data model, on-disk formats, eleven architectural decisions |
| [02 — Use cases](docs/02-use-cases.md) | Actors, use case diagram, nine detailed specifications, operational scenarios |
| [03 — Function reference](docs/03-function-reference.md) | Every function: behaviour, edge cases, errors, covering tests |
| [04 — Runtime behaviour](docs/04-runtime-behaviour.md) | Sequence diagrams, the share recovery algorithm, exit codes, timing |
| [05 — Security analysis](docs/05-security-analysis.md) | Threat model, security properties, steganalysis results, limitations |
| [06 — Security review](docs/06-security-review.md) | Static analysis, fuzzing, mutation testing, ASVS checklist, findings and fixes |

## License

MIT — see [LICENSE](LICENSE).

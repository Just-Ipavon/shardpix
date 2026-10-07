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

## Why it matters

Splitting a key with Shamir's scheme and hiding the shares in pictures is not
a new idea. What is usually missing is the question an adversary would
actually ask: **not "does this one photo hide something?", but "do these
photos, taken together, hide something?"** Whoever finds one share often
finds others of the same vault - the holders know each other, use the same
cloud, send to the same people. Schemes that combine secret sharing and
steganography are judged image by image, typically with off-the-shelf tools,
and most hide the shares by LSB embedding.

shardpix is built around that question and measures the answer:

- **One image is the wrong test.** With LSB-style embedding (format 3, kept
  as a baseline) a trained detector is wrong 42.6% of the time on a single
  512x512 image - it looks almost safe. Given 50 images of the same vault and
  pooling its scores, it is wrong only 7.4% of the time: the shares give the
  vault away together.
- **Adaptive embedding holds.** Format 4 places each share with
  syndrome-trellis codes where the photo is textured; on the same 10,000
  BOSSbase images the pooled detector stays at chance, about 50%, from 1 to
  50 images.
- **Real covers, not lab covers.** Phone photos are JPEG, so shardpix hides
  the share inside the JPEG coefficients themselves (format 5) and returns a
  JPEG with the same quality settings and metadata - no conversion that
  would betray the image.
- **Everything is reproducible.** The detectors, the datasets, the positive
  controls and the confidence intervals are in the repository; every number
  in this README can be regenerated.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/pooled-512-dark.png">
  <img alt="Detection error against the number of images of one vault the adversary holds: format 3 falls from 43% to 7% at 50 images, format 4 stays at 50%" src="assets/pooled-512-light.png">
</picture>

*Where the numbers come from:* BOSSbase 1.01, 10,000 photographs at
512x512 greyscale, one vault share per image. A detector (SRM-lite features
with an ensemble classifier) is trained on 5,000 images and scores the other
5,000; groups of 1 to 50 images are then pooled by a likelihood ratio, over
40 random calibration/evaluation splits. 42.6% and 7.4% are the medians,
7.4% with a 4.5-11.5% range. Method and full table:
[docs/05 §5.5.7](docs/05-security-analysis.md#557-several-images-of-one-vault-pooled-steganalysis);
raw data: [docs/data/pooled_512.json](docs/data/pooled_512.json);
reproduce with `python -m shardpix.analysis.pooled`.

## How it works

```text
notes.pdf ──AES-256-GCM, random key K──────────►  notes.pdf.spx      store it anywhere
K ─────────Shamir over GF(256), 3 of 5─────────►  5 authenticated shares
share i ───adaptive ±1, a few hundred changes─►  photo_i.jpg        one per holder
```

- **The vault file** is ciphertext. It can sit on a shared drive or in an
  e-mail: without the key it is useless.
- **The key** exists only as shares. Any 3 of the 5 rebuild it; 2 say nothing
  about it, not even with unlimited computing power.
- **Each share** is hidden in a photo, among candidate positions only the
  passphrase can find, with its few changes placed where the photo is
  textured, and encrypted so the hidden bits look like noise.

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

shardpix needs Python 3.10 or later. Install it with
[pipx](https://pipx.pypa.io), which puts it in its own environment and the
`shardpix` command on your `PATH`, so it works in every terminal and every
folder:

```bash
# 1. pipx, once
sudo apt install pipx            # Debian, Ubuntu, Kali
brew install pipx                # macOS
py -m pip install --user pipx    # Windows
pipx ensurepath                  # then open a new terminal

# 2. shardpix, straight from GitHub
pipx install git+https://github.com/Just-Ipavon/shardpix.git
shardpix --version
```

Update to the latest version with `pipx reinstall shardpix`, remove it with
`pipx uninstall shardpix`.

### Windows and PowerShell

shardpix runs the same in PowerShell (Windows 10 and 11, Python 3.10 or
later; every dependency ships ready-made for Windows). Install pipx with
`py -m pip install --user pipx`, run `py -m pipx ensurepath`, open a new
PowerShell window and continue as above. Two things differ from bash:

- PowerShell does not expand `*.jpg` for other programs; shardpix does it
  itself, so `shardpix seal notes.pdf photos\*.jpg -k 3 -p` works as in bash.
- Never redirect a file with `>` (`shardpix extract out.jpg > file.pdf`):
  Windows PowerShell 5 rewrites the bytes as text and corrupts the file. Use
  `-o file.pdf`, which works everywhere.

### For development

To work on the code, use a virtual environment instead. The `shardpix`
command then exists only while that environment is active: in a new
terminal, run `source .venv/bin/activate` again (`.venv\Scripts\activate` on
Windows).

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

Trained detectors are stronger. On BOSSbase, 10,000 never-compressed
photographs, a rich-model classifier trained under ideal conditions for the
attacker brings a share in a 512x512 greyscale photo to 42.5% detection
error, against 50% for guessing: weak, but not zero. The signal shrinks with
the square root of the cover size: at the lowest rate measured the
detectors were within 1.5 points of chance.

That was format 3. **Format 4, adaptive embedding, is at chance**: the same
detectors on the same 10,000 images are wrong 49.9% of the time on a share,
and only start to see the embedding at 10% of the samples, where format 3
was caught nine times out of ten. Colour photos of 2 megapixels or more
remain the safer choice.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/ml-format-comparison-512-dark.png">
  <img alt="Detection error against embedding rate for format 3 and format 4: format 4 is at 50% at one share and at 43-46% at 10%, where format 3 is at 12-19%" src="assets/ml-format-comparison-512-light.png">
</picture>

The full results, the chi-square attack, the trained detectors and the known
limitations are in [docs/05-security-analysis.md](docs/05-security-analysis.md).
Reproduce them with `pip install -e ".[bench]"` and
`python -m shardpix.analysis.benchmark`, and for the trained detectors
`pip install -e ".[bench,ml]"` and `python -m shardpix.analysis.ml_benchmark`
on a copy of BOSSbase.

## Phone photos and other covers

**Use the photos your phone takes, as they are.** shardpix reads the first
bytes of each cover and hides the share the way that file is stored:

| Cover | How the share is hidden | Output |
| --- | --- | --- |
| JPEG (phone photos, cameras) | In the JPEG's own coefficients (format 5): never decoded or recompressed, same quality tables and EXIF | `.jpg` |
| PNG, TIFF, BMP, RAW export | In the pixels (format 4) | `.png` |
| iPhone HEIC | Not readable: set the camera to *Most Compatible* (JPEG) | — |

Choose textured photos you took yourself and never shared, and send the
results as files, not as "photos" in a messaging app, which re-compresses
them. Details and step-by-step instructions:
[docs/07-covers-and-formats.md](docs/07-covers-and-formats.md).

## Design notes

**Split the key, not the file.** Only the 32-byte key is shared, so every
image carries about 160 bytes however large the file is. A small payload is
what keeps the images hard to tell from the originals.

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

**Changes go where the photo is already noisy.** Since format 4 the
payload is written as a syndrome-trellis code over keyed candidate samples:
the encoder may pick which samples to change and picks those with the lowest
HiLL cost, in foliage and grain rather than in the sky. A share changes
about a third as many samples as before (208 against 633 in a 512x512
photo), and the extractor never needs to know where they are.

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
├── media.py            JPEG or pixels: picks the format from the file
├── jpeg.py             format 5: embedding in JPEG coefficients
├── stego.py            key derivation, keyed walk, formats v4 (adaptive) and v3, framing
├── stc.py              syndrome-trellis codes (Viterbi)
├── costs.py            HiLL embedding costs
├── shamir.py           secret sharing, share format, MACs, robust recovery
├── gf256.py            GF(2^8) arithmetic and Lagrange interpolation
├── images.py           any image in, lossless PNG out
├── errors.py           exception hierarchy
└── analysis/
    ├── chi_square.py   Westfeld–Pfitzmann chi-square attack
    ├── rs.py           Fridrich–Goljan–Du RS analysis
    ├── benchmark.py    detectability experiments and charts
    ├── features.py     SPAM and SRM-lite steganalysis features
    ├── ensemble.py     Kodovský–Fridrich–Holub ensemble classifier
    ├── cnn.py          convolutional steganalysis network (PyTorch)
    ├── ml_benchmark.py trained-detector experiments on BOSSbase
    └── pooled.py       an adversary holding several images of one vault
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
| [07 — Covers and formats](docs/07-covers-and-formats.md) | PNG and JPEG, embedding methods, phone photos |

## License

MIT — see [LICENSE](LICENSE).

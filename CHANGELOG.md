# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Documentation

- docs/05 §5.7 **Related work** (EN and IT): secret sharing hidden in
  images (Thien–Lin, Lin–Tsai, Woźniak–Ogiela–Ogiela, sssteg) and pooled
  steganalysis (Ker, steganographer identification, content-adaptive batch
  steganography), and what shardpix adds. The README credits pooled
  steganalysis to Ker instead of presenting the question as new.
- docs/05 says that the chi-square attack of `analyze` on JPEG is no
  evidence of security (DCTR is), and §5.6 lists the detectors that were
  not run (full SRM, maxSRM, GFR, SRNet); its paragraphs on JPEG covers and
  metadata no longer describe the behaviour before format 5.
- CHANGELOG 2.0.0 no longer says that `--method matching` writes format 3.

## [2.0.0] — 2026-10-07

Major version: the CLI no longer has `--method`, and new images are written
in formats 4 (PNG) and 5 (JPEG). Images and vaults made by 1.x still open.

### Changed

- **`analyze` on JPEG.** The pixel attacks see nothing in a JPEG, whose data
  lives in the DCT coefficients. On a JPEG, `analyze` now runs the chi-square
  attack on the quantised luminance coefficients (Westfeld's attack on
  JSteg) and shows the estimated quality. Its closing note no longer says
  shardpix uses LSB matching: it says what the classical attacks catch and
  where shardpix's adaptive formats are measured.
- **Phone photos are used as taken.** A JPEG cover is embedded in its own
  quantised coefficients (**stego format 5**, `shardpix/jpeg.py`): non-zero
  AC luminance coefficients, UERD costs, the same syndrome-trellis codes as
  format 4; never decoded or recompressed, written back with the same
  quantisation tables and EXIF/ICC metadata. The output is a `.jpg`. Other
  covers still give PNG (format 4). `media.py` picks the format from the
  file's first bytes.
- The CLI no longer has `--method`: format 3 (matching, replacement) stays
  in the library as a benchmark baseline only.
- **JPEG results (docs/05 §5.5.8).** On 10,000 BOSSbase images with DCTR,
  one share in format 5 is at chance at quality 95 (49.6%; 50.0% with fifty
  images pooled) against 18.6% for the non-adaptive baseline. At quality 75
  it is weakly detectable on one image (42.5%) and clearly once pooled
  (7.8% with fifty): covers should be original camera files, not photos
  recompressed by chat apps.
- **Recompressed JPEG warning.** shardpix estimates a JPEG's quality from
  its luminance quantisation table (`jpeg.estimate_quality`, exact for
  standard tables) and `embed` and `seal` warn below 90, where the
  measurements show pooled detection; `capacity` shows the estimate.
- **Progress bar.** `seal`, `unseal`, `embed` and `extract` show a bar
  with the current step (deriving the key, measuring the texture, choosing
  the changes, writing the image) on a terminal; nothing changes when the
  output is piped.
- `extract` and `combine` no longer print a binary payload on a terminal:
  they say what it looks like (PNG, JPEG, PDF, ZIP...) and ask for `-o`.
- **PowerShell.** Wildcards such as `photos\*.jpg`, which PowerShell and
  cmd.exe pass unexpanded, are expanded by shardpix; CI also runs the tests
  on Windows.
- **Fixed:** embedding a large payload in a flat cover, such as a
  screenshot, failed with "no solution avoids the forbidden elements". Every
  change in a flat area costs the maximum, and thousands of them added up
  past the threshold that marks a forbidden sample; the coder now checks
  each chosen change instead of their sum.
- **Detailed help.** `shardpix -h` shows how the pieces fit, a quick start,
  how to pick covers and how passphrases work; every `shardpix COMMAND -h`
  explains what the command does and ends with examples.
- The README installs shardpix with pipx, so the command works in every
  terminal; the virtual environment remains for development.

- **Stego format v4, adaptive embedding, is the default** for `seal`,
  `embed` and the library (`Method.ADAPTIVE`). The salt, the length and the
  sealed body are written as syndrome-trellis codes (Filler, Judas and
  Fridrich) whose changes follow HiLL costs: one share changes about a third
  as many samples as before (208 against 633 on BOSSbase 512x512), in
  texture rather than in smooth areas. Against SPAM and SRM-lite on 10,000
  BOSSbase images a share is at chance (49.9%, against 42.5% for format 3),
  and the detectors only start to see it at 10% of the samples
  (docs/05 §5.5.6). Format 3 images are still read. shardpix 1.1 cannot read
  format 4.

### Added

- `shardpix/stc.py` (syndrome-trellis codes) and `shardpix/costs.py`
  (HiLL and UERD costs); `shardpix/media.py`; new dependency `jpeglib`.
- DCTR features and a JPEG steganalysis benchmark
  (`python -m shardpix.analysis.jpeg_benchmark`).
- docs/07: PNG and JPEG, the embedding methods, and how to get good covers
  from a phone.
- `ml_benchmark --strategy adaptive`.
- Pooled steganalysis (`python -m shardpix.analysis.pooled`, docs/05
  §5.5.7): an adversary holding several images of one vault. Format 3
  falls from 42.6% detection error on one image to 25.7% on ten and 7.4%
  on fifty; format 4 stays at 50% up to fifty. New adversary ADV-5.

- Trained steganalysis (`python -m shardpix.analysis.ml_benchmark`, extra
  `ml`): SPAM and SRM-lite features with the Kodovský–Fridrich–Holub
  ensemble classifier, and a small CNN of the Xu-Net / Yedroudj-Net family,
  evaluated on BOSSbase 1.01 (docs/05 §5.5.5).

### Documentation

- docs/05 §5.5.5 reports the measurement and §5.6 replaces the expectation
  that trained detectors would not see a share: in a 512x512 greyscale photo
  they do, weakly (42.5% error against 50% for guessing; 29.6% for the rich
  model and 31.6% for the CNN at 256x256). Covers should be colour photos of
  at least 2 megapixels.

## [1.1.0] — 2026-10-06

Internal security review: see [docs/06-security-review.md](docs/06-security-review.md).

### Security

- **SR-01** Passphrases are hardened with scrypt N = 2^17, r = 8, p = 1, the
  first OWASP recommendation (was N = 2^15). The cost is stored in each image
  (**stego format v3**), so it can be raised later without breaking images;
  costs above 2^18 are refused before any key derivation.
- **SR-03** Every output file is created exclusively (`O_CREAT | O_EXCL`):
  no race between checking and writing, and dangling symbolic links are
  never followed.

### Fixed

- **SR-02** `chi2_sf` no longer crashes on a subnormal statistic (found by
  fuzzing).

### Added

- Property-based tests and parser fuzzing with Hypothesis
  (`HYPOTHESIS_PROFILE=fuzz` for 3,000 cases per property).
- 31 tests closing gaps found by mutation testing, including a known-answer
  test for embedding without a passphrase.
- `security` CI job: bandit, semgrep, pip-audit and the fuzzing profile.
- `audit` extra, mutmut configuration, `SECURITY.md`.
- A warning when `--method replacement` is used (**SR-05**).

### Changed

- Images made with 1.0.0 cannot be read by 1.1.0 (stego format v3).

## [1.0.0] — 2026-10-06

### Added

- `seal` and `unseal`: encrypt a file with AES-256-GCM, split the key k-of-n
  with Shamir and hide one share per cover image; open it with any k images,
  with a report on every image.
- `inspect`: show whether an image holds a share, and of which vault.
- RS steganalysis (Fridrich, Goljan and Du), reported by `analyze` alongside
  the chi-square attack.
- Detectability benchmark (`python -m shardpix.analysis.benchmark`) with
  charts and tables, and the `bench` extra.
- Technical documentation in `docs/` and an Italian README.
- Known-answer tests pinning the walk, share, stego and vault formats.
- Warnings when a cover was decoded from JPEG.

### Changed

- **Stego format v2.** A random 128-bit salt per image, written at publicly
  walked positions; keys derived from passphrase and salt. Images sealed with
  the same passphrase no longer share positions or keys.
- Positions come from a rejection-sampled ChaCha20 walk whose cost grows with
  the payload, not the image.
- Samples outside 2–253 are never used nor produced, which removes the
  one-way moves that made LSB matching visible to RS on clipped photos.
- At most half of the eligible samples are used.
- Share recovery searches for clusters of mutually authenticating shares,
  tries disjoint blocks first, and reports ambiguous or forged sets instead
  of accepting the first consistent subset.
- PNG files are written at the default compression level (about 8 times
  faster than `optimize`, 4% larger).

### Fixed

- Every expected failure now ends with a one-line error and exit code 1,
  never a traceback (unwritable outputs, non-UTF-8 passphrase files,
  oversized images, tiny images in `analyze`, too many shares).
- `combine -o` can no longer overwrite one of its share files.

### Removed

- Reading images produced by 0.x releases (stego format v1).

## [0.2.0] — 2026-10-06

### Added

- GF(256) arithmetic, Shamir secret sharing with authenticated shares
  (checksum and MAC with a shared MAC key), `split` and `combine`.

## [0.1.0] — 2026-10-06

### Added

- Keyed LSB embedding with an AES-256-GCM sealed payload, `embed`,
  `extract`, `capacity`.
- Chi-square attack (Westfeld and Pfitzmann) and `analyze`.

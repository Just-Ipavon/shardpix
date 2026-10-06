# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- Trained steganalysis (`python -m shardpix.analysis.ml_benchmark`, extra
  `ml`): SPAM and SRM-lite features with the Kodovský–Fridrich–Holub
  ensemble classifier, and a small CNN of the Xu-Net / Yedroudj-Net family,
  evaluated on BOSSbase 1.01 (docs/05 §5.5.5).

### Documentation

- docs/05 §5.5.5 reports the measurement and §5.6 replaces the expectation
  that trained detectors would not see a share: in a 512x512 greyscale photo
  they do, weakly (42.5% error against 50% for guessing). Covers should be
  colour photos of at least 2 megapixels.

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

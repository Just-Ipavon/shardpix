# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

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

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Security

- **`combine` no longer picks the largest of two share sets.** Anyone who has
  seen one share can make a whole set that authenticates a secret of their
  choice, as large as they like; `combine` returned the secret of the largest
  set with exit code 0. It now fails whenever the shares authenticate more
  than one secret, and lists the shares (file and line) behind each, so the
  forged set can be left out. `unseal` was not affected: the vault's GCM tag
  decides there.
- **`--force` keeps outputs private.** Overwriting truncated the existing
  file in place, so it kept its mode and owner: `unseal -f`, `extract -f` or
  `combine -o FILE -f` over a world-readable file, or over one another user
  had planted in a shared directory, left the plaintext readable by others
  (SR-12 promised mode 0600 for every output). The data now goes to a new
  0600 file that atomically replaces the old one, which also means a crash
  never leaves a half-written vault.
- **Restored names stay harmless.** `unseal` without `-o` writes the name
  stored by whoever made the vault. `.bashrc`, `.envrc` or `-rf` came back
  unchanged, and `--force` let such a name replace a shell startup file. Leading
  dots and dashes are now removed, `:<>|?*"` become `_` (no NTFS alternate
  data streams), and Windows device names are recognised after the trailing
  spaces Win32 ignores (`CON .` used to pass as `CON `), including `COM¹`,
  `LPT³`, `CONIN$` and `CONOUT$`. `--force` no longer applies to a restored
  name: replacing an existing file takes `-o`. The property test now checks
  names the way Win32 reads them.
- **No input is overwritten, whatever the case.** The CLI compared output and
  input paths exactly, although SP-11 promised case-folded checks: on macOS
  or Windows `unseal -f` restoring `A.JPG` could overwrite the share image
  `a.jpg`, and `-o` on `embed`, `extract` and `combine` had the same gap.
  Paths are now compared case-folded and by file identity (hard links), and
  the `-i` payload and `--passphrase-file` count as inputs too.

### Added

- `shardpix verify VAULT IMAGES…` (#32): reports, image by image, whether
  each holds a valid share and whether together they open the vault
  (trial-decrypted in memory), without writing or printing the plaintext;
  exit status 0 or 1. `vault.verify` is the library form.
- `seal` reads every written image and the vault back from disk before
  reporting success, and fails with "self-check failed" naming the file if
  one does not give back its share or the source; `--no-check` skips it
  (#32).
- Secrets off the command line (#29): `embed -i -` and `split -i -` read the
  payload from standard input, and `-t -` asks for the text without echo (or
  reads one line from a pipe). A literal `-t VALUE` still works, with a
  warning that it is visible in `ps` and the shell history. The README, the
  help examples and docs/02 no longer put a secret on the command line.

### Fixed

- The benchmark modules no longer default to a `docs/data` path relative to
  the working directory when it is not there: outside a repository checkout
  they ask for `--data` instead of writing results wherever they run.
  `shardpix.analysis.cnn` without PyTorch fails with an install hint.
  The CLI's warning for JPEG files decoded to pixels, which no input could
  reach (every JPEG is embedded natively), is removed with
  `SealedImage.from_jpeg`; `Carrier.from_jpeg` stays for library callers
  of `load_image` (#37).
- JPEG outputs keep everything after the cover's first image: a second MPO
  frame, a gain map, depth data, a motion-photo video or a vendor trailer was
  dropped while `structure_kept` stayed true, leaving an MPF index that
  pointed past the end of the file. The bytes are now copied back unchanged
  and the MPF offsets shifted by the change in the primary image's size; if
  the index cannot be read, the bytes are still kept and the structure is
  reported as changed (#24).
- 16-bit colour PNG and TIFF covers are refused, as docs/07 already said;
  Pillow opened them as 8-bit RGB and the stego image silently lost the extra
  depth (16-bit greyscale was already refused). Animated GIF and PNG and
  multi-page TIFF covers are refused too, instead of coming back as a single
  still image (#25).
- A truncated JPEG is refused as a cover ("truncated JPEG (no end-of-image
  marker)") instead of being accepted while libjpeg printed "Premature end of
  JPEG file" and filled in the missing blocks. Malformed JPEG headers now name
  the file in the error, like every other image error (#26).
- `seal --name` accepts a file name only: a value with a path separator
  (`../escaped.spx`) is a usage error (exit 2) instead of writing the vault
  outside `-d`; `vault.seal` refuses it too (#28).
- `unseal` with a missing or wrong passphrase said "no shares given". When no
  image yields a share of the vault it now says so and names the likely
  causes: wrong or missing passphrase, edited images, or images of another
  vault (#27).

## [3.0.0] — 2026-10-18

Major version. A second security review of 2.0.0 (docs/06 §6.13; like the
first, not an independent audit) found that images of formats 3 to 5 can be
recognised without the passphrase. New images are written in **formats 6
(PNG) and 7 (JPEG)**, and `seal` and `embed` require a passphrase.

**Compatibility.** 3.0.0 reads every image and vault made by 1.x and 2.x
(formats 3 to 5). Images made by 3.0.0 cannot be read by 2.0.0. Scripts
that call `seal` or `embed` without `-p` or `--passphrase-file` now fail
unless they add `--insecure-no-passphrase`. Images in formats 3 to 5 keep
their fingerprint: re-seal them to remove it.

### Security

- **SR-07, a keyless fingerprint (High).** Formats 3 to 5 write the scrypt
  cost byte at public positions, and it decodes to the same value in every
  image: anyone with the source code recognised a shardpix image without
  the passphrase, whatever the steganalysis said. **Stego formats 6 (PNG)
  and 7 (JPEG)** write only the 128-bit salt there and fix the cost by the
  version. docs/06 corrects the original assessment, which had accepted
  SR-07 as harmless.
- **SR-09, JPEG structure (High).** The JPEG output had two JFIF segments
  (or a JFIF on an EXIF-only camera file) and standard Huffman tables on
  covers with optimised ones. It now keeps the cover's metadata byte for
  byte, its segment layout, and optimised tables when the cover has them.
  `embed` and `seal` warn on progressive covers and restart markers, which
  cannot be reproduced.
- **SR-10.** `seal` and `embed` require a passphrase; hiding without one
  takes `--insecure-no-passphrase`.
- **SR-11.** Image size is read from the header and refused above 130
  megapixels before anything is decoded (a crafted JPEG header could ask
  libjpeg for gigabytes).
- **SR-12.** Every output is created with mode 0600 and never through a
  symbolic link, also with `--force`.
- **SR-16.** `seal` no longer crashes on a file that grows while it is read.

### Added

- `--insecure-no-passphrase` for `seal` and `embed`.
- `EmbedReport.structure_kept`, and a warning when a JPEG cover's structure
  cannot be kept.
- GFR features (`features.gfr`); `jpeg_benchmark --detectors`, `--tag` and
  `--dataset-name`, and `pooled --jpeg` with `--detector`, `--tag` and
  `--dataset-name`, to measure several detectors and other cover sets.
- `scripts/srnet_colab.py`: SRNet against format 5 on a Colab GPU
  (docs/05 §5.5.9).

### Changed

- **`analyze` on JPEG.** The pixel attacks see nothing in a JPEG, whose data
  lives in the DCT coefficients. On a JPEG, `analyze` now runs the chi-square
  attack on the quantised luminance coefficients (Westfeld's attack on
  JSteg) and shows the estimated quality. Its closing note no longer says
  shardpix uses LSB matching: it says what the classical attacks catch and
  where shardpix's adaptive formats are measured.
- **License: GPL-3.0-or-later.** `pyproject.toml` and the License sections
  of both READMEs said MIT while `LICENSE` and the badge were GPLv3; they
  now all say GPL-3.0-or-later.
- The benchmarks keep writing formats 4 and 5 (`version=`), so the published
  measurements stay reproducible.

### Fixed

- **DCTR and GFR as published.** Both JPEG feature sets filtered the
  decompressed image after rounding it to integers, and GFR used other
  quantisation steps than the published ones; both detectors were slightly
  weaker than in the literature. `features.decompress(..., rounded=False)`
  and `features.gfr_step` fix it; `jpeg_benchmark` stores a features version
  (2) and never reuses features or results of version 1.
- Ctrl-D, or no input, at the passphrase prompt ended in a traceback; it is
  now a one-line error.

### Documentation

- docs/05 §5.5.9: **SRNet**, trained on a GPU on 10,000 ALASKA2 photographs
  at quality 75 and 95 (curriculum 0.4, 0.2, 0.1, one share; 4,500 training
  pairs), with DCTR measured again on the same images. One share at quality
  95 is at chance for SRNet on one image (49.8%) and on fifty pooled
  (49.2%); at quality 75 it is weakly detectable (45.7%) and more so pooled
  (16.3% with fifty). SRNet trained on 4,500 pairs is weaker than DCTR at
  0.1 bits per coefficient, so DCTR remains the reference.
- docs/06 §6.13: the second review, its findings and what was accepted
  (secrets not wiped, PNG re-encoding, asymmetries of the embedding) and
  why. Every document says the measurements were made on formats 3 to 5
  and apply to 6 and 7, which embed the same way, and describes the
  formats, functions and options of 3.0.0.
- docs/05 §5.5.8: every JPEG measurement again with the corrected
  detectors, and a second cover source, ALASKA2 (real camera photographs at
  quality 75, 90 and 95), measured with DCTR and GFR. One image at quality
  90-95 stays at chance; over fifty images at quality 95 DCTR shows a weak
  trend (43.6% on BOSSbase, 44.3% on ALASKA2), which the README and docs/07
  say; at quality 75 format 5 falls to 7% with fifty images on both
  sources. The GFR reference is corrected; ALASKA2, the source of GFR's
  steps, HiLL, UERD and syndrome-trellis codes are cited.
- docs/05 §5.7 **Related work**: secret sharing hidden in images
  (Thien–Lin, Lin–Tsai, Woźniak–Ogiela–Ogiela, sssteg) and pooled
  steganalysis (Ker, steganographer identification, content-adaptive batch
  steganography), and what shardpix adds. The README credits pooled
  steganalysis to Ker instead of presenting the question as new, and frames
  the threshold constraint (a whole share in every image) as the worst case
  for the steganographer, with key splitting and adaptive embedding as the
  defence shardpix implements and measures.
- docs/05 says that the chi-square attack of `analyze` on JPEG is no
  evidence of security (DCTR is), and §5.6 lists the detectors that were
  not run (full SRM, maxSRM, SRNet on pixels).
- The README (EN and IT) starts from the product: what shardpix gives you
  and what opening a file takes (the `.spx`, any *k* photos and the
  passphrase), diagrams of sealing and opening, install and quick start;
  the research (why it matters, detectability) follows.
- The Italian documentation (`docs_it/`, `README.it.md`) has every change
  above.
- CHANGELOG 2.0.0 no longer says that `--method matching` writes format 3,
  nor lists the `analyze` change, which came after the 2.0.0 tag.

## [2.0.0] — 2026-10-07

Major version: the CLI no longer has `--method`, and new images are written
in formats 4 (PNG) and 5 (JPEG). Images and vaults made by 1.x still open.

### Changed

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

### Fixed

- Embedding a large payload in a flat cover, such as a
  screenshot, failed with "no solution avoids the forbidden elements". Every
  change in a flat area costs the maximum, and thousands of them added up
  past the threshold that marks a forbidden sample; the coder now checks
  each chosen change instead of their sum.

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

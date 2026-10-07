# 5. Security analysis

| | |
| --- | --- |
| Document | SDD-05 — Security analysis |
| System | shardpix 1.1.0 |
| Status | Approved |
| Last revised | 2026-10-06 |

## 5.1 Purpose and scope

This document states what shardpix protects, against whom, on which
arguments, and where it stops. It also reports the steganalysis measurements
that back the claims about detectability.

shardpix is a portfolio and learning project. Its cryptography comes from
audited libraries (ADR-02), its own code is tested against independent
references, and it has been through the internal review documented in
[06-security-review.md](06-security-review.md), but **the system as a whole
has not been audited by an independent third party**. For secrets whose loss would really hurt, prefer established tools
— for example [age](https://age-encryption.org) for file encryption and
[SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
implementations for secret sharing — and treat shardpix as a well-documented
way to understand how such tools are built.

## 5.2 Threat model

### 5.2.1 Assets

| Asset | Description |
| --- | --- |
| A-1 File contents | The sealed file. |
| A-2 Key | The 256-bit key that encrypts it. |
| A-3 Existence | The fact that a given image carries hidden data at all. |
| A-4 Availability | The ability of k honest holders to recover the file. |

### 5.2.2 Adversaries

| Id | Adversary | Capabilities |
| --- | --- | --- |
| ADV-1 | Curious holder or coalition | Holds up to k − 1 images, may know the passphrase, may hold the vault file. |
| ADV-2 | Passive finder | Has some images (a stolen phone, a shared album), not the passphrase. |
| ADV-3 | Steganalyst | Wants to tell stego images from ordinary photos; has the tool and its source. |
| ADV-4 | Active forger | Can modify images, fabricate shares (knows the public group id) and modify the vault file. |

### 5.2.3 Assumptions

1. The machine running shardpix is not compromised while sealing or unsealing.
2. The original covers are not available to the adversary (see §5.6).
3. The passphrase, when used, is not guessable within the scrypt budget.
4. Images travel as files; nobody re-compresses or resizes them on the way.
5. The adversary knows everything about the design (Kerckhoffs's principle):
   every argument below assumes the source code is public, because it is.

## 5.3 Security properties

| Id | Property | Against | Argument | Verified by |
| --- | --- | --- | --- | --- |
| SP-01 | The file is confidential without k shares | ADV-1, ADV-2 | AES-256-GCM under a uniformly random key that exists only as Shamir shares (and briefly in memory). | `test_vault.py::TestFailures` |
| SP-02 | The file and its metadata are authentic | ADV-4 | GCM tag over the ciphertext; the header (group id, k, n, nonce) is the associated data; the file name is inside the ciphertext. | `test_tampered_vault_file`, `test_tampered_header_is_detected` |
| SP-03 | k − 1 shares reveal nothing about the key | ADV-1 | Each byte of key ‖ MAC key has its own random polynomial of degree k − 1, so any k − 1 values are uniform whatever the key. The MACs depend only on the MAC key, which is shared the same way, so they add nothing — even for a low-entropy secret (ADR-08). Only the secret's length leaks. | `TestSecrecy` (exhaustive over all coefficients), `test_mac_is_not_keyed_with_the_secret` |
| SP-04 | Damaged or altered shares are detected and identified | ADV-4 | The checksum catches accidental damage without a key; once k good shares reconstruct the MAC key, every other share is checked and reported. | `TestAuthentication`, `TestRobustSearch` |
| SP-05 | An image reveals neither its payload nor which samples hold it | ADV-2, ADV-3 | Payload sealed with AES-256-GCM; positions from a ChaCha20 walk keyed by scrypt(passphrase, per-image salt); length masked. Without the passphrase the written bits are indistinguishable from random. | `TestAuthentication`, `TestKeyDerivation` |
| SP-06 | A fabricated set of shares is never accepted as the vault key | ADV-4 | Clusters are disjoint; each candidate key is tested against the vault's GCM tag, which a forger cannot satisfy without the real key. | `TestForgedSets` |
| SP-07 | Passphrase guessing is expensive and per image | ADV-2 | scrypt N = 2^17, r = 8 (≈ 128 MiB, ≈ 0.4 s per guess, OWASP's first recommendation), salted per image, so no table can be precomputed for an image size and no guess carries over to another image. | `test_production_scrypt_cost`, `test_same_passphrase_scatters_differently_in_every_image` |
| SP-08 | One error message for every extraction failure | ADV-3, ADV-4 | Wrong passphrase, clean image and modified image all raise the same `PayloadNotFoundError`, so the tool is no oracle for "is there something here?". | `TestAuthentication` |
| SP-09 | Neither classical nor trained steganalysis (SPAM, SRM-lite) detects a vault share in format 4 | ADV-3 | Adaptive ±1 embedding with syndrome-trellis codes and HiLL costs (ADR-12), no forced moves at 0/255 (ADR-06), and a fixed payload of 1,264 bits. At chance on BOSSbase 512x512 (§5.5.6); format 3 was weakly detectable (§5.5.5). | Benchmarks (§5.5.1–5.5.6) |
| SP-10 | Restoring a file cannot escape the output directory or abuse the terminal | ADV-4 | `safe_filename` keeps the base name, strips control and format characters and replaces reserved names. | `TestRestoredNames`, `TestSafeFilename` |
| SP-11 | No input is ever overwritten | User error | Case-folded path identity checks in the CLI and in `seal`. | `TestOutputCollisions`, `test_combine_never_overwrites_its_input` |

What shardpix deliberately does **not** claim: that a share is invisible to
*every* trained detector — format 4 is at chance against SPAM and SRM-lite
(§5.5.6), but stronger detectors were not run — that format 3 shares are
invisible in small covers (they are not, §5.5.5), or that the vault file
itself is inconspicuous — it is recognisable ciphertext.

## 5.4 Cryptographic parameters

| Purpose | Primitive | Parameters | Source |
| --- | --- | --- | --- |
| File encryption | AES-256-GCM | 256-bit random key, 96-bit random nonce, 35-byte AAD | `cryptography` |
| Stego payload encryption | AES-256-GCM | 256-bit derived key, 96-bit random nonce, AAD = domain ‖ version ‖ length | `cryptography` |
| Passphrase hardening | scrypt | N = 2^17, r = 8, p = 1, 128-bit salt per image; cost stored in the image, at most 2^18 accepted | `hashlib` |
| Key separation | HKDF-SHA256 | Labels `order`, `aead`, `length` | `cryptography` |
| Sample positions | ChaCha20 keystream | 256-bit key, rejection-sampled modular reduction | `cryptography` |
| Share authentication | HMAC-SHA256 | 256-bit shared MAC key, tag truncated to 128 bits | `hmac` |
| Share checksum | SHA-256 | Truncated to 32 bits (accidental damage only) | `hashlib` |
| Secret sharing | Shamir over GF(2^8) | Polynomial 0x11B, generator 0x03, k ≤ n ≤ 255 | this project |
| Randomness | `os.urandom` | — | OS CSPRNG |

Nonce reuse is not a concern: every AES-GCM key is used to encrypt exactly
once (the vault key is fresh per vault; the stego key is fresh per image
because the salt is), and the ChaCha20 keys are only ever used to generate a
single keystream.

## 5.5 Steganalysis results

The benchmark embeds random bits — what an encrypted payload looks like — in
ten public-domain photographs from scikit-image (six RGB, four greyscale) at
eleven rates from 0 to 75% of the samples, with four strategies, and runs the
two classical attacks. Run it with `python -m shardpix.analysis.benchmark`;
the raw numbers are in [data/benchmark.json](data/benchmark.json). §5.5.5
adds trained detectors on a standard dataset of 10,000 photographs.

### 5.5.1 RS analysis

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/rs-estimate-dark.png">
  <img alt="RS estimate against true embedding rate: LSB replacement follows the diagonal, shardpix stays near zero at every rate" src="../assets/rs-estimate-light.png">
</picture>

Mean RS estimate over the ten photographs:

| Strategy | 0% | 5% | 10% | 20% | 50% | 75% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| LSB replacement, scattered | +2.0% | +7.3% | +12.9% | +21.2% | +50.9% | +76.8% |
| LSB matching, naive | +2.0% | +2.6% | +2.4% | +1.3% | +2.7% | +3.6% |
| shardpix | +2.0% | +2.2% | +1.4% | +2.3% | +2.2% | +1.4% |

RS measures LSB replacement almost exactly, and sees neither variant of LSB
matching on average. The average hides one case, which is what motivated
ADR-06:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/rs-clipped-dark.png">
  <img alt="On the astronaut photo, naive LSB matching reaches a 30% RS estimate at 75% embedding while shardpix stays at 3%" src="../assets/rs-clipped-light.png">
</picture>

RS estimate per photograph with 50% of the samples carrying data:

| Cover | Clean | LSB replacement | LSB matching, naive | shardpix |
| --- | ---: | ---: | ---: | ---: |
| astronaut | +2.4% | +52.3% | +22.4% | +4.5% |
| chelsea | +0.0% | +49.8% | -0.4% | -1.0% |
| coffee | +2.1% | +52.3% | +1.7% | +3.3% |
| rocket | +0.9% | +51.2% | +0.8% | +0.7% |
| hubble_deep_field | +8.3% | +54.2% | +2.8% | +5.9% |
| immunohistochemistry | -2.5% | +47.9% | -2.2% | +3.2% |
| camera | +1.2% | +52.4% | +1.0% | -0.0% |
| brick | +0.3% | +51.9% | -1.0% | -1.0% |
| grass | +0.7% | +46.3% | -6.0% | +8.2% |
| gravel | +6.9% | +51.1% | +7.8% | -1.9% |

`astronaut` has 11% of its samples at pure black. Under naive LSB matching
those can only move up, from 0 to 1 — exactly the move LSB replacement makes
— and RS reads 22%. Skipping samples outside 2–253 brings it to 4.5%. On the
fine greyscale textures (`grass`, `gravel`) RS scatters by several points
between runs whatever is embedded: a single channel gives it fewer groups to
average over.

### 5.5.2 The operating point: one vault share

The figures above go up to 75% to show the shape of each curve. A vault puts
158 bytes into each image:

| Cover | Size | Share embedding rate | RS, clean | RS, with share | Change |
| --- | --- | ---: | ---: | ---: | ---: |
| astronaut | 512x512 RGB | 0.161% | +2.45% | +2.47% | +0.02% |
| chelsea | 451x300 RGB | 0.311% | +0.05% | +0.01% | -0.04% |
| coffee | 600x400 RGB | 0.176% | +2.12% | +2.13% | +0.01% |
| rocket | 640x427 RGB | 0.154% | +0.92% | +0.91% | -0.01% |
| hubble_deep_field | 1000x872 RGB | 0.048% | +8.31% | +8.30% | -0.02% |
| immunohistochemistry | 512x512 RGB | 0.161% | -2.46% | -2.35% | +0.11% |
| camera | 512x512 grey | 0.482% | +1.24% | +1.35% | +0.11% |
| brick | 512x512 grey | 0.482% | +0.29% | +0.18% | -0.11% |
| grass | 512x512 grey | 0.482% | +0.68% | -0.02% | -0.70% |
| gravel | 512x512 grey | 0.482% | +6.89% | +7.01% | +0.12% |

The median change is 0.07 points, against clean photographs that already
range from −2.5% to +8.3%. The largest change, 0.7 points, is on a greyscale
texture, inside the scatter described above. At this rate, RS cannot tell a
sealed image from the photo it came from.

### 5.5.3 Chi-square attack

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/chi-square-dark.png">
  <img alt="Chi-square probability over the share of the image scanned: sequential replacement stays at 1 until the payload ends, scattered replacement and shardpix drop to 0 within a few percent like the clean cover" src="../assets/chi-square-light.png">
</picture>

The chi-square attack is decisive against what naive tools do — write the
payload from the first pixel with LSB replacement — and reads the payload
length off the curve (it ends a little after the true 50%, because the test
statistic is cumulative). Scattered replacement at the same rate keeps it
high only over the first few percent, and shardpix behaves like the clean
cover.

The attack is also prone to false positives: on four of the ten clean
photographs (`chelsea`, `immunohistochemistry`, `grass`, `gravel`), whose
histograms are naturally smooth, it reports a signature over 46% to 100% of
the image. `analyze` reports it as evidence, not as a verdict.

### 5.5.4 The visual attack

![Least significant bit plane of the camera photo: clean, after a naive tool embedded 50% sequentially, and after a shardpix vault share](../assets/lsb-planes.png)

The least significant bit plane of a photograph is not pure noise: smooth
regions leave structure in it, as the sky bands at the top of `camera` show.
A naive tool replacing the first half of the image erases that structure, and
the boundary is visible to the eye. A vault share changes a few hundred
samples out of 262,144 and is invisible.

### 5.5.5 Trained detectors

Chi-square and RS need no training. Modern steganalysis does: a detector
learns the difference between covers and stego images from thousands of
examples. This section runs three such detectors against shardpix:

| Detector | Features | Classifier |
| --- | --- | --- |
| SPAM | 686 Markov transition probabilities of pixel differences, designed against LSB matching (Pevný, Bas and Fridrich) | Ensemble of Fisher linear discriminants on random subspaces (Kodovský, Fridrich and Holub) |
| SRM-lite | 3,125 co-occurrences of five rich-model residuals (Fridrich and Kodovský); the full SRM has 34,671 | The same ensemble |
| CNN | Learnt, after a fixed bank of 14 SRM high-pass filters and a truncation unit | Five convolutional blocks of the Xu-Net / Yedroudj-Net family, trained with curriculum from high to low rates |

**Data.** BOSSbase 1.01, the reference set for spatial-domain steganalysis:
10,000 greyscale 512x512 photographs converted from RAW, never
JPEG-compressed. Every cover is embedded with shardpix's own strategy
(LSB matching on samples 2–253, keyed positions, random bits) at each rate.
Half of the images train the detector, the other half test it; a cover and
its stego image are always on the same side.

**The attacker is given every advantage.** The detector is trained at the
exact rate it is tested on and on images from the same source as the test
images. In the field a steganalyst knows neither the rate nor the camera and
processing that produced the covers, and *cover-source mismatch* - training
on one kind of image and testing on another - is known to cost trained
detectors accuracy, often substantially. The numbers below are
therefore an upper bound on what these detectors achieve, not an estimate of
what they would achieve on a real holder's photo.

**Metric.** P_E = (false alarms + missed detections) / 2 on the 5,000 test
pairs, at the detector's own decision threshold: 50% is guessing, 0% is
never wrong. The interval is the 95% binomial interval (about ±1 point).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/ml-detection-512-dark.png">
  <img alt="Detection error of SPAM and SRM-lite against embedding rate on BOSSbase 512x512: from 4-8% at 40% embedding up to 42-45% at one vault share and 48-49% at 0.1%" src="../assets/ml-detection-512-light.png">
</picture>

BOSSbase at its native 512x512 (raw numbers in
[data/ml_benchmark_512.json](data/ml_benchmark_512.json)):

| Samples carrying bits | Bits | M/√N | SPAM | SRM-lite |
| ---: | ---: | ---: | ---: | ---: |
| 40% | 104,858 | 205 | 8.1% | 4.0% |
| 10% | 26,214 | 51 | 19.0% | 12.1% |
| 2% | 5,243 | 10 | 34.2% | 28.4% |
| 1% | 2,621 | 5.1 | 40.0% | 35.8% |
| **0.48% (one share)** | **1,264** | **2.5** | **45.0%** [44.0, 46.0] | **42.5%** [41.5, 43.5] |
| 0.25% | 655 | 1.3 | 47.1% [46.1, 48.1] | 45.6% [44.6, 46.6] |
| 0.1% | 262 | 0.5 | 49.0% [48.0, 50.0] | 48.5% [47.6, 49.5] |

Resized to 256x256, the size most deep-learning steganalysis is evaluated
at, a share is 1.93% of the samples (raw numbers in
[data/ml_benchmark_256.json](data/ml_benchmark_256.json)):

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/ml-detection-256-dark.png">
  <img alt="Detection error at 256x256 for SPAM, SRM-lite and the CNN: 5-7% at 40% embedding, 30-36% at one vault share, 43-46% at 0.5%" src="../assets/ml-detection-256-light.png">
</picture>

| Samples carrying bits | Bits | M/√N | SPAM | SRM-lite | CNN |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 40% | 26,214 | 102 | 6.9% | 4.7% | 5.2% |
| 20% | 13,107 | 51 | 13.0% | 8.1% | 11.6% |
| 10% | 6,554 | 26 | 18.9% | 12.7% | 15.7% |
| 5% | 3,277 | 13 | 26.2% | 19.0% | 20.5% |
| 2% | 1,311 | 5.1 | 36.1% | 28.7% | — |
| **1.93% (one share)** | **1,264** | **4.9** | **35.9%** [34.9, 36.8] | **29.6%** [28.7, 30.5] | **31.6%** [30.6, 32.5] |
| 1% | 655 | 2.6 | 42.2% | 37.1% | 37.8% |
| 0.5% | 328 | 1.3 | 46.0% | 42.9% | — |

The CNN was trained once, from 40% down to 1%, fine-tuning at each rate
from the previous one (20 epochs at 40%, then 5 per rate, on 128x128
windows; about two hours on four CPU cores). It is not run at 512x512, where
training and testing would take several times longer on a CPU.

What this shows:

1. **The detectors work.** At 40% embedding the rich model is wrong 4% of
   the time.
2. **One share in a 512x512 greyscale photo is detectable, weakly.** P_E is
   42.5% (AUC 0.61) for SRM-lite: well above chance with these sample sizes,
   but a detector that is wrong on 42 of every 100 decisions. At a realistic
   base rate - few of the photos a steganalyst inspects carry anything -
   almost every alarm it raises would be false. The expectation stated
   before this measurement, that trained detectors would not see a share at
   all, was wrong for covers this small.
3. **Smaller covers are worse.** At 256x256 the same 158 bytes are 1.93% of
   the samples and SRM-lite drops to 29.6%. The CNN reaches 31.6%: a
   network of this size, trained on a CPU, matches the rich model rather
   than beating it, so deep learning does not change the picture at this
   scale.
4. **What matters is the payload against the square root of the cover.**
   The *square-root law* of steganographic capacity (Ker et al.) says a fixed
   payload of M bits in a cover of N samples becomes harder to detect as
   M/√N decreases, not merely as M/N does. The share is fixed at 1,264 bits,
   so the cover size alone decides. At M/√N ≈ 0.5 SPAM is at chance within
   its interval and SRM-lite is 1.5 points from it (48.5%, AUC 0.52). The two image sizes agree with the law only
   roughly (at M/√N = 1.3, SRM-lite reads 45.6% at 512 and 42.9% at 256),
   because resizing changes the noise the detectors rely on.

What it means for a real cover: a share in a 512x512 greyscale image has
M/√N ≈ 2.5; in a 1-megapixel colour photo (3 million samples) ≈ 0.7; in a
2-megapixel colour photo ≈ 0.5, the lowest point measured; in a
12-megapixel phone photo ≈ 0.2, more than twice below it. **Use colour photos of at least
2 megapixels** — the advice was derived for format 3; format 4 is already
at chance at 512x512 (§5.5.6), and more samples remain the safer choice. That threshold is an extrapolation along the square-root law
from greyscale 512x512 images, not a measurement on large photos, which
BOSSbase does not contain.

Reproduce (about one hour for the feature-based detectors at each size on
four CPU cores; the CNN about two more):

```bash
pip install -e ".[bench,ml]"
python -m shardpix.analysis.ml_benchmark BOSSbase_1.01/ --size 512 --detectors spam,srm_lite
python -m shardpix.analysis.ml_benchmark BOSSbase_1.01/ --size 512 --detectors spam,srm_lite --rates 0.0025,0.001
python -m shardpix.analysis.ml_benchmark BOSSbase_1.01/ --size 256 --rates 0.4,0.2,0.1,0.05,0.02,0.01,0.005 --detectors spam,srm_lite
python -m shardpix.analysis.ml_benchmark BOSSbase_1.01/ --size 256 --rates 0.4,0.2,0.1,0.05,0.01 --detectors cnn --fine-epochs 5 --checkpoint cnn-256
```

### 5.5.6 Adaptive embedding (format 4)

§5.5.5 found that format 3 is weakly visible to trained detectors in small
covers. Format 4 (01 ADR-12) writes the same payload as a syndrome-trellis
code whose changes follow HiLL costs: about a third as many changes (208
against 633 per share in BOSSbase 512x512, 07 §7.3), all in texture. The
same experiment, the same 10,000 BOSSbase images, the same split and the
same detectors were run against it; the stego images are produced by
`stego.embed` itself (`ml_benchmark --strategy adaptive`), so what is
measured is exactly what the tool writes.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/ml-format-comparison-512-dark.png">
  <img alt="Detection error against embedding rate for format 3 and format 4 on BOSSbase 512x512: format 4 is at 50% at one share and at 43-46% at 10%, where format 3 is at 12-19%" src="../assets/ml-format-comparison-512-light.png">
</picture>

Raw numbers in [data/ml_benchmark_512_adaptive.json](data/ml_benchmark_512_adaptive.json).

| Samples carrying bits | Format 3, SPAM | Format 3, SRM-lite | **Format 4, SPAM** | **Format 4, SRM-lite** |
| ---: | ---: | ---: | ---: | ---: |
| **0.48% (one share)** | 45.0% | 42.5% | **49.9%** [48.9, 50.9], AUC 0.50 | **49.9%** [48.9, 50.8], AUC 0.50 |
| 10% | 19.0% | 12.1% | **46.0%** [45.0, 47.0], AUC 0.57 | **42.9%** [42.0, 43.9], AUC 0.61 |

What this shows:

1. **One share in format 4 is at chance.** Both detectors, trained at the
   exact rate on images from the same source as the test images, are wrong
   49.9% of the time; the 95% intervals contain 50% and the AUC is 0.50.
   Format 3 at the same rate gave 42.5%.
2. **The measurement is not blind.** At 10% the same detectors see format 4
   (SRM-lite 42.9%, interval well below 50%), so the experiment can detect
   it when there is something to detect. A null result with no positive
   control would have proved nothing.
3. **The gain is large.** Format 4 at 10% of the samples is about as
   visible as format 3 at one share (42.9% against 42.5%), with twenty
   times the payload. In square-root-law terms the same cover now carries
   a far larger payload at the same risk; for a fixed share it moves the
   operating point well inside the region where these detectors fail.
4. **What it does not show.** Stronger detectors (the full SRM with its
   min-max residuals, SRNet trained on a GPU) are designed for adaptive
   embedding and could still find something at one share. The intermediate
   rates (5%, 2%, 1%) are being measured with the same setup and will be
   added to the data file; a first run, interrupted before it was saved,
   gave 49.7% (SPAM) and 50.3% (SRM-lite) at 1%.

Reproduce (about 1.5 hours per rate on four CPU cores, the
syndrome-trellis coder being pure numpy):

```bash
python -m shardpix.analysis.ml_benchmark BOSSbase_1.01/ --size 512 --strategy adaptive --detectors spam,srm_lite --rates 0.00482177734375
python -m shardpix.analysis.ml_benchmark BOSSbase_1.01/ --size 512 --strategy adaptive --detectors spam,srm_lite --rates 0.1,0.05,0.02,0.01
```


## 5.6 Known limitations

**Not independently audited.** See §5.1 and 06.

**Trained steganalysis: measured against two detectors, not all.** A
format-4 share on BOSSbase 512x512 is at chance for SPAM and SRM-lite
(§5.5.6); format 3 was weakly visible (42.5% for SRM-lite, §5.5.5) and is
still what `--method matching` writes. The detectors used are SPAM, a
3,125-feature subset of the spatial rich model and, for format 3, a small
CNN trained on a CPU. The full SRM (34,671 features, including the min-max
residuals designed against adaptive embedding) and larger networks such as
SRNet, trained on a GPU, would likely do better and were not run. All
measurements use one image source (BOSSbase); in the field, cover-source
mismatch works against the detector.

**JPEG covers.** Pixels decoded from a JPEG obey the block quantisation of
the original file. Changing any of them by ±1 breaks that structure, which
JPEG-compatibility steganalysis (Fridrich, Goljan and Du) can detect at any
embedding rate. A PNG that came from a JPEG is also unusual in itself. The
CLI warns when a cover was decoded from JPEG; use photos that were never
JPEG-compressed (RAW exports, PNG screenshots).

**Cover availability.** If the adversary has the original cover, a pixel
comparison reveals every changed sample. Never publish the covers, and do
not use images found online: a reverse image search finds the original.

**Transport.** Messaging apps and social networks re-compress or resize
images, which destroys the payload. Images must travel as files.

**Metadata.** Output PNGs keep the ICC profile but not EXIF data. A
smartphone photo that arrives as a metadata-less PNG may itself be unusual
in some contexts.

**The vault file is not hidden.** Its magic, group id, threshold and number
of shares are in clear (authenticated, not encrypted). Anyone who finds it
knows it is a shardpix vault and how many images open it — but not its file
name, contents or which images belong to it.

**One passphrase per vault.** All images of a vault use the same passphrase,
so every holder who must be able to take part in a recovery knows it. The
passphrase protects the images against outsiders (ADV-2); confidentiality
among holders rests on the threshold (SP-03), not on the passphrase.

**Python is not constant-time.** GF(256) table lookups and other operations
on secret data have data-dependent timing, and Python cannot reliably wipe
secrets from memory. Acceptable for a local tool run on a trusted machine
(assumption 1); not acceptable for a service.

**Search budget.** An adversary who controls many of the shares offered to
`combine` can exhaust the 10,000-subset budget, turning a recovery into an
error. They cannot turn it into a wrong answer.

**Residual forced moves.** Samples at exactly 2 or 253 still move in a fixed
direction when they carry a mismatching bit. They are far rarer than clipped
samples and did not register in the benchmark.

**Format v3.** The stego format changed twice (ADR-04, ADR-05, and the scrypt
cost raised in 1.1, see 06); images produced by 0.x or 1.0 cannot be read by
1.1. Because the cost is now stored in each image, future increases will not
break compatibility.

## 5.7 References

1. A. Shamir, "How to share a secret", *Communications of the ACM*, 1979.
2. A. Westfeld and A. Pfitzmann, "Attacks on steganographic systems",
   *Information Hiding*, 1999 (chi-square attack, visual attack).
3. J. Fridrich, M. Goljan and R. Du, "Reliable detection of LSB steganography
   in color and grayscale images", *ACM Workshop on Multimedia and Security*,
   2001 (RS analysis).
4. J. Fridrich, M. Goljan and R. Du, "Steganalysis based on JPEG
   compatibility", *SPIE Multimedia Systems and Applications*, 2001.
5. J. Harmsen and W. Pearlman, "Steganalysis of additive noise modelable
   information hiding", *SPIE Electronic Imaging*, 2003.
6. A. Ker, "Steganalysis of LSB matching in grayscale images", *IEEE Signal
   Processing Letters*, 2005.
7. J. Fridrich and J. Kodovský, "Rich models for steganalysis of digital
   images", *IEEE Transactions on Information Forensics and Security*, 2012.
8. M. Boroumand, M. Chen and J. Fridrich, "Deep residual network for
   steganalysis of digital images" (SRNet), *IEEE Transactions on Information
   Forensics and Security*, 2019.
9. C. Percival, "Stronger key derivation via sequential memory-hard
   functions" (scrypt), 2009.
10. NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation:
    Galois/Counter Mode (GCM) and GMAC*, 2007.
11. SatoshiLabs, *SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes*.
12. T. Pevný, P. Bas and J. Fridrich, "Steganalysis by subtractive pixel
    adjacency matrix" (SPAM), *IEEE Transactions on Information Forensics and
    Security*, 2010.
13. J. Kodovský, J. Fridrich and V. Holub, "Ensemble classifiers for
    steganalysis of digital media", *IEEE Transactions on Information
    Forensics and Security*, 2012.
14. P. Bas, T. Filler and T. Pevný, "Break our steganographic system: the ins
    and outs of organizing BOSS", *Information Hiding*, 2011 (BOSSbase).
15. G. Xu, H.-Z. Wu and Y.-Q. Shi, "Structural design of convolutional neural
    networks for steganalysis", *IEEE Signal Processing Letters*, 2016.
16. M. Yedroudj, F. Comby and M. Chaumont, "Yedroudj-Net: an efficient CNN
    for spatial steganalysis", *IEEE ICASSP*, 2018.
17. A. Ker, T. Pevný, J. Kodovský and J. Fridrich, "The square root law of
    steganographic capacity", *ACM Workshop on Multimedia and Security*, 2008.

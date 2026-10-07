# 6. Security review

| | |
| --- | --- |
| Document | SDD-06 — Internal security review report |
| System | shardpix 1.1.0 (review started on 1.0.0) |
| Status | Complete |
| Last revised | 2026-10-06 |

## 6.1 Purpose, scope and independence

This report documents a structured security review of shardpix: what was
examined, how, what was found, and what was done about it. It follows the
shape of a third-party audit report so that a future independent auditor can
start from it.

**It is not an independent audit.** The review was carried out alongside the
development of the code it reviews. Its value lies in the method being
explicit and reproducible — every tool, configuration and result below can
be re-run from the repository — not in the independence of the reviewer.
See §6.12 for what an independent review should focus on.

**In scope:** every module of the `shardpix` package, with emphasis on
`stego.py`, `shamir.py`, `gf256.py` and `vault.py`; the on-disk formats; the
command line interface's handling of files and secrets; the dependencies.

**Out of scope:** the `cryptography`, NumPy and Pillow libraries themselves;
the host operating system; trained steganalysis (see 05 §5.6).

## 6.2 Method

| Activity | Tool | Version | What it establishes |
| --- | --- | --- | --- |
| Static analysis | bandit | 1.9.4 | Known insecure Python patterns (weak randomness, unsafe deserialisation, shell injection, hard-coded secrets, …) |
| Static analysis | semgrep with the 112 rules of the official `python` rule set | 1.179.0 | Same class of issues, including cryptographic API misuse rules |
| Dependency audit | pip-audit against the PyPI advisory database | 2.10.1 | Known vulnerabilities in the four runtime dependencies and their dependencies |
| Property-based testing and fuzzing | Hypothesis | 6.168 | Correctness claims hold for generated inputs; parsers fail only with their own error on arbitrary input |
| Mutation testing | mutmut, with every surviving mutant re-run against the full suite outside mutmut | 3.8.0 | The tests actually detect faults in the cryptographic core, rather than merely executing it |
| Manual review | OWASP ASVS 4.0.3 chapter V6 (stored cryptography) and selected controls of V2, V5, V7, V12, V14; OWASP Password Storage Cheat Sheet | — | Design and implementation against an external checklist |

Severity uses four levels: **High** (breaks confidentiality or integrity of
sealed data under the threat model of 05), **Medium** (weakens a security
property or a stated parameter), **Low** (robustness or defence in depth),
**Info** (no direct impact; process or documentation).

## 6.3 Summary

| | |
| --- | --- |
| Findings | 8: 0 High, 1 Medium, 2 Low, 5 Info |
| Fixed | 5 (all Medium and Low, 2 Info) |
| Accepted with rationale | 3 Info |
| Static analysis | 0 issues (bandit, 112 semgrep rules); 0 known vulnerabilities in 9 dependencies |
| Fuzzing | 16 properties, 48,000 generated cases per run in the fuzz profile; 1 crash found and fixed |
| Mutation testing | 1,575 mutants; 90.9% detected, 95.6% of the non-equivalent ones; every survivor inspected (§6.8) |
| Tests | 255 before the review, 310 after |

No finding compromised the confidentiality or integrity of sealed files. The
most significant result is SR-01: the passphrase hardening was below the
current OWASP recommendation, and the image format had no room to raise it
without breaking existing images. Both are fixed in 1.1.0.

## 6.4 Findings

| Id | Severity | Title | Found by | Status |
| --- | --- | --- | --- | --- |
| SR-01 | Medium | scrypt cost below the OWASP recommendation, and not stored in the image | Manual review | Fixed in 1.1.0 |
| SR-02 | Low | `chi2_sf` crashes on a subnormal statistic | Fuzzing | Fixed in 1.1.0 |
| SR-03 | Low | Outputs created with check-then-write: a race window, and dangling symbolic links followed | Manual review | Fixed in 1.1.0 |
| SR-04 | Info | Test gaps: public-mode key derivation, report fields and error details not pinned | Mutation testing | Fixed in 1.1.0 (31 tests added) |
| SR-05 | Info | `--method replacement` offered without a warning | Manual review | Fixed in 1.1.0 |
| SR-06 | Info | Dependencies specified by lower bound only; no lock file | Manual review | Accepted |
| SR-07 | Info | Salt and cost positions are public and depend only on the eligible samples | Manual review | Accepted |
| SR-08 | Info | `random_bytes` injection hook in the public API | Manual review | Accepted |

### SR-01 — scrypt cost below the OWASP recommendation, and not stored (Medium)

**Observation.** Passphrases were hardened with scrypt N = 2^15, r = 8, p = 1
(32 MiB). The OWASP Password Storage Cheat Sheet recommends N = 2^17, r = 8,
p = 1 (128 MiB), or equivalents trading memory for parallelism such as
N = 2^15 with p = 3. With p = 1, 2^15 provides about a third of the
recommended work per guess. In addition the parameters were implicit in the
format: raising them would have made every existing image unreadable, which
in practice means they would never be raised (ASVS 6.2.4, crypto agility).

**Impact.** An attacker holding a stego image (ADV-2) can test passphrase
guesses about three times faster than recommended. Confidentiality of the
*file* is not affected — it rests on the threshold, not on the passphrase —
but the claim that an image does not reveal its share (SP-05) is weaker for
low-entropy passphrases.

**Fix.** Stego format v3 stores log2(N) in one byte next to the salt, along
the public walk. New embeddings use N = 2^17 (≈ 0.4 s and 128 MiB per image).
Extraction accepts 2^10 to 2^18 and refuses anything else *before* calling
scrypt, so a forged image cannot make the extractor allocate gigabytes (a
cost of 2^30 would request 128 GiB). Tests: `test_cost_is_read_from_the_image`,
`test_forged_cost_is_rejected_before_any_key_derivation`,
`test_production_scrypt_cost`, updated known-answer tests.

**Trade-off.** Sealing five images now spends about 2 seconds in scrypt, and
unsealing three about 1.3 seconds. Images made with 1.0 are not readable by
1.1; no 1.0 images had been distributed.

### SR-02 — `chi2_sf` crashes on a subnormal statistic (Low)

**Observation.** Hypothesis generated `statistic = 5e-324` (the smallest
positive double). Halving it underflows to 0, and the series evaluation then
computes `log(0)`, raising `ValueError`.

**Impact.** A crash in `analyze` for a statistic that real images never
produce; no security impact, but exactly the kind of edge a parser of
attacker-supplied data must not have.

**Fix.** The zero test is done after halving. Regression test
`test_subnormal_statistic_does_not_crash`.

### SR-03 — Check-then-write on outputs (Low)

**Observation.** Every output was protected by `path.exists()` followed by a
write. Between the two there is a window in which a file can appear (TOCTOU),
and `exists()` returns `False` for a *dangling* symbolic link, which the
write then follows: a link named like the file restored by `unseal` would
redirect the write to the link's target.

**Impact.** Requires an attacker able to create links in the directory where
the user writes, which assumption 1 of 05 largely excludes. Defence in depth.

**Fix.** All outputs go through `images.write_new`, which creates files with
`O_CREAT | O_EXCL` unless `--force` is given: the existence check and the
creation are one atomic operation, and any existing name — including a
dangling link — is refused. Tests: `TestWriteNew`,
`test_dangling_symlink_is_never_followed`.

### SR-04 — Test gaps found by mutation testing (Info)

**Observation.** Mutation testing showed faults the suite would not have
caught. The most consequential: no test pinned key derivation *without* a
passphrase, so changing the public-mode derivation string would have
silently made every passphrase-less image unreadable while all tests passed.
Others: per-image report fields (`path`, `share_index`, `detail`) that could
be wrong without failing a test; the `rejected` details carried by share
errors; the search budget and block order; exact capacity boundaries; the
behaviour of the naive bounds used by the benchmark.

**Fix.** 31 tests added (see §6.8), including a known-answer test for
public-mode embedding. The 55 tests added by the review overall are these, the
16 properties of §6.7 and 8 regression tests for SR-01, SR-02, SR-03 and SR-05.

### SR-05 — Replacement mode without warning (Info)

`--method replacement` exists to demonstrate what the attacks detect. Used
for a real vault it makes the images detectable (05 §5.5). The CLI now prints
a warning whenever it is selected.

### SR-06 — No lock file (Accepted, Info)

Runtime dependencies have lower bounds only, and CI installs the latest
versions. A malicious or broken release of a dependency would be picked up.
Accepted for a library-style tool that users install into their own
environments, where a lock file would not apply; mitigated by pip-audit in CI
and by the known-answer tests, which fail if a dependency upgrade changes any
output.

### SR-07 — Public salt positions (Accepted, Info)

The 136 positions holding the salt and the cost are derived from a public
key and the set of eligible samples, so anyone can locate and read them. They
must be readable before any key exists. The salt is uniformly random and the
cost byte is constant, so what an observer reads there is 128 random bits and
8 bits that are mostly unchanged cover LSBs at scattered positions — no more
distinguishable from a clean image than any other 136 samples. Accepted.

### SR-08 — `random_bytes` hook (Accepted, Info)

`embed`, `split` and `seal` accept a `random_bytes` callable so tests can be
deterministic. A caller passing a weak generator would weaken every key. The
CLI never passes one; the parameter is documented as a test hook. Accepted.

## 6.5 Earlier review (before 1.0.0)

An independent code read before the 1.0.0 release reported issues that were
fixed before that release; they are listed here for completeness.

| Severity | Issue | Fix |
| --- | --- | --- |
| High | One bad share listed first could exhaust the search; a flood of shares reusing one index made it explode | Disjoint blocks first, index combinations with one share per index (ADR-09) |
| Medium | The first self-consistent subset was accepted, so fabricated shares could win | Cluster search; the vault's GCM tag decides (ADR-09) |
| Medium | Salt derived from image size: shared positions and keys across images, precomputable scrypt | Random per-image salt (ADR-05) |
| Medium | Memory proportional to image size (about 1 GiB for a 12 MP photo) | Rejection-sampled walk (ADR-04) |
| Medium | `--name` could overwrite a share image; case-only name collisions | Case-folded collision checks |
| Medium | Several failures ended in tracebacks | `ShardpixError` everywhere, `OSError` caught in `main` |
| Medium | Restored file names could carry control characters and escape sequences | `safe_filename` strips Cc/Cf and reserved names |
| Low | JPEG covers detectable by JPEG-compatibility analysis | Warning and documentation |
| Low | `combine -o` could overwrite its input | Inputs protected |

## 6.6 Static analysis

| Tool | Configuration | Result |
| --- | --- | --- |
| bandit | Default rule set, recursive over `shardpix/` (2,522 lines) | 0 issues |
| semgrep | 112 rules of the official `python` rule set | 0 findings, 0 errors |
| pip-audit | `requirements.txt`, 9 resolved packages | 0 known vulnerabilities |

A clean result from these tools is expected for code that uses no `eval`,
`pickle`, `subprocess` or `random` and takes no input from a network; their
role is to keep it that way. All three now run in the `security` CI job on
every push.

## 6.7 Property-based testing and fuzzing

[tests/test_properties.py](../tests/test_properties.py) states 16 properties.
The default profile runs 60 cases per property in the normal suite; the
`fuzz` profile (`HYPOTHESIS_PROFILE=fuzz`, run in CI) runs 3,000, about
48,000 cases in 90 seconds.

| Area | Property |
| --- | --- |
| GF(256) | Field axioms; division inverts multiplication |
| Shamir | Any subset of at least k shares recovers the secret and verifies every share; fewer than k always fail; encodings are lossless |
| Shamir | `from_bytes` and `from_text` raise only `ShareFormatError` on arbitrary bytes and text |
| Shamir | Any single corrupted byte is caught by the checksum |
| Shamir | An altered value with a valid checksum is never used, and the genuine secret is still recovered |
| Stego | Any payload that fits round trips on random images of every mode, with distortion ≤ 1 |
| Stego | Changing any single sample yields the original payload or none — never different data |
| Stego | Extraction from arbitrary images raises only `PayloadNotFoundError` |
| Vault | The header parser raises only `VaultError` on arbitrary bytes |
| Vault | `safe_filename` output never contains separators, control or format characters, `.`/`..` or reserved names, for any Unicode input |
| Analysis | `chi2_sf` is a decreasing probability; RS never crashes and stays finite |

One property failed during the review: the `chi2_sf` monotonicity property
found SR-02. All properties pass after the fix.

## 6.8 Mutation testing

Mutation testing introduces small faults — an operator flipped, a constant
changed, an argument dropped — and checks that some test fails. It measures
whether the tests *detect* faults, which line coverage cannot.

mutmut was run on `gf256.py`, `shamir.py`, `stego.py` and `vault.py`. Because
mutmut instruments code at function level and selects tests per function, it
can report a mutant as surviving when the real suite would catch it. Every
mutant it reported as surviving was therefore applied to a clean copy of the
source and the whole suite was run against it.

| Round | Code | Mutants | Detected | Survivors after re-run | Score |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | 1.0.0, original suite | 1,552 | 1,287 | 228 (+37 not re-run) | 82.9% (lower bound) |
| 2 | after the first round of new tests and SR-01 | 1,573 | 1,386 | 150 (+37 not re-run) | 88.1% (lower bound) |
| 3 | final code, final suite | 1,575 | 1,429 | 146 | 90.7% |
| 3, after two last fixes | same, plus the two tests below | 1,575 | 1,431 | 144 | **90.9%** |

"Detected" counts mutants that make a test fail or time out (an infinite
loop is a detected fault). In rounds 1 and 2, 37 mutants of class methods
could not be re-applied by the verification script and are counted as
survivors; in round 3 they were re-applied with `mutmut apply` instead (4 were
detected, 33 survive and are classified below). Of the 146 survivors of round
3, two exposed real gaps, closed afterwards and verified by re-applying the
mutant:

- `rstrip("=")` → `rstrip("XX=XX")` in `Share.to_text`. Base32 contains the
  letter X; a share whose encoding ends in "X" would lose characters. Random
  test inputs almost never produce such a share — only lengths that are a
  multiple of 5 bytes have no padding, and then 1 time in 32 —
  so a dedicated test now builds one.
- `save_png(..., overwrite=force)` → `save_png(...)` in `seal`: harmless
  because `seal` checks for existing files first, but it reopened the race of
  SR-03. `save_png` now defaults to exclusive creation.

The surviving mutants of the final round, classified one by one:

| Category | Mutants | Why they survive |
| --- | ---: | --- |
| Error and report message text | 66 | Tests match messages by key words, not character by character; a mutated message still reads as an error. Deliberate: pinning every message would make the suite brittle without protecting any security property. |
| Equivalent: default arguments and harmless parameters | 39 | `to_bytes(2, "big")` → `to_bytes(2)` (big-endian is the default since Python 3.11), `strict=True` on zips of equal length, `copy=True` on a conversion that always copies, `"utf-8"` → `"UTF-8"`, a larger scrypt `maxmem`, … |
| Equivalent: identical elements | 6 | `subset[0]` → `subset[1]` where every element has the same group id, threshold and length. |
| Equivalent: argued individually | 33 | Antilog-table wrap-around in `div`; initial values of tables that are fully overwritten; walk batch sizes, which cannot change the walk by construction; the rejection tail of the walk (probability below 10⁻¹⁰); weaker pre-checks followed by an authentication that fails anyway; `support = used − confirmed`, which is equal for two clusters exactly when `used + confirmed` is, since both use k shares. |
| **Total** | **144** | |

Excluding the 78 equivalent mutants, which no test can detect by
definition, the suite detects 1,431 of 1,497 mutants (95.6%); the remaining
66 are message texts.

Examples of mutants that survive because they are equivalent:

- `EXP[LOG[a] + ORDER - LOG[b]]` → `EXP[LOG[a] - ORDER - LOG[b]]` in `div`:
  the index becomes negative, Python indexes from the end of the 510-entry
  table, and the antilog table is periodic with period 255 — same result.
- `share.group_id != subset[0].group_id` → `subset[1]`: every share of a
  cluster has the same group id.
- Batch sizes in the keyed walk: the walk is the same sequence however the
  keystream is read (ADR-04), which is exactly the property the mutant
  cannot break.
- Rejection of the biased tail of 64-bit words: for any image size the
  probability of a word falling in the tail is below 10⁻¹⁰, so no test can
  observe its removal; the rejection is kept because correctness should not
  depend on probability.

## 6.9 Manual review checklist

| Control | Requirement | Assessment |
| --- | --- | --- |
| ASVS 6.2.1 | Modules fail securely; no oracle in error handling | Pass. Wrong passphrase, clean image and modified image give one error (SP-08); decryption failures never return partial data. |
| ASVS 6.2.2 | Industry-proven algorithms and libraries | Pass. AES-GCM, ChaCha20, HMAC-SHA256, HKDF, scrypt from `cryptography`/`hashlib`. Own code limited to Shamir, GF(256), embedding and steganalysis (ADR-02). |
| ASVS 6.2.3 | Correct IV, mode and padding configuration | Pass. AEAD only; 96-bit random nonces; no padding. |
| ASVS 6.2.4 | Algorithms and parameters can be replaced | Pass after SR-01. Every format is versioned; the scrypt cost is stored per image. |
| ASVS 6.2.5 | No insecure modes or primitives | Pass. No ECB, CBC, MD5, SHA-1. ChaCha20 is used as a keystream with a zero nonce under single-use keys. |
| ASVS 6.2.6 | Nonces not reused with the same key | Pass. Each AES-GCM key encrypts once: the vault key is fresh per vault, the stego key fresh per image via the salt. |
| ASVS 6.2.7 | Encrypted data is authenticated | Pass. Vault, stego payload and shares are all authenticated; the vault header is AAD. |
| ASVS 6.2.8 | Constant-time operations on secrets | Partial. MAC and checksum comparisons use `hmac.compare_digest`. GF(256) table lookups are not constant-time; accepted for a local tool (05 §5.6). |
| ASVS 6.3.1 | Cryptographically secure randomness | Pass. `os.urandom` for keys, salts, nonces, coefficients and ±1 directions. `numpy.random` appears only in the benchmark and tests. |
| ASVS 6.3.3 | Sufficient entropy | Pass. 256-bit keys, 128-bit salts and group ids. |
| ASVS 6.4.1–6.4.2 | Key material isolated, not exposed | Pass with limitation. Keys never touch disk; passphrases never on the command line. Python cannot wipe memory (05 §5.6). |
| ASVS 2.4.1 / OWASP cheat sheet | Passphrase hashing with an approved, memory-hard function and current parameters | Pass after SR-01 (scrypt N = 2^17, r = 8, p = 1). |
| ASVS 5.1.3 / 12.1.1 | Input validation; resource limits on files | Pass. Decompression-bomb limit, 2 GiB file limit, scrypt cost cap, search budget, length checks before decryption. |
| ASVS 7.4.1 | Generic error messages, no stack traces | Pass. `TestCleanErrors`. |
| ASVS 12.3.1–12.3.2 | File names from untrusted data are sanitised; no path traversal | Pass. `safe_filename`, property-tested. |
| ASVS V12.3 (general) | Files written without races or link following | Pass after SR-03. |
| ASVS 14.2.1 | Dependencies up to date, no known vulnerabilities | Pass, with SR-06 accepted. |

## 6.10 Accepted risks

Beyond SR-06 to SR-08, the limitations listed in 05 §5.6 remain accepted:
trained steganalysis measured against SPAM and SRM-lite only (format 4 at
chance, 05 §5.5.6; format 3 weakly detectable in small covers, §5.5.5), JPEG covers, cover availability,
transport re-compression, visible vault metadata, one passphrase per vault,
non-constant-time arithmetic and memory that cannot be wiped, and the search
budget as a denial-of-service limit.

## 6.11 Reproducing this review

```bash
pip install -e ".[dev,audit]" semgrep

bandit -r shardpix
semgrep scan --config p/python --metrics=off shardpix
pip-audit -r requirements.txt

HYPOTHESIS_PROFILE=fuzz pytest -q tests/test_properties.py

mutmut run          # configuration in pyproject.toml ([tool.mutmut])
mutmut results      # then re-run each survivor against the full suite
```

## 6.12 Handover for an independent review

An external reviewer would add most value by attacking what this review
could only argue:

1. **SP-03, secrecy of k − 1 shares with the shared MAC key** (ADR-08). The
   argument is in 05 §5.3 and a test enumerates the k = 2 case exhaustively;
   a proof sketch reviewed by someone else would close it.
2. **The cluster search** (`shamir.recover_all`) under adversarial share
   sets, including the budget and the reasons reported.
3. **Detectability** against stronger trained steganalysis than 05 §5.5.5
   could run on a CPU — the full SRM, SRNet — and on large colour photos,
   where the 2-megapixel threshold is extrapolated, not measured. Testing
   under cover-source mismatch would show how much of the measured advantage
   survives outside the laboratory.
4. **The public walk** and whether its positions plus the cost byte leak
   anything across many images.
5. **Side channels** in extraction, if shardpix were ever used outside a
   trusted local machine.

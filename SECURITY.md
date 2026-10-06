# Security policy

## Status

shardpix has had an **internal security review** — static analysis,
property-based fuzzing, mutation testing and a manual review against OWASP
ASVS — documented in [docs/06-security-review.md](docs/06-security-review.md).
It has **not** been audited by an independent third party. Do not rely on it
alone for secrets whose loss or disclosure would cause serious harm.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| 0.x | No (pre-releases, older image format) |

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
private vulnerability reporting ("Report a vulnerability" on the *Security*
tab of the repository) and include:

- the version or commit you tested;
- what an attacker can achieve, and under which assumptions;
- a minimal way to reproduce it (a script, or the images and vault involved).

You can expect an acknowledgement within a week. Confirmed issues are fixed
in a new release, listed in the changelog and added to the findings table of
the security review, with credit to the reporter unless they prefer otherwise.

## Scope

In scope: confidentiality and integrity of sealed files and shares, the
detectability claims in [docs/05-security-analysis.md](docs/05-security-analysis.md),
handling of malicious images, shares and vault files, and file system safety.

Out of scope: attacks that require a compromised machine, availability of the
covers to the attacker, and detection of payloads in images re-compressed by
third parties — these are documented limitations.

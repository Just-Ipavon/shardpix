# shardpix

[![CI](https://github.com/Just-Ipavon/shardpix/actions/workflows/ci.yml/badge.svg)](https://github.com/Just-Ipavon/shardpix/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Hide authenticated, encrypted payloads in ordinary-looking PNG images — and
measure how detectable they are.

> **Work in progress.** This release covers the steganography layer, the
> chi-square attack and Shamir secret sharing. The full pipeline is next.

## Install

```bash
git clone https://github.com/Just-Ipavon/shardpix.git
cd shardpix
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# How much can this image hold?
shardpix capacity photo.jpg

# Hide a message (prompts for a passphrase)
shardpix embed photo.jpg -o holiday.png -t "meet me at noon" -p

# Recover it
shardpix extract holiday.png -p

# Look for the statistical fingerprint of LSB replacement
shardpix analyze holiday.png

# Split a secret into 5 shares, any 3 of which recover it
shardpix split -t "safe code 4815" -k 3 -n 5 -d shares/

# Recover it from any 3 share files
shardpix combine shares/share-*-1.txt shares/share-*-3.txt shares/share-*-4.txt
```

## License

MIT — see [LICENSE](LICENSE).

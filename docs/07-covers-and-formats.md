# 7. Covers: PNG, JPEG and phone photos

| | |
| --- | --- |
| Document | SDD-07 — Covers, image formats and embedding methods |
| System | shardpix 1.2.0 (unreleased) |
| Status | Draft |
| Last revised | 2026-10-07 |

## 7.1 In short

**Use the photos your phone takes, as they are.** shardpix recognises a
JPEG and hides the share inside the JPEG itself; the result is a JPEG with
the same quality settings and the same camera metadata. A PNG, TIFF or RAW
export gives a PNG. The user never chooses a method: the file decides.

Four rules matter more than anything else:

1. a colour photo of at least 2 megapixels with some texture (any phone
   photo qualifies);
2. a photo nobody else has: never one from the web, and never publish the
   original;
3. send the result as a **file** (e-mail attachment, cloud drive, "send as
   document"), never as a "photo" in a messaging app, which re-compresses it;
4. on iPhone, keep the camera on *Most Compatible* (JPEG) rather than *High
   Efficiency* (HEIC), which shardpix cannot read.

The rest of this document explains why. The measurements behind it are in
05 §5.5.

## 7.2 How PNG and JPEG store a photograph

| | PNG (and TIFF, BMP) | JPEG (and HEIC, AVIF, WebP lossy) |
| --- | --- | --- |
| What is stored | Every pixel value, exactly | 8x8 blocks of DCT coefficients, divided by a quantisation table and rounded |
| Compression | Lossless | Lossy: the rounding throws information away |
| Where hidden data can live | The least significant bit of each pixel value | The quantised DCT coefficients |
| What re-saving does | Nothing: the pixels come back identical | Re-quantises everything: anything hidden is destroyed |
| Typical source | Screenshots, RAW exports, image editors | Every phone camera, every messaging app, the web |

So a JPEG has to be handled **in its own domain**. Decoding it to pixels,
hiding data there and saving a PNG - what shardpix did before format 5 -
fails in two ways: the PNG of a phone photo is unusual in itself, and the
pixels of a decoded JPEG obey the 8x8 block quantisation, so a ±1 change
produces a block no JPEG compressor could have produced. *JPEG-compatibility
steganalysis* (Fridrich, Goljan and Du, 2001) detects that at any rate.

## 7.3 The two formats shardpix writes

| Cover | Format | Where the share goes | Output | Measured against |
| --- | --- | --- | --- | --- |
| JPEG (phone photos, most cameras) | 5 | Non-zero AC coefficients of the luminance, chosen by a syndrome-trellis code with UERD costs | JPEG with the same quantisation tables and metadata | DCTR (05 §5.5.8) |
| PNG, TIFF, BMP, RAW export | 4 | Pixel values in 2–253, chosen by a syndrome-trellis code with HiLL costs | PNG | SPAM, SRM-lite, pooled (05 §5.5.6–5.5.7) |

Both formats rest on the same idea. A **cost** says how risky a ±1 change
is at each place: high where the image is smooth and predictable (a sky, a
wall, a flat 8x8 block), low where it is busy (foliage, gravel, sensor
noise). The payload is written as the **syndrome** of a block of candidate
places (Filler, Judas and Fridrich, 2011): the embedder may change any of
them as long as the block's syndrome equals the message, and the Viterbi
algorithm picks the changes with the lowest total cost. The extractor only
computes the syndrome; it never needs the costs.

What format 5 adds for JPEG:

- **Only non-zero AC coefficients move.** Turning a zero into a non-zero
  is the most detectable change in a JPEG, so zeros and DC coefficients are
  never touched, and a coefficient at ±1 always moves away from zero. The
  set of usable coefficients is the same before and after, so the extractor
  finds it without side information.
- **UERD costs** (Guo et al., 2015): a change costs the quantisation step of
  its frequency divided by the energy of its block and its neighbours -
  cheap in busy blocks and low frequencies, expensive in flat blocks.
- **Nothing else changes.** The image is never decoded or recompressed:
  quantisation tables, chroma, dimensions and the EXIF and ICC metadata are
  written back as they were.

The formats used before (3: one bit per sample by LSB matching or
replacement) are no longer offered by the CLI. They remain in the library
only as the baseline the benchmarks compare against.

## 7.4 What happens to each kind of input

| Input | What shardpix does | Output | Verdict |
| --- | --- | --- | --- |
| JPEG from a phone or camera | Embeds in the coefficients (format 5) | JPEG | **Good cover**, as taken |
| PNG, TIFF or BMP photo, 8-bit | Embeds in the pixels (format 4) | PNG | **Good cover** |
| RAW / DNG (iPhone ProRAW, Android RAW) | Not read directly: export it to an 8-bit PNG or TIFF | PNG | **Good cover**, after export |
| HEIC (iPhone "High Efficiency") | Not readable (no HEIF support in Pillow) | — | Switch the camera to JPEG; converting HEIC to JPEG compresses the photo twice |
| 16-bit PNG or TIFF | Refused | — | Export as 8-bit |
| Screenshot | Embeds in the pixels | PNG | Works, but flat areas leave little texture; prefer photos |

The kind is read from the first bytes of the file, not from its name, and
the output must carry the matching extension (`.jpg` or `.png`).

## 7.5 Phone photos step by step

1. **Camera settings.** iPhone: *Settings → Camera → Formats → Most
   Compatible*. Android cameras save JPEG by default. Keep the highest
   quality and the full resolution.
2. **Pick the photos.** Textured scenes - trees, streets, fabric, crowds -
   rather than a blue sky or a white wall. Photos you took yourself and
   never shared.
3. **Copy them to the computer as the original files**: by cable, or with a
   cloud drive set to keep originals. Avoid anything that resizes or
   converts them on the way.
4. **Seal** with `shardpix seal secret.pdf photo1.jpg photo2.jpg ... -k 3 -p`.
   The `sealed/` folder receives one `.jpg` per photo and the vault file.
5. **Hand out the `.jpg` files as files**, and delete or keep private the
   originals. Each holder can keep the photo in an album: what matters is
   that it is never re-compressed (no edits, no "save as", no messaging app
   in photo mode).

## 7.6 Limits that remain

- **File structure.** Quantisation tables and metadata are kept, but the
  file is rewritten by libjpeg: Huffman tables, marker order or progressive
  encoding can differ from what a given phone model writes. A forensic
  analyst comparing the file's structure with that phone's usual output
  could notice that it was rewritten, without learning anything about the
  share. Steganalysis of the content is a separate question (05 §5.5.8).
- **Luminance only.** Chroma coefficients are never used: they are fewer,
  more coarsely quantised, and capacity is far beyond a share anyway.
- **Detectors.** Format 5 is measured against DCTR; stronger JPEG detectors
  (GFR, deep networks such as SRNet for JPEG) were not run.

## 7.7 Summary: which cover should I use?

| You have | Do |
| --- | --- |
| A phone | Use its JPEG photos as they are: textured, full resolution, never shared |
| RAW exports or PNG photos | Use them: they give PNG outputs (format 4) |
| HEIC photos | Switch the camera to JPEG for the photos you will use |
| Images from the web | Do not use them: the original is one reverse image search away |

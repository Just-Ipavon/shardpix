# 7. Covers: PNG, JPEG and phone photos

| | |
| --- | --- |
| Document | SDD-07 — Covers, image formats and embedding methods |
| System | shardpix 1.2.0 (unreleased) |
| Status | Draft |
| Last revised | 2026-10-07 |

## 7.1 Purpose

Which photo a share is hidden in matters as much as how it is hidden. This
document explains how PNG and JPEG store a photograph, what that means for
steganography, which embedding methods shardpix offers, and how to get a
good cover out of a phone. The measurements behind the advice are in
05 §5.5.

## 7.2 How PNG and JPEG store a photograph

| | PNG (and TIFF, BMP) | JPEG (and HEIC, AVIF, WebP lossy) |
| --- | --- | --- |
| What is stored | Every pixel value, exactly | 8x8 blocks of DCT coefficients, divided by a quantisation table and rounded |
| Compression | Lossless | Lossy: the rounding throws information away |
| Where hidden data can live | The least significant bit of each pixel value | The quantised DCT coefficients |
| What re-saving does | Nothing: the pixels come back identical | Re-quantises everything: hidden bits in the pixels are destroyed |
| Typical source | Screenshots, RAW exports, image editors | Every phone camera, every messaging app, the web |

The consequence is that **pixel-domain steganography and JPEG are
incompatible in two ways**:

1. **Output.** A payload written into pixel LSBs does not survive saving as
   JPEG, so shardpix only writes PNG (ADR-10).
2. **Input.** A JPEG decoded to pixels is not an ordinary photo: every 8x8
   block is the inverse DCT of rounded coefficients, so its pixel values
   are constrained. Changing any of them by ±1 produces a block that no JPEG
   compressor could have produced, and *JPEG-compatibility steganalysis*
   (Fridrich, Goljan and Du, 2001) detects that at **any** embedding rate,
   whatever method chose the pixels. A PNG that was obviously once a JPEG is
   also unusual in itself.

HEIC, AVIF and lossy WebP use larger and variable transform blocks; the same
reasoning applies, although compatibility attacks on them are less studied.
shardpix treats them like JPEG: decoded pixels are not a clean cover.

## 7.3 Embedding methods

| Method | Format | How a share is written | Samples changed by one share (BOSSbase 512x512, mean of 60) | Against trained detectors (05 §5.5) | Use |
| --- | --- | --- | ---: | --- | --- |
| `adaptive` (default) | v4 | ±1 changes placed by a syndrome-trellis code where the HiLL cost is lowest: in texture and noise, away from smooth areas | 208 | At chance: 49.9% for SPAM and SRM-lite at 512x512 (05 §5.5.6) | Always, unless you need format 3 |
| `matching` | v3 | ±1 changes at keyed pseudo-random positions, one bit per sample | 633 | SRM-lite 42.5% error at 512x512 | Compatibility with shardpix 1.1 |
| `replacement` | v3 | LSB overwritten at keyed positions | about 630 | Broken by RS and chi-square | Demonstrations only |

**Adaptive embedding in one paragraph.** A *cost map* (HiLL: a high-pass
filter and two low-pass filters) scores how risky a ±1 change is at each
sample: high in skies, walls and skin, low in foliage, gravel and sensor
noise. The payload is not written one bit per sample but as the *syndrome*
of a block of candidate samples (Filler, Judas and Fridrich, 2011): the
embedder may choose which samples to change, as long as the block's
syndrome equals the message, and the Viterbi algorithm finds the choice with
the lowest total cost. The extractor only computes the syndrome and never
needs the cost map. Fewer changes, and changes where the image is already
unpredictable, is what lowers detectability.

**Format 4 layout.** Three syndrome codes, each read before the next can be
located: the public salt and cost byte (fixed width, public matrix), the
masked length (fixed width, keyed matrix) and the sealed body (width from
the length, up to 128 candidates per bit). Details in 01 §1.5.1.
shardpix 1.2 reads both formats; shardpix 1.1 cannot read format 4.

**JPEG-domain embedding — not implemented yet.** The method that suits
phone photos changes the quantised DCT coefficients themselves (with
costs such as UERD or J-UNIWARD and the same syndrome-trellis codes) and
writes a JPEG with the original quantisation tables and metadata. The
result is an ordinary-looking camera JPEG, and the compatibility attack of
§7.2 no longer applies because no pixel is ever re-rounded; what it must
resist instead is JPEG-domain steganalysis. It is the next planned step
(§7.6); until then, shardpix embeds in pixels only.

## 7.4 What happens to each kind of input today

| Input | What shardpix does | Output | Verdict |
| --- | --- | --- | --- |
| PNG, TIFF or BMP photo, 8-bit, never JPEG-compressed | Embeds in the pixels | PNG | **Best cover** |
| RAW / DNG (iPhone ProRAW, Android RAW) | Not read directly: develop it to an 8-bit PNG or TIFF first | PNG | **Best cover**, after export |
| JPEG (phone default "Most Compatible", most cameras) | Decodes, embeds in the pixels, prints a warning | PNG | Detectable by JPEG-compatibility steganalysis whatever the method |
| HEIC (iPhone default "High Efficiency") | Not readable (no HEIF support in Pillow) | — | Convert it, but the result is a decoded lossy image: same problem as JPEG |
| 16-bit PNG or TIFF | Refused | — | Export as 8-bit |
| Screenshot | Embeds in the pixels | PNG | Works, but large flat areas give the adaptive method little texture to hide in; prefer photos |

## 7.5 Phone photos in practice

The phone is a fine camera for shardpix; its default file formats are the
problem. To get a clean cover:

1. **Shoot RAW if the phone can.** On iPhone Pro models enable
   *Settings → Camera → Formats → Apple ProRAW*; on Android many camera
   apps offer RAW (DNG) in their Pro or manual mode. Develop the DNG on a
   computer (darktable, RawTherapee, Lightroom, Apple Photos) and **export
   an 8-bit PNG or TIFF at full resolution**, without sharpening or noise
   reduction beyond the defaults: sensor noise is where the adaptive method
   hides its changes.
2. **Use colour photos of at least 2 megapixels**, with texture: foliage,
   gravel, fabric, crowds. Detectability falls with the square root of the
   number of samples (05 §5.5.5). A phone photo is usually 12 megapixels,
   far above the threshold.
3. **If only a JPEG is available**, embedding still works but carries the
   risk of §7.2. Scaling the photo down by a factor of two or more weakens
   the trace of the 8x8 grid and is a common countermeasure; it has *not*
   been measured here, and the result is a PNG of unusual size for a phone.
   Prefer RAW.
4. **Never publish or keep the original next to the stego image.** Anyone
   with both sees every changed sample (05 §5.6).
5. **Move the images as files, never as "photos".** Messaging apps and
   social networks re-compress images and destroy the payload. Send them as
   documents, e-mail attachments or through a cloud drive.
6. **Expect metadata to differ.** The output PNG keeps the ICC colour
   profile but not EXIF; a phone photo without EXIF can itself stand out in
   some contexts.

## 7.6 Roadmap: JPEG-domain embedding

The JPEG method will read the quantised coefficients without decoding
(`jpeglib`), compute UERD costs per coefficient, write the payload with the
same syndrome-trellis codes into non-zero AC coefficients, and save a JPEG
with the original quantisation tables, chroma subsampling and EXIF. It will
be evaluated with JPEG-domain detectors (DCTR, GFR) on BOSSbase compressed
at quality 75 and 95, as the spatial methods are in 05 §5.5. Until that is
measured, the advice in §7.5 stands.

## 7.7 Summary: which cover should I use?

| You have | Do |
| --- | --- |
| A RAW-capable phone or camera | Shoot RAW, export 8-bit PNG/TIFF, ≥ 2 MP colour, textured scene |
| Only JPEGs | Use them knowing the risk of §7.2, or wait for JPEG-domain embedding |
| HEIC photos | Switch the camera to RAW, or treat converted HEIC like JPEG |
| Images from the web | Do not use them: the original is one reverse image search away |

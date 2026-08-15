# TOTP enrolment: the QR code

The enrolment page shows a scannable QR code, with the key still available for
manual entry behind a `Can't scan it?` disclosure.

This was an acknowledged gap for a long time — the page printed a base32 secret
and asked people to type it. Most expect to point a camera at a square, and the
ones who do not expect it often cannot manage 32 characters on a phone keyboard.

## Why the encoder is in this repo

The obvious library, `github.com/skip2/go-qrcode`, is archived and has not been
touched since 2020. An unmaintained dependency in an identity provider — to
render, of all things, the enrolment secret for the second factor — is a worse
trade than ~450 lines that are exhaustively checked against a reference.

Scope is deliberately narrow: **byte mode, error correction level M, versions 1
to 12**. That covers every `otpauth://` URI this product produces (they run
90–160 bytes; version 12 holds 288) and nothing else. Anything wider would be
paths nothing here exercises.

## How it is known to be right

Not by inspection. Three independent checks, because this is exactly the kind of
code that produces a plausible-looking square while being wrong:

**1. Module-for-module against Python's `qrcode`**, across six inputs × all eight
masks. Two things had to be pinned for that comparison to mean anything:

- the reference is forced into single-segment **byte mode**. Left alone it
  switches to alphanumeric for uppercase input — a denser, equally valid encoding
  of different bits, which would show up as a difference that is not an error.
- the **mask is fixed** on both sides, because selection is a separate question
  (below).

**2. Penalty scores match the reference's scorer exactly**, for every mask.

**3. OpenCV's detector decodes the rendered image** back to the original URI.
That is the property an operator actually cares about — a camera pointed at it
recovers the secret.

### What the checks caught

**Reversed format bits.** The 15-bit format field is written least-significant
bit first along each arm; I had it most-significant first. The result had
flawless finder patterns, correct timing, a perfect data region — and **no
scanner on earth could read it**, because the format field is how a decoder
learns which mask to undo. Every version failed to decode; one bit-order fix made
all of them pass. Reading the code would not have found this.

**Penalty rule 3 over-counted at the edges.** The standard states the finder-like
pattern as one *eleven*-module window (`10111010000` / `00001011101`). I had
implemented it as a seven-module pattern plus a separate look outwards, treating
off-symbol positions as light — so every near-edge occurrence scored. Totals came
out around 1000 instead of ~300, and a worse mask won: a valid symbol that is
harder to scan, which is the one failure this scoring exists to prevent. Fixed,
and the scores now match the reference exactly.

### Where we differ from the reference, on purpose

Python's `qrcode` sometimes scores mask 2 lowest and then returns mask 5 anyway —
a quirk in its selection, not its scoring. The standard says the lowest penalty
wins, which is what this package does. So the tests compare **scores**, not the
chosen mask, and compare **matrices only with the mask pinned**.

## Rendering

SVG, inline. No image encoder, no rasterising, no blurring when a browser scales
it — and it can be inlined, which matters because the enrolment page carries a
Content-Security-Policy that forbids external sources.

The background is drawn explicitly white. On a dark-themed page a transparent
background puts dark modules on dark and the symbol simply does not scan.

It is inserted with `template.HTML`, which turns off escaping. That is only safe
while the SVG is built entirely from integers and literals, so the property is
asserted rather than argued: `TestSVGContainsNothingButGeneratedMarkup` feeds
`</svg><script>alert(1)</script>...` through the encoder and requires the output
to contain exactly four opening and four closing brackets — the `<svg>`,
`<rect/>`, `<path/>` and `</svg>` this package emits, and nothing else.

## Failure behaviour

If the QR code cannot be built, the page still renders with the key for manual
entry and logs a warning. Losing the ability to turn on a second factor is a far
worse outcome than losing the square.

## Verified end to end

Against the running engine, using only what the QR code carries:

```
GET /account/mfa/totp        -> page with an inline <svg>
decode the served SVG        -> otpauth://totp/Default:...?secret=YDFBKF3G...
derive a TOTP code from it   -> 6 digits
POST /account/mfa/totp       -> "Two-factor authentication is on", 10 recovery codes
```

The secret read out of the QR code matched the one shown for manual entry, and
the code derived from it was accepted.

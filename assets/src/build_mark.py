#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Render the Deedseal mark (counterseal) at any size.

The mark is letterless: two concentric rings with one green point. Below
64 px the inner ring is dropped so the mark stays legible. Requires Pillow.
"""
import argparse
from PIL import Image, ImageDraw, ImageFilter

S = 4  # supersample factor

DARK_FIELD = (11, 15, 20)
RING = (150, 162, 173)
POINT = (52, 168, 115)
POINT_CORE = (96, 214, 156)


def render(size: int, out_path: str) -> None:
    small = size < 64
    pad_frac = 0.10 if size <= 16 else 0.18
    ring_w_frac = 0.125 if size <= 16 else (0.09 if small else 0.05)
    dot_frac = 0.34 if size <= 16 else (0.28 if small else 0.175)

    W = size * S
    img = Image.new("RGBA", (W, W), DARK_FIELD + (255,))
    d = ImageDraw.Draw(img)
    c = W // 2
    R = int(W * (0.5 - pad_frac / 2))
    width = max(int(W * ring_w_frac / 2), S)

    fracs = (1.0,) if small else (1.0, 0.60)
    for f in fracs:
        r = int(R * f)
        d.ellipse([c - r, c - r, c + r, c + r], outline=RING, width=width)

    pr = int(R * dot_frac)
    if not small:
        # the Signal treatment: the point glows at 64 px and above
        layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
        ld = ImageDraw.Draw(layer)
        gr = int(pr * 4.2)
        ld.ellipse([c - gr, c - gr, c + gr, c + gr], fill=POINT + (110,))
        layer = layer.filter(ImageFilter.GaussianBlur(radius=int(pr * 1.9)))
        img.alpha_composite(layer)
        d = ImageDraw.Draw(img)
    d.ellipse([c - pr, c - pr, c + pr, c + pr], fill=POINT + (255,))
    if not small:
        cr = int(pr * 0.45)
        d.ellipse([c - cr, c - cr, c + cr, c + cr], fill=POINT_CORE + (255,))

    img.convert("RGB").resize((size, size), Image.LANCZOS).save(out_path, optimize=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--size", type=int, required=True, help="output size in pixels")
    ap.add_argument("--out", required=True, help="output PNG path")
    args = ap.parse_args()
    render(args.size, args.out)


if __name__ == "__main__":
    main()

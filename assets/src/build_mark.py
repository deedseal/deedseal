#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Render the Deedseal mark (counterseal) at any size.

The mark is letterless: two concentric rings with one green point. Below
64 px the inner ring is dropped so the mark stays legible. Requires Pillow.
"""
import argparse
from PIL import Image, ImageDraw

S = 4  # supersample factor

DARK_FIELD = (11, 15, 20)
RING = (150, 162, 173)
POINT = (52, 168, 115)


def render(size: int, out_path: str) -> None:
    small = size < 64
    pad_frac = 0.10 if size <= 16 else 0.18
    ring_w_frac = 0.125 if size <= 16 else (0.09 if small else 0.05)
    dot_frac = 0.34 if size <= 16 else (0.28 if small else 0.175)

    W = size * S
    img = Image.new("RGB", (W, W), DARK_FIELD)
    d = ImageDraw.Draw(img)
    c = W // 2
    R = int(W * (0.5 - pad_frac / 2))
    width = max(int(W * ring_w_frac / 2), S)

    fracs = (1.0,) if small else (1.0, 0.60)
    for f in fracs:
        r = int(R * f)
        d.ellipse([c - r, c - r, c + r, c + r], outline=RING, width=width)

    pr = int(R * dot_frac)
    d.ellipse([c - pr, c - pr, c + pr, c + pr], fill=POINT)

    img.resize((size, size), Image.LANCZOS).save(out_path, optimize=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--size", type=int, required=True, help="output size in pixels")
    ap.add_argument("--out", required=True, help="output PNG path")
    args = ap.parse_args()
    render(args.size, args.out)


if __name__ == "__main__":
    main()

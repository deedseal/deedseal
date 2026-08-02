#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Render the Deedseal 1280x640 identity card (social preview).

Requires Pillow and two OFL fonts (not vendored): BricolageGrotesque-Bold.ttf
and GeistMono-Regular.ttf. See assets/README.md for sources.
"""
import argparse
from PIL import Image, ImageDraw, ImageFilter, ImageFont

S = 2  # supersample factor
W, H = 1280 * S, 640 * S
TRACK = -0.012  # wordmark tracking, em

DARK = {
    "field": (11, 15, 20), "name": (242, 245, 248), "muted": (140, 152, 163),
    "ring": (40, 50, 62), "hair": (23, 30, 39), "point": (52, 168, 115),
    "point_core": (96, 214, 156), "glow": True,
}
LIGHT = {
    "field": (244, 246, 248), "name": (16, 21, 27), "muted": (110, 120, 131),
    "ring": (110, 120, 131), "hair": (206, 212, 219), "point": (26, 127, 85),
    "point_core": None, "glow": False,  # light does not glow on paper
}

SLOGAN = "Proof over trust."


def measure_tracked(draw, text, font):
    tracking = TRACK * font.size
    width = 0.0
    for ch in text:
        width += draw.textlength(ch, font=font) + tracking
    return width - tracking


def draw_tracked(draw, x, baseline, text, font, fill):
    tracking = TRACK * font.size
    for ch in text:
        draw.text((x, baseline), ch, font=font, fill=fill, anchor="ls")
        x += draw.textlength(ch, font=font) + tracking


def luminous_point(img, cx, cy, r, point, core):
    """The Signal treatment: a soft halo, the solid point, a lighter core."""
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    gr = int(r * 4.2)
    ld.ellipse([cx - gr, cy - gr, cx + gr, cy + gr], fill=point + (110,))
    layer = layer.filter(ImageFilter.GaussianBlur(radius=int(r * 1.9)))
    img.alpha_composite(layer)
    d = ImageDraw.Draw(img)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=point + (255,))
    cr = int(r * 0.45)
    d.ellipse([cx - cr, cy - cr, cx + cr, cy + cr], fill=core + (255,))


def render(fonts_dir: str, light: bool, out_path: str) -> None:
    p = LIGHT if light else DARK
    wordmark = ImageFont.truetype(f"{fonts_dir}/BricolageGrotesque-Bold.ttf", 116 * S)
    mono = ImageFont.truetype(f"{fonts_dir}/GeistMono-Regular.ttf", 23 * S)

    img = Image.new("RGBA", (W, H), p["field"] + (255,))
    d = ImageDraw.Draw(img)

    text = "deedseal"
    wm_w = measure_tracked(d, text, wordmark)
    cap = -d.textbbox((0, 0), "d", font=wordmark, anchor="ls")[1]
    mark_r = 40 * S
    gap = 54 * S
    group_w = wm_w + gap + 2 * mark_r
    cx = W // 2
    x0 = cx - group_w // 2
    baseline = 330 * S

    draw_tracked(d, x0, baseline, text, wordmark, p["name"])

    mx = x0 + wm_w + gap + mark_r
    my = baseline - int(cap * 0.63)
    d.ellipse([mx - mark_r, my - mark_r, mx + mark_r, my + mark_r],
              outline=p["ring"], width=2 * S)
    r2 = int(mark_r * 0.60)
    d.ellipse([mx - r2, my - r2, mx + r2, my + r2], outline=p["ring"], width=2 * S)
    pr = 7 * S
    if p["glow"]:
        luminous_point(img, mx, my, pr, p["point"], p["point_core"])
        d = ImageDraw.Draw(img)
    else:
        d.ellipse([mx - pr, my - pr, mx + pr, my + pr], fill=p["point"])

    ly = baseline + 50 * S
    d.line([x0, ly, x0 + group_w, ly], fill=p["hair"], width=2 * S)

    d.text((cx, baseline + 108 * S), SLOGAN, font=mono, fill=p["muted"], anchor="ms")

    img.convert("RGB").resize((1280, 640), Image.LANCZOS).save(out_path, optimize=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fonts", required=True, help="directory containing the two TTF files")
    ap.add_argument("--light", action="store_true", help="render the light-field version")
    ap.add_argument("--out", required=True, help="output PNG path")
    args = ap.parse_args()
    render(args.fonts, args.light, args.out)


if __name__ == "__main__":
    main()

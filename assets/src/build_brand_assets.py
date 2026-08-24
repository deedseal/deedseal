#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Generate every Deedseal brand asset from one deterministic construction.

The identity is one idea drawn one way. Two congruent forms -- each the other
turned half a turn -- meet along a single stepped seam of constant width and
never touch. That is the product: a bounded authority recorded before an action
and a matching record produced after it, held apart so the correspondence
between them can be checked rather than assumed.

Everything downstream of that idea is arithmetic. Every coordinate this file
emits is an integer on a 64-unit field, so the same source produces the same
bytes on every machine, with no font, no renderer and no network involved.

Run `python3 assets/src/build_brand_assets.py --check` to prove the committed
SVGs are exactly what this construction produces.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SVG_DIR = ROOT / "assets/svg"

IDENTITY_VERSION = "1.0"
PRODUCT_NAME = "Deedseal"
SVG_NAMESPACE = "http://www.w3.org/2000/svg"

# --------------------------------------------------------------------------
# the closed palette
#
# The identity carries no colour of its own. In this product colour is a
# runtime verdict, so lending a hue to the brand would spend a signal the
# product needs to keep truthful. Every asset is one ink on one surface.
# --------------------------------------------------------------------------

INK = "#141414"
INK_INVERSE = "#FAFAF7"
SURFACE = "#FAFAF7"
SURFACE_INVERSE = "#141414"
MUTED = "#5C5C57"

# --------------------------------------------------------------------------
# the field
# --------------------------------------------------------------------------

FIELD = 64          # the mark's square field
BAR = 10            # one bar thickness, shared by the mark and the wordmark
SEAM = 6            # the constant gap between the two forms
MARGIN = 6          # the mark's built-in inset inside its field

CAP = 64            # wordmark cap height, equal to the mark's field
XHEIGHT = 46
BASELINE = 64
XTOP = BASELINE - XHEIGHT
STROKE = BAR        # the wordmark's stroke is the mark's bar
RADIUS_X = 16       # outer corner radius at x-height
RADIUS_CAP = 22     # outer corner radius at cap height
RADIUS_S = 14       # the tighter radius the 's' spine needs
CROSSBAR = 36       # the shared middle of 'e' and 's'

CLEARSPACE = 16     # a quarter of the field, on every side
LOCKUP_GAP = 32     # half the field, between mark ink and wordmark ink


def rect(x: int, y: int, w: int, h: int) -> str:
    """One closed rectangular subpath, wound clockwise in screen coordinates."""
    return f"M{x} {y}H{x + w}V{y + h}H{x}Z"


def sector(cx: int, cy: int, radius: int, quadrant: str) -> str:
    """One quarter annulus, wound clockwise like `rect` so unions are exact.

    The inner radius is always one bar thinner than the outer, which is what
    makes every curve in the wordmark the same pen turning the same corner.
    Every endpoint lands on an integer because the centres and radii do.
    """
    inner = radius - STROKE
    left, right = cx - radius, cx + radius
    top, bottom = cy - radius, cy + radius
    inner_left, inner_right = cx - inner, cx + inner
    inner_top, inner_bottom = cy - inner, cy + inner
    ends = {
        "tl": ((left, cy), (cx, top), (cx, inner_top), (inner_left, cy)),
        "tr": ((cx, top), (right, cy), (inner_right, cy), (cx, inner_top)),
        "br": ((right, cy), (cx, bottom), (cx, inner_bottom), (inner_right, cy)),
        "bl": ((cx, bottom), (left, cy), (inner_left, cy), (cx, inner_bottom)),
    }
    (ax, ay), (bx, by), (px, py), (qx, qy) = ends[quadrant]
    return (
        f"M{ax} {ay}"
        f"A{radius} {radius} 0 0 1 {bx} {by}"
        f"L{px} {py}"
        f"A{inner} {inner} 0 0 0 {qx} {qy}"
        "Z"
    )


def shift(parts: list[tuple], dx: int, dy: int) -> list[tuple]:
    """Translate a part list by integers, so the result stays integral."""
    moved: list[tuple] = []
    for part in parts:
        if part[0] == "r":
            _, x, y, w, h = part
            moved.append(("r", x + dx, y + dy, w, h))
        else:
            _, cx, cy, radius, quadrant = part
            moved.append(("a", cx + dx, cy + dy, radius, quadrant))
    return moved


def render(parts: list[tuple]) -> str:
    """One `d` string for a whole figure: subpaths union under the nonzero rule."""
    pieces = []
    for part in parts:
        if part[0] == "r":
            pieces.append(rect(part[1], part[2], part[3], part[4]))
        else:
            pieces.append(sector(part[1], part[2], part[3], part[4]))
    return "".join(pieces)


def bounds(parts: list[tuple]) -> tuple[int, int, int, int]:
    """The integer bounding box of a part list, as (x0, y0, x1, y1)."""
    xs: list[int] = []
    ys: list[int] = []
    for part in parts:
        if part[0] == "r":
            _, x, y, w, h = part
            xs += [x, x + w]
            ys += [y, y + h]
        else:
            _, cx, cy, radius, _quadrant = part
            xs += [cx - radius, cx + radius]
            ys += [cy - radius, cy + radius]
    return min(xs), min(ys), max(xs), max(ys)


# --------------------------------------------------------------------------
# the mark
#
# Form A is a step: a bar across the top, a stem down the left, a foot back to
# the right. Form B is form A turned half a turn about the centre of the field.
# The turn is the whole argument -- the two forms are the same form, so one can
# be checked against the other, and the seam between them never closes.
# --------------------------------------------------------------------------

# Every dimension below is forced by the field, the bar and the seam. Nothing
# here is a taste decision that a later reader would have to take on trust:
# the top bar runs until one seam short of the turned form's stem, the foot
# runs until one seam short of the turned form's foot, and the seam band is
# centred on the field. Change `SEAM` and the whole mark re-solves.
FOOT_TOP = (FIELD - BAR) // 2                       # the seam band, centred
TOP_BAR = FIELD - 2 * MARGIN - BAR - SEAM           # 36
STEM_HEIGHT = (FIELD + BAR) // 2 - MARGIN           # 31
FOOT_WIDTH = (FIELD - SEAM) // 2 - MARGIN           # 23

MARK_A_FULL: list[tuple] = [
    ("r", MARGIN, MARGIN, TOP_BAR, BAR),            # the bar across the top
    ("r", MARGIN, MARGIN, BAR, STEM_HEIGHT),        # the stem down the left
    ("r", MARGIN, FOOT_TOP, FOOT_WIDTH, BAR),       # the foot back to the right
]
MARK_A_ICON = MARK_A_FULL[:2]                       # the icon drops the foot


def half_turn(parts: list[tuple]) -> list[tuple]:
    """Form A turned half a turn about the centre of the field."""
    return [("r", FIELD - x - w, FIELD - y - h, w, h) for _, x, y, w, h in parts]


MARK_PARTS = MARK_A_FULL + half_turn(MARK_A_FULL)
ICON_PARTS = MARK_A_ICON + half_turn(MARK_A_ICON)


# --------------------------------------------------------------------------
# the wordmark
#
# Constructed, not typeset: bars and quarter turns of one pen on the same
# 64-unit field as the mark, so the wordmark needs no font to render and none
# to verify. Each glyph below is a part list in its own space.
# --------------------------------------------------------------------------

def glyph_cap_d() -> tuple[list[tuple], int]:
    width, radius = 52, RADIUS_CAP
    parts = [
        ("r", 0, 0, STROKE, CAP),
        ("r", STROKE, 0, width - STROKE - radius, STROKE),
        ("r", STROKE, CAP - STROKE, width - STROKE - radius, STROKE),
        ("a", width - radius, radius, radius, "tr"),
        ("r", width - STROKE, radius, STROKE, CAP - 2 * radius),
        ("a", width - radius, CAP - radius, radius, "br"),
    ]
    return parts, width


def bowl(width: int) -> list[tuple]:
    """The shared x-height bowl of 'd' and 'a', open on its right into a stem."""
    radius = RADIUS_X
    return [
        ("a", radius, XTOP + radius, radius, "tl"),
        ("r", 0, XTOP + radius, STROKE, XHEIGHT - 2 * radius),
        ("a", radius, BASELINE - radius, radius, "bl"),
        ("r", radius, XTOP, width - radius, STROKE),
        ("r", radius, BASELINE - STROKE, width - radius, STROKE),
    ]


def glyph_d() -> tuple[list[tuple], int]:
    width = 50
    return bowl(width) + [("r", width - STROKE, 0, STROKE, CAP)], width


def glyph_a() -> tuple[list[tuple], int]:
    width = 48
    return bowl(width) + [("r", width - STROKE, XTOP, STROKE, XHEIGHT)], width


def glyph_e() -> tuple[list[tuple], int]:
    width, radius = 48, RADIUS_X
    parts = [
        ("a", radius, XTOP + radius, radius, "tl"),
        ("r", radius, XTOP, width - 2 * radius, STROKE),
        ("a", width - radius, XTOP + radius, radius, "tr"),
        ("r", 0, XTOP + radius, STROKE, BASELINE - radius - XTOP - radius),
        ("r", width - STROKE, XTOP + radius,
         STROKE, CROSSBAR + STROKE - XTOP - radius),
        ("r", 0, CROSSBAR, width, STROKE),
        ("a", radius, BASELINE - radius, radius, "bl"),
        ("r", radius, BASELINE - STROKE, width - radius - STROKE, STROKE),
    ]
    return parts, width


def glyph_s() -> tuple[list[tuple], int]:
    width, radius = 46, RADIUS_S
    parts = [
        ("r", radius, XTOP, width - radius, STROKE),
        ("a", radius, XTOP + radius, radius, "tl"),
        ("r", 0, XTOP + radius, STROKE, CROSSBAR - XTOP - radius),
        ("r", 0, CROSSBAR, width, STROKE),
        ("r", width - STROKE, CROSSBAR + STROKE,
         STROKE, BASELINE - radius - CROSSBAR - STROKE),
        ("a", width - radius, BASELINE - radius, radius, "br"),
        ("r", 0, BASELINE - STROKE, width - radius, STROKE),
    ]
    return parts, width


def glyph_l() -> tuple[list[tuple], int]:
    return [("r", 0, 0, STROKE, CAP)], STROKE


GLYPHS = {
    "D": (glyph_cap_d, 8, 6),
    "e": (glyph_e, 6, 6),
    "d": (glyph_d, 6, 8),
    "s": (glyph_s, 6, 6),
    "a": (glyph_a, 6, 8),
    "l": (glyph_l, 8, 8),
}


def build_wordmark() -> tuple[list[tuple], int, list[dict]]:
    """`Deedseal` set on its sidebearings, translated so ink starts at zero.

    The layout comes back with the parts, because the manifest declares where
    each glyph sits and the checker uses those boxes to prove that the letters
    repeat exactly where the name repeats.
    """
    parts: list[tuple] = []
    layout: list[dict] = []
    pen = 0
    for character in PRODUCT_NAME:
        builder, left, right = GLYPHS[character]
        glyph, width = builder()
        parts += shift(glyph, pen + left, 0)
        layout.append({"character": character, "origin": pen + left, "width": width})
        pen += left + width + right
    x0, _y0, x1, _y1 = bounds(parts)
    for entry in layout:
        entry["origin"] -= x0
    return shift(parts, -x0, 0), x1 - x0, layout


WORDMARK_PARTS, WORDMARK_WIDTH, WORDMARK_LAYOUT = build_wordmark()

# The lockup puts the mark's ink at the origin and sets the wordmark exactly
# half a field away from it, on the same baseline grid.
MARK_X0, _MARK_Y0, MARK_X1, _MARK_Y1 = bounds(MARK_PARTS)
MARK_INK_WIDTH = MARK_X1 - MARK_X0
LOCKUP_WORDMARK_X = MARK_INK_WIDTH + LOCKUP_GAP
LOCKUP_WIDTH = LOCKUP_WORDMARK_X + WORDMARK_WIDTH
LOCKUP_PARTS = (
    shift(MARK_PARTS, -MARK_X0, 0)
    + shift(WORDMARK_PARTS, LOCKUP_WORDMARK_X, 0)
)


# --------------------------------------------------------------------------
# constructed numerals
#
# The identity board labels its own size ladder, and a brand asset may not
# carry a `<text>` element: a label that needs a font is a label a reviewer
# cannot verify. Only the six digits the board actually sets are constructed.
# No complete numeral set is claimed.
# --------------------------------------------------------------------------

def digit_1() -> tuple[list[tuple], int]:
    return [("r", 0, 0, 18, STROKE), ("r", 8, 0, STROKE, CAP)], 18


def digit_2() -> tuple[list[tuple], int]:
    width, radius = 44, RADIUS_CAP
    return [
        ("a", radius, radius, radius, "tl"),
        ("a", radius, radius, radius, "tr"),
        ("r", width - STROKE, radius, STROKE, 12),
        ("r", 0, 34, width, STROKE),
        ("r", 0, 44, STROKE, 10),
        ("r", 0, CAP - STROKE, width, STROKE),
    ], width


def digit_3() -> tuple[list[tuple], int]:
    width, radius = 44, RADIUS_CAP
    return [
        ("r", 0, 0, radius, STROKE),
        ("a", radius, radius, radius, "tr"),
        ("r", width - STROKE, radius, STROKE, 5),
        ("r", 12, 27, width - 12, STROKE),
        ("r", width - STROKE, 37, STROKE, 5),
        ("a", radius, CAP - radius, radius, "br"),
        ("r", 0, CAP - STROKE, radius, STROKE),
    ], width


def digit_4() -> tuple[list[tuple], int]:
    width = 44
    return [
        ("r", 0, 0, STROKE, 44),
        ("r", 0, 34, width, STROKE),
        ("r", 28, 0, STROKE, CAP),
    ], width


def digit_5() -> tuple[list[tuple], int]:
    width, radius = 44, RADIUS_CAP
    return [
        ("r", 0, 0, width, STROKE),
        ("r", 0, 0, STROKE, 30),
        ("r", 0, 20, radius, STROKE),
        ("a", radius, CAP - radius, radius, "tr"),
        ("a", radius, CAP - radius, radius, "br"),
        ("r", 0, CAP - STROKE, radius, STROKE),
    ], width


def digit_6() -> tuple[list[tuple], int]:
    width, radius, low = 44, RADIUS_CAP, RADIUS_X
    return [
        ("a", radius, radius, radius, "tl"),
        ("r", radius, 0, radius, STROKE),
        ("r", 0, radius, STROKE, 26),
        ("a", low, CAP - low, low, "tl"),
        ("a", width - low, CAP - low, low, "tr"),
        ("a", low, CAP - low, low, "bl"),
        ("a", width - low, CAP - low, low, "br"),
        ("r", low, CAP - 2 * low, width - 2 * low, STROKE),
        ("r", low, CAP - STROKE, width - 2 * low, STROKE),
    ], width


DIGITS = {
    "1": digit_1, "2": digit_2, "3": digit_3,
    "4": digit_4, "5": digit_5, "6": digit_6,
}


def numeral(text: str) -> tuple[list[tuple], int]:
    """A short numeral string, translated so its ink starts at zero."""
    parts: list[tuple] = []
    pen = 0
    for character in text:
        glyph, width = DIGITS[character]()
        parts += shift(glyph, pen, 0)
        pen += width + 12
    x0, _y0, x1, _y1 = bounds(parts)
    return shift(parts, -x0, 0), x1 - x0


# --------------------------------------------------------------------------
# emitting
# --------------------------------------------------------------------------

def number(value: float) -> str:
    """A stable decimal: no exponent, no trailing zeros, no locale."""
    text = f"{value:.6f}".rstrip("0").rstrip(".")
    return text if text else "0"


def svg_document(
    *,
    width: int,
    height: int,
    body: str,
    asset: str,
    geometry: str,
    label: str,
) -> str:
    """One asset file. No script, no style, no font, no link, no text node."""
    return (
        f'<svg xmlns="{SVG_NAMESPACE}"'
        f' viewBox="0 0 {width} {height}"'
        f' width="{width}" height="{height}"'
        f' role="img" aria-label="{label}"'
        f' data-identity-version="{IDENTITY_VERSION}"'
        f' data-asset="{asset}" data-geometry="{geometry}">'
        f"{body}"
        "</svg>\n"
    )


def figure(parts: list[tuple], ink: str) -> str:
    return f'<path fill="{ink}" fill-rule="nonzero" d="{render(parts)}"/>'


def placed(parts: list[tuple], x: int, y: int, scale: float, ink: str) -> str:
    """A figure dropped onto the board at a scale, its own geometry untouched."""
    transform = f"translate({number(x)} {number(y)}) scale({number(scale)})"
    return f'<g transform="{transform}">{figure(parts, ink)}</g>'


def panel(x: int, y: int, w: int, h: int, fill: str, name: str, body: str) -> str:
    return (
        f'<g data-panel="{name}">'
        f'<path fill="{fill}" d="{rect(x, y, w, h)}"/>'
        f"{body}"
        "</g>"
    )


def ladder(parts: list[tuple], sizes: list[int], x: int, y: int, ink: str) -> str:
    """A size ladder: each specimen on one baseline, its size set beneath it."""
    body = []
    pen = x
    baseline = y + 60 + max(sizes)
    for size in sizes:
        body.append(placed(parts, pen, baseline - size, size / FIELD, ink))
        glyph, glyph_width = numeral(str(size))
        label_scale = 24 / CAP
        label_x = pen + (size - glyph_width * label_scale) / 2
        body.append(placed(glyph, label_x, baseline + 40, label_scale, ink))
        pen += size + 60
    return "".join(body)


BOARD_WIDTH = 1600
BOARD_HEIGHT = 2400
MARK_LADDER = [64, 32, 24, 16]
ICON_LADDER = [32, 24, 16]
SWATCHES = [("ink", INK), ("surface", SURFACE), ("muted", MUTED)]


def identity_board() -> str:
    """One specimen sheet: every asset, every declared size, both surfaces.

    The board sets no type it cannot draw, so it carries the same guarantee as
    the assets it displays -- open it anywhere and it renders identically.
    """
    body = [
        panel(0, 0, 800, 520, SURFACE, "mark-light",
              placed(MARK_PARTS, 208, 68, 6, INK)),
        panel(800, 0, 800, 520, SURFACE_INVERSE, "mark-dark",
              placed(MARK_PARTS, 1008, 68, 6, INK_INVERSE)),
        panel(0, 520, 800, 280, SURFACE, "mark-sizes-light",
              ladder(MARK_PARTS, MARK_LADDER, 100, 520, INK)),
        panel(800, 520, 800, 280, SURFACE, "icon-sizes-light",
              ladder(ICON_PARTS, ICON_LADDER, 900, 520, INK)),
        panel(0, 800, 800, 280, SURFACE_INVERSE, "mark-sizes-dark",
              ladder(MARK_PARTS, MARK_LADDER, 100, 800, INK_INVERSE)),
        panel(800, 800, 800, 280, SURFACE_INVERSE, "icon-sizes-dark",
              ladder(ICON_PARTS, ICON_LADDER, 900, 800, INK_INVERSE)),
        panel(0, 1080, 1600, 280, SURFACE, "lockup-light",
              placed(LOCKUP_PARTS, 276, 1156, 2, INK)),
        panel(0, 1360, 1600, 280, SURFACE_INVERSE, "lockup-dark",
              placed(LOCKUP_PARTS, 276, 1436, 2, INK_INVERSE)),
        panel(0, 1640, 1600, 220, SURFACE, "wordmark-light",
              placed(WORDMARK_PARTS, 360, 1686, 2, INK)),
    ]

    # Clearspace: the rule drawn rather than asserted. The keep-out boundary
    # sits one clearspace unit outside the lockup's ink on every side, and the
    # unit itself is set beside it so the ratio is readable off the sheet.
    unit = CLEARSPACE * 2
    ink_x, ink_y, ink_w, ink_h = 276, 1946, LOCKUP_WIDTH * 2, CAP * 2
    keepout = (
        f'<path fill="none" stroke="{MUTED}" stroke-width="2"'
        f' d="{rect(ink_x - unit, ink_y - unit, ink_w + 2 * unit, ink_h + 2 * unit)}"/>'
    )
    unit_square = (
        f'<path fill="none" stroke="{MUTED}" stroke-width="2"'
        f' d="{rect(ink_x - unit, ink_y - unit, unit, unit)}"/>'
    )
    body.append(panel(
        0, 1860, 1600, 300, SURFACE, "clearspace",
        placed(LOCKUP_PARTS, ink_x, ink_y, 2, INK) + keepout + unit_square,
    ))

    # The palette, which is three values doing five jobs. Nothing here is a
    # runtime verdict colour: those are declared in the manifest and never
    # drawn into an asset.
    swatches = []
    pen = 200
    for _role, value in SWATCHES:
        swatches.append(f'<path fill="{value}" d="{rect(pen, 2220, 300, 140)}"/>')
        swatches.append(
            f'<path fill="none" stroke="{MUTED}" stroke-width="2"'
            f' d="{rect(pen, 2220, 300, 140)}"/>'
        )
        pen += 450
    body.append(panel(0, 2160, 1600, 240, SURFACE, "palette", "".join(swatches)))

    return svg_document(
        width=BOARD_WIDTH, height=BOARD_HEIGHT,
        body="".join(body),
        asset="identity-board", geometry="board",
        label=f"{PRODUCT_NAME} identity board",
    )


def asset_documents() -> dict[str, str]:
    """Every asset this packet publishes, keyed by name under `assets/svg/`."""
    documents: dict[str, str] = {}
    for suffix, ink in (("", INK), ("-inverse", INK_INVERSE)):
        documents[f"deedseal-mark{suffix}.svg"] = svg_document(
            width=FIELD, height=FIELD,
            body=figure(MARK_PARTS, ink),
            asset=f"mark{suffix}", geometry="mark",
            label=f"{PRODUCT_NAME} mark",
        )
        documents[f"deedseal-wordmark{suffix}.svg"] = svg_document(
            width=WORDMARK_WIDTH, height=CAP,
            body=figure(WORDMARK_PARTS, ink),
            asset=f"wordmark{suffix}", geometry="wordmark",
            label=PRODUCT_NAME,
        )
        documents[f"deedseal-lockup{suffix}.svg"] = svg_document(
            width=LOCKUP_WIDTH, height=CAP,
            body=figure(LOCKUP_PARTS, ink),
            asset=f"lockup{suffix}", geometry="lockup",
            label=PRODUCT_NAME,
        )
    documents["deedseal-icon.svg"] = svg_document(
        width=FIELD, height=FIELD,
        body=figure(ICON_PARTS, INK),
        asset="icon", geometry="icon",
        label=f"{PRODUCT_NAME} icon",
    )
    documents["deedseal-identity-board.svg"] = identity_board()
    return documents


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the Deedseal brand assets.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare the committed assets with this construction and change nothing",
    )
    parser.add_argument(
        "--digests",
        action="store_true",
        help="print the SHA-256 of every asset this construction produces",
    )
    args = parser.parse_args(argv)
    documents = asset_documents()

    if args.digests:
        for name in sorted(documents):
            digest = hashlib.sha256(documents[name].encode("utf-8")).hexdigest()
            print(f"{digest}  assets/svg/{name}")
        return 0

    if args.check:
        drift = []
        for name in sorted(documents):
            path = SVG_DIR / name
            if not path.is_file():
                drift.append(f"{name}: missing")
            elif path.read_text(encoding="utf-8") != documents[name]:
                drift.append(f"{name}: differs from the construction")
        extra = sorted(
            path.name for path in SVG_DIR.glob("*.svg") if path.name not in documents
        )
        drift += [f"{name}: not produced by the construction" for name in extra]
        if drift:
            print("BRAND_ASSET_BUILD: FAIL", file=sys.stderr)
            for item in drift:
                print(f"  {item}", file=sys.stderr)
            return 1
        print(f"BRAND_ASSET_BUILD: PASS {len(documents)} assets match")
        return 0

    SVG_DIR.mkdir(parents=True, exist_ok=True)
    for name in sorted(documents):
        (SVG_DIR / name).write_text(documents[name], encoding="utf-8")
    print(f"BRAND_ASSET_BUILD: WROTE {len(documents)} assets")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Check the Deedseal brand identity packet against its own manifest.

The manifest is the claim; the files are the evidence. This checker refuses
whenever the two disagree, and it refuses on shape rather than on taste: a
missing asset, a stale digest, a wordmark that stopped spelling the product's
name, a variant whose geometry drifted from its twin, a colour nobody
declared, a runtime verdict colour smuggled into a logo, a font role with no
upstream pin, a raster target with the wrong dimensions, a downstream pin
record that does not bind what it claims to bind.

It is deterministic and it never touches the network: every input is a file in
this repository, and every answer is a function of those bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = "assets/brand-manifest.v1.json"
DOCUMENT_PATH = "assets/BRAND-IDENTITY-v1.0.md"
ASSETS_README = "assets/README.md"
BUILDER_PATH = "assets/src/build_brand_assets.py"
BOARD_PATH = "assets/svg/deedseal-identity-board.svg"

# --------------------------------------------------------------------------
# the sentence this identity is reviewed under
#
# The identity's one-sentence argument is the deliverable a reader selects on,
# and it names a measurable geometric fact. An earlier candidate said the two
# forms met along a seam "of constant width"; the drawn corridor is six units
# where the feet face and eleven across the horizontal reaches, so the sentence
# asserted a property the bytes do not have and nothing could catch it, because
# the statement was the one manifest field no check read.
#
# It is read now. The canonical text lives here as data -- never imported from
# the builder or the manifest this file is judging -- so that changing the
# sentence anywhere in the packet, in either direction, is a change that has to
# come back through review.
# --------------------------------------------------------------------------

CANONICAL_STATEMENT = (
    "Two congruent forms, each the other turned half a turn, face across a "
    "stepped corridor with a six-unit closest approach and never touch \u2014 "
    "because Deedseal binds bounded authority recorded before an action to a "
    "matching record after it, while keeping authority and evidence distinct "
    "so the correspondence can be checked."
)

# Claims about the corridor that measurement refuses. The corridor is a
# staircase; it has one closest approach, not one width.
FALSE_SEPARATION_CLAIMS = (
    (re.compile(r"constant[\s-]+(?:width|gap|corridor|seam|separation)", re.I),
     "a corridor of constant width"),
    (re.compile(r"(?:seam|corridor|gap)\s+of\s+constant\s+width", re.I),
     "a seam of constant width"),
    (re.compile(r"uniform[\s-]+(?:width|gap|corridor|seam|separation)", re.I),
     "a uniform corridor"),
    (re.compile(r"(?:corridor|seam|gap)\s+is\s+(?:constant|uniform|even)\b", re.I),
     "a corridor of even width"),
    (re.compile(r"equidistant", re.I), "an equidistant boundary"),
)

# The board's panels, in the order a reviewer read them. A board that grows,
# loses or reorders a panel is a board nobody has looked at yet.
REQUIRED_BOARD_PANELS = (
    "mark-light",
    "mark-dark",
    "mark-sizes-light",
    "icon-sizes-light",
    "mark-sizes-dark",
    "lockup-light",
    "lockup-dark",
    "wordmark-light",
    "clearspace",
    "palette",
)

MANIFEST_VERSION = "deedseal.brand-identity-manifest/v1"
PIN_VERSION = "deedseal.brand-pin-record/v1"
PRODUCT_NAME = "Deedseal"
SVG_NAMESPACE = "http://www.w3.org/2000/svg"

MAX_ASSET_BYTES = 512 * 1024

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
COLOUR_RE = re.compile(r"^#[0-9A-F]{6}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+$")
RENDERER_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
INTEGER_ONLY_RE = re.compile(r"^[A-Za-z0-9 ,.\-]*$")
PATH_NUMBER_RE = re.compile(r"-?[0-9]+(?:\.[0-9]+)?")
RECT_SUBPATH_RE = re.compile(
    r"^M(-?[0-9]+) (-?[0-9]+)H(-?[0-9]+)V(-?[0-9]+)H(-?[0-9]+)$"
)

# Elements and attributes that turn a reviewable drawing into a program, a
# download, or a dependency on something outside these bytes.
FORBIDDEN_ELEMENTS = {
    "text", "tspan", "textPath", "script", "style", "foreignObject", "image",
    "use", "iframe", "audio", "video", "animate", "animateTransform",
    "animateMotion", "set", "font", "font-face", "switch", "filter",
}
FORBIDDEN_ATTRIBUTE_SUBSTRINGS = (
    "javascript:", "data:", "file:", "url(", "http://", "https://", "expression(",
)
TRANSFORM_RE = re.compile(
    r"^(?:translate\(-?[0-9]+(?:\.[0-9]+)? -?[0-9]+(?:\.[0-9]+)?\)"
    r"|scale\(-?[0-9]+(?:\.[0-9]+)?\)|\s)+$"
)

_CREDENTIAL_PREFIXES = ("gh" + "p_", "github_" + "pat_", "s" + "k-")
SECRET_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key material"),
    (
        re.compile(
            r"\b(?:" + "|".join(re.escape(item) for item in _CREDENTIAL_PREFIXES)
            + r")[A-Za-z0-9_.-]+"
        ),
        "credential-shaped token",
    ),
    (re.compile(r"(?:^|[\s\"'(])/(?:home|root|Users|var|etc|opt|srv)/"), "absolute local path"),
    (re.compile(r"\b[A-Za-z]:\\"), "absolute local path"),
)

# The product's name, set wrong. Lowercase is legitimate inside a repository
# coordinate or a file name, and nowhere else.
MISSPELLING_RE = re.compile(
    r"\bDeed[ _-]?Seal\b|\bDEEDSEAL\b|\bDeed seal\b"
    r"|(?<![/-])\bdeedseal\b(?![/.\\-])"
)

# A code span carries an identifier, a path or a pattern, and a document that
# forbids a spelling has to be able to quote it. The name rules below read
# prose only.
CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
CODE_SPAN_RE = re.compile(r"`[^`\n]*`")

# The geometric packet remains a review candidate.  These sentences bind the
# distinction between that study and the live release surface without
# manufacturing an asset specification for the live lockup.
LIVE_SURFACE_DISCLOSURE = (
    "The public release surface continues to use the existing Deedseal "
    "wordmark and one green point, pending a later Owner brand decision. "
    "This repository does not specify, version or publish an asset for that "
    "lockup."
)

_NEGATION_RE = re.compile(
    r"\b(?:not|never|no|none|nothing|nor|neither|without|cannot)\b",
    re.IGNORECASE,
)
_NEGATION_BOUNDARY = ".!?;\"'"
_FALSE_IDENTITY_CLAIMS = (
    (
        re.compile(
            r"\b(?:Owner[- ]selected|Owner[- ]approved|adopted|deployed|"
            r"canonical|current public)\s+(?:Deedseal\s+)?(?:Brand Identity "
            r"v1\.0|identity|logo|mark|assets?)\b",
            re.IGNORECASE,
        ),
        "an adopted, deployed or canonical public identity",
    ),
    (
        re.compile(
            r"\b(?:Brand Identity v1\.0|identity|logo|mark|assets?)\s+"
            r"(?:is|are|was|were|remains?|becomes?|as)\s+(?:the\s+)?"
            r"(?:Owner[- ]selected|Owner[- ]approved|adopted|deployed|"
            r"canonical|current public)\b",
            re.IGNORECASE,
        ),
        "an Owner selection of the review candidate",
    ),
    (
        re.compile(
            r"\b(?:authorize[ds]?|approve[ds]?|clear(?:ed|s)?)\s+(?:the\s+)?"
            r"(?:assets?\s+)?(?:for\s+)?downstream placement\b|"
            r"\bdownstream placement\s+(?:is|was|has been)\s+authorized\b",
            re.IGNORECASE,
        ),
        "an authorization of downstream placement",
    ),
)
_PERMANENT_LIVE_LOCKUP_TERM_RE = re.compile(
    r"\b(?:permanent|canonical|fully specified|final)\s+"
    r"(?:identity|logo|lockup|canon)\b",
    re.IGNORECASE,
)

FAQ_REQUIRED_COORDINATES = (
    "prerelease / design-partner stage",
    "not generally available",
    "deedseal-run-passport/1.0",
    "frozen",
    "historical",
    "v0.1.0",
    "v0.2.0",
)
_FAQ_UNFROZEN_RE = re.compile(
    r"\b(?:passport(?: format)?|passport envelope|envelope)\b.{0,64}"
    r"\b(?:is|remains|stays)\s+not\s+(?:yet\s+)?frozen\b",
    re.IGNORECASE | re.DOTALL,
)
_FAQ_NO_PUBLIC_RELEASE_RE = re.compile(
    r"\b(?:there\s+is|there's|we\s+have)\s+no\s+public\s+release\b|"
    r"\bno\s+public\s+release\s+(?:exists|has been published)\b",
    re.IGNORECASE,
)

# Claims this packet has no standing to make. The negative statements the
# document does make -- that there is no claim -- do not contain these.
TRADEMARK_CLAIM_RE = re.compile(
    r"registered trademark|trademark registration|trademark search (?:was|completed)"
    r"|trademark clearance (?:obtained|complete)|cleared for use|registrable"
    r"|exclusive right",
    re.IGNORECASE,
)
TRADEMARK_SYMBOLS = {"®": "registered sign", "™": "trademark sign"}

REQUIRED_TYPE_ROLES = ("display", "interface", "technical")
TYPE_ROLE_FIELDS = {
    "role", "use", "family", "weight", "style", "license",
    "upstream_project", "distribution", "release", "release_url",
    "woff2_file", "woff2_sha256",
}
ALLOWED_FONT_LICENSES = {"OFL-1.1", "Apache-2.0"}

# Every raster surface this identity owes a consumer, at the size that surface
# actually takes. A derivative at another size is a different asset.
REQUIRED_RASTER_TARGETS = {
    "favicon-16": (16, 16),
    "favicon-32": (32, 32),
    "apple-touch-icon": (180, 180),
    "pwa-icon-192": (192, 192),
    "pwa-icon-512": (512, 512),
    "github-organization-avatar": (512, 512),
    "github-repository-social-preview": (1280, 640),
}
RASTER_TARGET_FIELDS = {"target", "source", "width", "height", "surface", "output"}
RENDERER_FIELDS = {"name", "version", "mode", "command", "page", "determinism"}

REQUIRED_ASSETS = {
    "assets/svg/deedseal-mark.svg": ("mark", "mark", True),
    "assets/svg/deedseal-mark-inverse.svg": ("mark-inverse", "mark", True),
    "assets/svg/deedseal-wordmark.svg": ("wordmark", "wordmark", False),
    "assets/svg/deedseal-wordmark-inverse.svg": ("wordmark-inverse", "wordmark", False),
    "assets/svg/deedseal-lockup.svg": ("lockup", "lockup", False),
    "assets/svg/deedseal-lockup-inverse.svg": ("lockup-inverse", "lockup", False),
    "assets/svg/deedseal-icon.svg": ("icon", "icon", True),
    "assets/svg/deedseal-identity-board.svg": ("identity-board", "board", False),
}
SQUARE_GEOMETRIES = {"mark", "icon"}

MANIFEST_FIELDS = {
    "schema_version", "identity_version", "product_name", "status",
    "source_repository", "authority", "visual_idea", "geometry", "assets",
    "geometry_groups", "simplification", "palette", "typography", "wordmark",
    "clearspace", "minimum_sizes", "surfaces", "raster_derivatives", "downstream",
    "legal",
}
ASSET_FIELDS = {
    "path", "sha256", "asset", "geometry_group", "view_box", "square",
    "size_class", "ink_role",
}
GEOMETRY_FIELDS = {
    "field", "bar", "seam", "margin", "top_bar", "stem_height", "foot_width",
    "foot_top", "half_turn_centre", "cap_height", "x_height", "stroke",
    "crossbar", "corner_radius", "lockup_gap", "minimum_separation",
    "integer_coordinates_only",
}
PALETTE_FIELDS = {
    "roles", "asset_inks", "permitted_in_assets", "contrast_pairs", "runtime_states",
}
CONTRAST_FIELDS = {"foreground", "background", "ratio", "minimum"}
CLEARSPACE_FIELDS = {"unit", "units", "relative_to", "rule"}
DOWNSTREAM_FIELDS = {"statement", "consumers", "rules", "pin_record_schema"}
PIN_SCHEMA_FIELDS = {
    "schema_version", "required_fields", "field_patterns",
    "assets_entry_fields", "typography_entry_fields", "digest_pattern",
}
REQUIRED_PIN_FIELDS = (
    "schema_version", "source_repository", "accepted_merge_commit",
    "identity_version", "manifest_path", "manifest_sha256", "assets", "typography",
)
LEGAL_FIELDS = {
    "statement", "no_trademark_search", "no_clearance_claim",
    "no_registration_claim", "symbols_forbidden", "governing_notice",
}


class BrandIdentityError(RuntimeError):
    """One named refusal. The first one ends the check."""


def fail(message: str) -> None:
    raise BrandIdentityError(message)


def exact_fields(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label}: expected an object")
    observed = set(value)
    if observed != expected:
        fail(
            f"{label}: unexpected field set: "
            f"missing={sorted(expected - observed)} extra={sorted(observed - expected)}"
        )
    return value


def text_of(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label}: expected a non-empty string")
    return value


def whole(value: object, label: str, *, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        fail(f"{label}: expected an integer of at least {minimum}")
    return value


def read_text(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file():
        fail(f"{relative}: missing")
    if path.is_symlink():
        fail(f"{relative}: must be a regular file")
    if path.stat().st_size > MAX_ASSET_BYTES:
        fail(f"{relative}: exceeds {MAX_ASSET_BYTES} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeError:
        fail(f"{relative}: must be UTF-8 text")
    return ""


# --------------------------------------------------------------------------
# colour
# --------------------------------------------------------------------------

def relative_luminance(colour: str) -> float:
    raw = colour.lstrip("#")
    channels = [int(raw[index:index + 2], 16) / 255 for index in (0, 2, 4)]
    linear = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(foreground: str, background: str) -> float:
    high = max(relative_luminance(foreground), relative_luminance(background))
    low = min(relative_luminance(foreground), relative_luminance(background))
    return (high + 0.05) / (low + 0.05)


# --------------------------------------------------------------------------
# reading one asset
# --------------------------------------------------------------------------

class Asset:
    """One parsed SVG, reduced to the facts this checker judges."""

    def __init__(self, relative: str, raw: str) -> None:
        self.path = relative
        self.raw = raw
        self.digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
            fail(f"{relative}: document type and entity declarations are refused")
        try:
            self.root = ElementTree.fromstring(raw)
        except ElementTree.ParseError as error:
            fail(f"{relative}: is not well-formed XML: {error}")
        if self.root.tag != f"{{{SVG_NAMESPACE}}}svg":
            fail(f"{relative}: root element must be an SVG in the SVG namespace")
        self.elements = list(self.root.iter())
        self.paths = [
            element.get("d", "")
            for element in self.elements
            if element.tag == f"{{{SVG_NAMESPACE}}}path"
        ]
        self.geometry = "".join(self.paths)

    def attribute(self, name: str) -> str:
        value = self.root.get(name)
        if value is None:
            fail(f"{self.path}: missing required attribute {name}")
        return value

    def colours(self) -> set[str]:
        found: set[str] = set()
        for element in self.elements:
            for name in ("fill", "stroke", "stop-color", "color"):
                value = element.get(name)
                if value is not None and value != "none":
                    found.add(value)
        return found


def inspect_asset(asset: Asset) -> None:
    """Refuse anything that makes the drawing unreviewable or non-self-contained."""
    for element in asset.elements:
        tag = element.tag.split("}")[-1]
        if tag in FORBIDDEN_ELEMENTS:
            fail(f"{asset.path}: contains a forbidden <{tag}> element")
        if not element.tag.startswith(f"{{{SVG_NAMESPACE}}}"):
            fail(f"{asset.path}: contains an element outside the SVG namespace")
        for name, value in element.attrib.items():
            plain = name.split("}")[-1]
            if plain.lower().startswith("on"):
                fail(f"{asset.path}: contains the event attribute {plain}")
            if "href" in plain.lower():
                fail(f"{asset.path}: contains a link attribute {plain}")
            lowered = value.lower()
            for marker in FORBIDDEN_ATTRIBUTE_SUBSTRINGS:
                if marker in lowered:
                    fail(f"{asset.path}: attribute {plain} references {marker}")
            if plain == "transform" and TRANSFORM_RE.fullmatch(value) is None:
                fail(f"{asset.path}: transform is not a plain translate or scale")
    for pattern, label in SECRET_PATTERNS:
        if pattern.search(asset.raw):
            fail(f"{asset.path}: contains {label}")
    if re.search(r"\b[0-9a-f]{40}\b", asset.raw):
        fail(f"{asset.path}: contains a commit-shaped identifier")
    for symbol, label in TRADEMARK_SYMBOLS.items():
        if symbol in asset.raw:
            fail(f"{asset.path}: contains the {label}")
    for value in asset.paths:
        if not value:
            fail(f"{asset.path}: contains a path with no geometry")
        for number in PATH_NUMBER_RE.findall(value):
            if "." in number:
                fail(f"{asset.path}: path data carries the non-integer value {number}")


def view_box(asset: Asset) -> list[int]:
    raw = asset.attribute("viewBox").split()
    if len(raw) != 4:
        fail(f"{asset.path}: viewBox must carry exactly four values")
    numbers = []
    for item in raw:
        if not re.fullmatch(r"-?[0-9]+", item):
            fail(f"{asset.path}: viewBox value {item!r} is not numeric")
        numbers.append(int(item))
    if numbers[0] != 0 or numbers[1] != 0:
        fail(f"{asset.path}: viewBox must start at the origin")
    if numbers[2] < 1 or numbers[3] < 1:
        fail(f"{asset.path}: viewBox must have a positive extent")
    return numbers


# --------------------------------------------------------------------------
# the mark's own argument
#
# The identity claims that one form is the other turned half a turn, and that
# the two never touch. That is checkable arithmetic, not a matter of opinion,
# so it is checked here rather than asserted in prose.
# --------------------------------------------------------------------------

def rectangles(asset: Asset) -> list[tuple[int, int, int, int]]:
    """Every subpath of an asset, as (x0, y0, x1, y1), refusing non-rectangles."""
    found = []
    for subpath in asset.geometry.split("Z"):
        subpath = subpath.strip()
        if not subpath:
            continue
        match = RECT_SUBPATH_RE.fullmatch(subpath)
        if match is None:
            fail(f"{asset.path}: subpath {subpath!r} is not a rectangle")
        x0, y0, x1, y1, back = (int(item) for item in match.groups())
        if back != x0 or x1 <= x0 or y1 <= y0:
            fail(f"{asset.path}: subpath {subpath!r} is not a closed rectangle")
        found.append((x0, y0, x1, y1))
    return found


def separation(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> int:
    """The gap between two rectangles: negative when they intersect."""
    horizontal = max(a[0] - b[2], b[0] - a[2])
    vertical = max(a[1] - b[3], b[1] - a[3])
    if horizontal < 0 and vertical < 0:
        return -1
    return max(horizontal, vertical)


def check_half_turn(asset: Asset, field: int, expected_gap: int) -> None:
    parts = rectangles(asset)
    if len(parts) % 2 or not parts:
        fail(f"{asset.path}: the mark must be two forms of equal part count")
    half = len(parts) // 2
    form_a, form_b = parts[:half], parts[half:]
    turned = sorted(
        (field - x1, field - y1, field - x0, field - y0) for x0, y0, x1, y1 in form_a
    )
    if turned != sorted(form_b):
        fail(f"{asset.path}: the second form is not the first turned half a turn")
    gaps = [separation(a, b) for a in form_a for b in form_b]
    if min(gaps) < 0:
        fail(f"{asset.path}: the two forms intersect; the seam must never close")
    if min(gaps) != expected_gap:
        fail(
            f"{asset.path}: closest approach is {min(gaps)} units, "
            f"but the manifest declares {expected_gap}"
        )


# --------------------------------------------------------------------------
# the manifest's geometry, measured off the drawing
#
# `check_geometry` proves the manifest's numbers agree with one another. That
# is not the same as proving they describe this drawing: a table can re-solve
# perfectly and still be the table for some other mark. An earlier candidate
# could move `bar` from 10 to 12, or `margin` from 6 to 7, recompute every
# derived token, leave every SVG untouched, and pass -- because only `field`
# and the closest approach ever reached the art.
#
# Everything below is read off the committed path data and compared with what
# the manifest declares. A token that does not describe the drawing is refused
# whether or not the rest of the table agrees with it.
# --------------------------------------------------------------------------

def turn_about(part: tuple[int, int, int, int], centre: list[int]) -> tuple[int, int, int, int]:
    """One rectangle turned half a turn about a point."""
    x0, y0, x1, y1 = part
    cx, cy = centre
    return (2 * cx - x1, 2 * cy - y1, 2 * cx - x0, 2 * cy - y0)


def measure_forms(asset: Asset, centre: list[int]) -> dict[str, int]:
    """The pen, the inset and the closest approach, read off the drawing itself."""
    parts = rectangles(asset)
    if not parts or len(parts) % 2:
        fail(f"{asset.path}: the figure must be two forms of equal part count")
    half = len(parts) // 2
    form_a, form_b = parts[:half], parts[half:]
    if sorted(turn_about(part, centre) for part in form_a) != sorted(form_b):
        fail(
            f"{asset.path}: the second form is not the first turned half a turn "
            f"about the declared centre {centre}"
        )
    pens = {min(x1 - x0, y1 - y0) for x0, y0, x1, y1 in parts}
    if len(pens) != 1:
        fail(f"{asset.path}: is drawn with more than one pen width: {sorted(pens)}")
    gaps = [separation(a, b) for a in form_a for b in form_b]
    if min(gaps) < 0:
        fail(f"{asset.path}: the two forms intersect; they must never touch")
    return {
        "bar": pens.pop(),
        "left": min(x0 for x0, _y0, _x1, _y1 in parts),
        "top": min(y0 for _x0, y0, _x1, _y1 in parts),
        "right": max(x1 for _x0, _y0, x1, _y1 in parts),
        "bottom": max(y1 for _x0, _y0, _x1, y1 in parts),
        "closest_approach": min(gaps),
    }


def measure_mark_bands(asset: Asset) -> dict[str, int]:
    """The mark's four bands, read off the three rectangles of its first form."""
    parts = rectangles(asset)
    form_a = parts[: len(parts) // 2]
    horizontals = sorted(
        (part for part in form_a if part[2] - part[0] > part[3] - part[1]),
        key=lambda part: part[1],
    )
    verticals = [part for part in form_a if part[3] - part[1] > part[2] - part[0]]
    if len(horizontals) != 2 or len(verticals) != 1:
        fail(
            f"{asset.path}: the mark is a top bar, a stem and a foot, not "
            f"{len(horizontals)} horizontal and {len(verticals)} vertical bands"
        )
    top_bar, foot = horizontals
    stem = verticals[0]
    return {
        "top_bar": top_bar[2] - top_bar[0],
        "stem_height": stem[3] - stem[1],
        "foot_width": foot[2] - foot[0],
        "foot_top": foot[1],
    }


def check_geometry_against_art(
    geometry: dict[str, Any], assets: dict[str, Asset], boxes: dict[str, list[int]]
) -> None:
    """Refuse a manifest whose geometry does not describe the committed drawing."""
    field = geometry["field"]
    centre = geometry["half_turn_centre"]
    square_assets = (
        "assets/svg/deedseal-mark.svg",
        "assets/svg/deedseal-mark-inverse.svg",
        "assets/svg/deedseal-icon.svg",
    )
    for relative in square_assets:
        asset = assets[relative]
        box = boxes[relative]
        if [box[2], box[3]] != [field, field]:
            fail(
                f"{relative}: is drawn on a {box[2]} by {box[3]} field, but "
                f"geometry.field declares {field}"
            )
        measured = measure_forms(asset, centre)
        if measured["bar"] != geometry["bar"]:
            fail(
                f"{relative}: the drawn pen is {measured['bar']} units wide, but "
                f"geometry.bar declares {geometry['bar']}"
            )
        insets = {
            measured["left"],
            measured["top"],
            field - measured["right"],
            field - measured["bottom"],
        }
        if insets != {geometry["margin"]}:
            fail(
                f"{relative}: the drawn ink is inset {sorted(insets)} from the field, "
                f"but geometry.margin declares {geometry['margin']}"
            )

    mark = assets["assets/svg/deedseal-mark.svg"]
    approach = measure_forms(mark, centre)["closest_approach"]
    if approach != geometry["seam"]:
        fail(
            f"assets/svg/deedseal-mark.svg: the two forms come closest at "
            f"{approach} units, but geometry.seam declares {geometry['seam']}"
        )
    for name, drawn in measure_mark_bands(mark).items():
        if geometry[name] != drawn:
            fail(
                f"geometry.{name}: declares {geometry[name]}, but the committed "
                f"mark draws {drawn}"
            )


# --------------------------------------------------------------------------
# the identity board
#
# The board is a specimen sheet, so it is also a claim: every panel says "this
# asset exists, on this surface". An earlier candidate painted the icon in the
# inverse ink on a dark panel while the manifest, the document and the packet's
# own rules all said no inverse icon exists. Recomputing the board's digest hid
# nothing, because no check read what the board actually drew.
# --------------------------------------------------------------------------

def figure_signature(geometry: str) -> frozenset[str]:
    """One drawn figure, reduced to the set of subpaths that make it up."""
    return frozenset(part.strip() for part in geometry.split("Z") if part.strip())


def board_panels(board: Asset) -> list[tuple[str, str, list[tuple[str, str]]]]:
    """Every panel of the board: its name, the surface it lays down, what it paints.

    A panel lays its surface down first and draws onto it afterwards. That order
    is load-bearing rather than stylistic: it is how the surface a figure sits on
    is known at all, so a panel that opens with anything but its own background
    rectangle is refused rather than guessed at.
    """
    tag = f"{{{SVG_NAMESPACE}}}path"
    panels = []
    for group in board.root:
        name = group.get("data-panel")
        if name is None:
            fail(f"{board.path}: carries a top-level group that names no panel")
        children = list(group)
        if not children or children[0].tag != tag:
            fail(f"{board.path}: panel {name!r} does not lay its surface down first")
        background = children[0]
        if RECT_SUBPATH_RE.fullmatch(background.get("d", "").strip().rstrip("Z")) is None:
            fail(f"{board.path}: panel {name!r} opens with a figure rather than a surface")
        drawn = [
            (element.get("fill", ""), element.get("d", ""))
            for element in group.iter()
            if element.tag == tag and element is not background
        ]
        if not drawn:
            fail(f"{board.path}: panel {name!r} paints nothing onto its surface")
        panels.append((name, background.get("fill", ""), drawn))
    return panels


def check_board(
    board: Asset, assets: dict[str, Asset], groups: dict[str, Any], palette: dict[str, Any]
) -> None:
    """Refuse a board that demonstrates an asset this identity does not publish."""
    panels = board_panels(board)
    names = tuple(name for name, _surface, _drawn in panels)
    if names != REQUIRED_BOARD_PANELS:
        fail(
            f"{board.path}: draws panels {list(names)}, not the reviewed board "
            f"{list(REQUIRED_BOARD_PANELS)}"
        )

    roles = palette["roles"]
    for role in ("ink-inverse", "surface-inverse"):
        if role not in roles:
            fail(f"palette.roles.{role}: the board needs it to judge a dark panel")
    inverse_ink = roles["ink-inverse"]["value"]
    inverse_surface = roles["surface-inverse"]["value"]

    # Any geometry group with a single member has no inverse twin to draw with.
    # The board is itself such a group and is excluded: it is the sheet, not a
    # figure placed on one.
    single_ink = {}
    for name, group in groups.items():
        if name == "board" or len(group["members"]) != 1:
            continue
        member = group["members"][0]
        single_ink[name] = (member, figure_signature(assets[member].geometry))

    for panel_name, surface, drawn in panels:
        for group_name, (member, signature) in single_ink.items():
            for fill, data in drawn:
                if figure_signature(data) != signature:
                    continue
                if fill == inverse_ink:
                    fail(
                        f"{board.path}: panel {panel_name!r} paints {member} in the "
                        f"inverse ink, but this identity publishes no inverse {group_name}"
                    )
                if surface == inverse_surface:
                    fail(
                        f"{board.path}: panel {panel_name!r} demonstrates {member} on "
                        f"the dark surface, but this identity publishes no inverse "
                        f"{group_name}"
                    )


# --------------------------------------------------------------------------
# the wordmark's own argument
#
# A wordmark is a claim about a string. This checker cannot read letterforms,
# but it can prove the letters repeat where the name repeats: in `Deedseal`
# the second, third and sixth glyphs are one letter and must be one geometry.
# A wordmark that stopped spelling the product's name fails that test.
# --------------------------------------------------------------------------

SECTOR_SUBPATH_RE = re.compile(
    r"^M(-?[0-9]+) (-?[0-9]+)"
    r"A([0-9]+) ([0-9]+) 0 0 1 (-?[0-9]+) (-?[0-9]+)"
    r"L(-?[0-9]+) (-?[0-9]+)"
    r"A([0-9]+) ([0-9]+) 0 0 0 (-?[0-9]+) (-?[0-9]+)$"
)


def subpaths(asset: Asset) -> list[str]:
    return [item for item in (part.strip() for part in asset.geometry.split("Z")) if item]


def primitive(asset: Asset, subpath: str, dx: int = 0) -> tuple:
    """One subpath as a comparable tuple, with x translated by -dx."""
    rectangle = RECT_SUBPATH_RE.fullmatch(subpath)
    if rectangle is not None:
        x0, y0, x1, y1, back = (int(item) for item in rectangle.groups())
        if back != x0:
            fail(f"{asset.path}: rectangle {subpath!r} does not close on itself")
        return ("r", x0 - dx, y0, x1 - dx, y1)
    arc = SECTOR_SUBPATH_RE.fullmatch(subpath)
    if arc is None:
        fail(f"{asset.path}: subpath {subpath!r} is neither a rectangle nor a quarter turn")
    ax, ay, outer, outer2, bx, by, px, py, inner, inner2, qx, qy = (
        int(item) for item in arc.groups()
    )
    if outer != outer2 or inner != inner2:
        fail(f"{asset.path}: quarter turn {subpath!r} is not circular")
    if inner >= outer:
        fail(f"{asset.path}: quarter turn {subpath!r} has no pen width")
    return (
        "a", ax - dx, ay, outer, bx - dx, by,
        px - dx, py, inner, qx - dx, qy,
    )


def extent(item: tuple) -> tuple[int, int]:
    """The x-extent a primitive occupies, generously: arcs bulge to the radius."""
    if item[0] == "r":
        return item[1], item[3]
    _, ax, _ay, outer, bx, _by, px, _py, _inner, qx, _qy = item
    return min(ax, bx, px, qx) - outer, max(ax, bx, px, qx) + outer


def glyph_clusters(asset: Asset, glyphs: list[dict[str, Any]]) -> list[list[tuple]]:
    """Every subpath assigned to the one declared glyph box that contains it."""
    clusters: list[list[tuple]] = [[] for _ in glyphs]
    for subpath in subpaths(asset):
        item = primitive(asset, subpath)
        low, high = extent(item)
        home = [
            index for index, glyph in enumerate(glyphs)
            if glyph["origin"] - glyph["width"] <= low
            and high <= glyph["origin"] + 2 * glyph["width"]
            and glyph["origin"] <= (low + high) / 2 <= glyph["origin"] + glyph["width"]
        ]
        if len(home) != 1:
            fail(
                f"{asset.path}: subpath {subpath!r} does not sit inside exactly one "
                f"declared glyph box"
            )
        index = home[0]
        clusters[index].append(primitive(asset, subpath, glyphs[index]["origin"]))
    for index, cluster in enumerate(clusters):
        if not cluster:
            fail(f"{asset.path}: declared glyph {index} has no geometry")
    return clusters


def check_wordmark(asset: Asset, wordmark: dict[str, Any]) -> None:
    glyphs = wordmark["glyphs"]
    spelled = "".join(glyph["character"] for glyph in glyphs)
    if spelled != PRODUCT_NAME:
        fail(f"{asset.path}: the declared glyph sequence spells {spelled!r}")
    if asset.attribute("aria-label") != PRODUCT_NAME:
        fail(f"{asset.path}: accessible name must be exactly {PRODUCT_NAME!r}")
    clusters = glyph_clusters(asset, glyphs)
    shapes: dict[str, list[tuple]] = {}
    for glyph, cluster in zip(glyphs, clusters):
        character = glyph["character"]
        shape = sorted(cluster)
        if character in shapes:
            if shapes[character] != shape:
                fail(
                    f"{asset.path}: two glyphs declared {character!r} do not share "
                    f"one geometry"
                )
        else:
            shapes[character] = shape
    for left in shapes:
        for right in shapes:
            if left < right and shapes[left] == shapes[right]:
                fail(
                    f"{asset.path}: glyphs {left!r} and {right!r} are the same shape, "
                    f"so the wordmark does not distinguish them"
                )


def check_lockup(lockup: Asset, mark: Asset, wordmark: Asset, offset: int) -> None:
    """The lockup must be the mark and the wordmark, not a redrawing of them."""
    mark_parts = sorted(primitive(mark, item) for item in subpaths(mark))
    word_parts = sorted(primitive(wordmark, item) for item in subpaths(wordmark))
    mark_ink = min(extent(item)[0] for item in mark_parts)
    expected = sorted(
        [
            primitive(mark, item, mark_ink)
            for item in subpaths(mark)
        ]
        + [
            tuple(
                value + offset if index in _X_SLOTS[primitive(wordmark, item)[0]] else value
                for index, value in enumerate(primitive(wordmark, item))
            )
            for item in subpaths(wordmark)
        ]
    )
    observed = sorted(primitive(lockup, item) for item in subpaths(lockup))
    if observed != expected:
        fail(f"{lockup.path}: geometry is not the mark and the wordmark placed together")
    if not mark_parts or not word_parts:
        fail(f"{lockup.path}: the lockup's components carry no geometry")


# Which slots of a primitive tuple hold an x coordinate.
_X_SLOTS = {"r": {1, 3}, "a": {1, 4, 6, 9}}


# --------------------------------------------------------------------------
# the non-donor boundary
#
# The retired public assets are a live observation, not a design authority.
# The mechanical half of that rule is checkable: their generators must be gone
# and none of their palette coordinates may reappear. The vocabulary half --
# no retired slogan, no retired motif -- stays a reviewer's judgement, and this
# checker does not pretend otherwise.
# --------------------------------------------------------------------------

RETIRED_GENERATORS = ("assets/src/build_card.py", "assets/src/build_mark.py")
RETIRED_PALETTE = (
    "#0B0F14", "#F4F6F8", "#10151B", "#8C98A3", "#171E27",
    "#CED4DB", "#28323E", "#34A873", "#60D69C", "#96A2AD",
)
RETIRED_FAMILIES = ("Bricolage", "Geist Mono")


def check_non_donor(root: Path, texts: dict[str, str]) -> None:
    for relative in RETIRED_GENERATORS:
        if (root / relative).exists():
            fail(f"{relative}: a retired generator is still present")
    for relative, text in texts.items():
        upper = text.upper()
        for colour in RETIRED_PALETTE:
            if colour.upper() in upper:
                fail(f"{relative}: carries the retired palette coordinate {colour}")
        for family in RETIRED_FAMILIES:
            if family.lower() in text.lower():
                fail(f"{relative}: carries the retired type family {family}")


def unwrapped(text: str) -> str:
    """One long line, so a sentence is found however its file happened to wrap it."""
    lines = [re.sub(r"^\s*>\s?", "", line) for line in text.splitlines()]
    return re.sub(r"\s+", " ", " ".join(lines)).strip()


def check_no_false_separation(relative: str, text: str) -> None:
    """Refuse any file in this packet that claims a separation the art does not have."""
    for pattern, claim in FALSE_SEPARATION_CLAIMS:
        found = pattern.search(text)
        if found is not None:
            fail(
                f"{relative}: claims {claim} ({found.group(0)!r}); the corridor is a "
                f"staircase and has one closest approach, not one width"
            )


def check_visual_idea(idea: dict[str, Any], texts: dict[str, str]) -> None:
    """Bind the identity's one-sentence argument to the sentence under review.

    Three refusals, in the order a reviewer would meet them: a statement that
    reaches for the shorthand this identity rejects; a statement that claims a
    separation the drawing does not have; and any other unreviewed edit.
    """
    statement = text_of(idea["statement"], "visual_idea.statement")
    for shorthand in idea["rejected_shorthand"]:
        if not isinstance(shorthand, str) or not shorthand.strip():
            fail("visual_idea.rejected_shorthand: every entry must be a named motif")
        if re.search(rf"\b{re.escape(shorthand)}\b", statement, re.IGNORECASE):
            fail(
                f"visual_idea.statement: names the rejected shorthand {shorthand!r}"
            )
    check_no_false_separation("visual_idea.statement", statement)
    if statement != CANONICAL_STATEMENT:
        fail(
            "visual_idea.statement: is not the canonical statement this identity is "
            "reviewed under; changing the argument is a change that comes back "
            "through review"
        )
    for relative, text in texts.items():
        check_no_false_separation(relative, text)
    for relative in (DOCUMENT_PATH, BUILDER_PATH):
        text = texts.get(relative)
        if text is None:
            continue
        if CANONICAL_STATEMENT not in unwrapped(text):
            fail(f"{relative}: does not carry the canonical statement verbatim")


def prose_only(relative: str, text: str) -> str:
    """Markdown with its code spans and fenced blocks removed."""
    if not relative.endswith(".md"):
        return text
    return CODE_SPAN_RE.sub(" ", CODE_FENCE_RE.sub(" ", text))


def _claim_is_negated(text: str, start: int) -> bool:
    """Whether a claim-shaped term is denied in its own clause."""
    window = text[max(0, start - 72) : start]
    boundary = max(window.rfind(character) for character in _NEGATION_BOUNDARY)
    if boundary >= 0:
        window = window[boundary + 1 :]
    return _NEGATION_RE.search(window) is not None


def identity_alignment_violation(raw: str, relative: str = "public text") -> str | None:
    """Name a public claim that promotes the review candidate or live lockup.

    This is intentionally prose-aware and negation-aware.  A truthful denial
    ("not the adopted identity") must remain writable, while an affirmative
    claim cannot be laundered by another denial elsewhere in the document.
    """
    text = unwrapped(prose_only(relative, raw))
    for pattern, reason in _FALSE_IDENTITY_CLAIMS:
        for match in pattern.finditer(text):
            if not _claim_is_negated(text, match.start()):
                return reason
    for match in _PERMANENT_LIVE_LOCKUP_TERM_RE.finditer(text):
        context = text[max(0, match.start() - 200) : match.start()].lower()
        boundary = max(context.rfind(character) for character in _NEGATION_BOUNDARY)
        if boundary >= 0:
            context = context[boundary + 1 :]
        if (
            "wordmark" in context
            and "green point" in context
            and not _claim_is_negated(text, match.start())
        ):
            return "the live wordmark and green point settled as a specified permanent canon"
    return None


def faq_alignment_violation(raw: str) -> str | None:
    """Name a drift from the release and passport coordinates the FAQ owes."""
    # Coordinates are intentionally code-formatted in Markdown, so keep inline
    # code while excluding fenced examples.
    text = unwrapped(CODE_FENCE_RE.sub(" ", raw))
    if _FAQ_UNFROZEN_RE.search(text):
        return "the 1.0 passport envelope called unfrozen"
    if _FAQ_NO_PUBLIC_RELEASE_RE.search(text):
        return "no public release, while v0.1.0 is preserved as historical"
    lower = text.lower()
    for coordinate in FAQ_REQUIRED_COORDINATES:
        if coordinate.lower() not in lower:
            return f"missing FAQ alignment coordinate {coordinate!r}"
    return None


def check_prose(relative: str, raw: str) -> None:
    text = prose_only(relative, raw)
    misspelled = MISSPELLING_RE.search(text)
    if misspelled is not None:
        fail(f"{relative}: sets the product name as {misspelled.group(0)!r}")
    if PRODUCT_NAME not in text:
        fail(f"{relative}: never sets the canonical product name")
    for symbol, label in TRADEMARK_SYMBOLS.items():
        if symbol in text:
            fail(f"{relative}: carries the {label}")
    claim = TRADEMARK_CLAIM_RE.search(text)
    if claim is not None:
        fail(f"{relative}: makes the trademark claim {claim.group(0)!r}")


# --------------------------------------------------------------------------
# the downstream pin record
# --------------------------------------------------------------------------

def check_pin_record(record: object, manifest: dict[str, Any], label: str = "pin") -> None:
    """Refuse a consumer's pin unless it binds exactly what it claims to bind."""
    schema = manifest["downstream"]["pin_record_schema"]
    if not isinstance(record, dict):
        fail(f"{label}: expected an object")
    exact_fields(record, set(schema["required_fields"]), label)
    for field, pattern in schema["field_patterns"].items():
        value = record[field]
        if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
            fail(f"{label}.{field}: does not match {pattern}")
    if record["identity_version"] != manifest["identity_version"]:
        fail(f"{label}.identity_version: does not match the manifest")

    declared = {item["path"]: item["sha256"] for item in manifest["assets"]}
    pinned = record["assets"]
    if not isinstance(pinned, list) or not pinned:
        fail(f"{label}.assets: expected a non-empty array")
    seen = set()
    for index, item in enumerate(pinned):
        exact_fields(item, set(schema["assets_entry_fields"]), f"{label}.assets[{index}]")
        path = item["path"]
        if path not in declared:
            fail(f"{label}.assets[{index}]: {path} is not a declared asset")
        if re.fullmatch(schema["digest_pattern"], str(item["sha256"])) is None:
            fail(f"{label}.assets[{index}]: digest is malformed")
        if item["sha256"] != declared[path]:
            fail(f"{label}.assets[{index}]: {path} is pinned to a digest the manifest does not carry")
        seen.add(path)
    if seen != set(declared):
        fail(f"{label}.assets: does not pin every declared asset: missing={sorted(set(declared) - seen)}")

    fonts = {role["role"]: role for role in manifest["typography"]["roles"]}
    pinned_fonts = record["typography"]
    if not isinstance(pinned_fonts, list) or not pinned_fonts:
        fail(f"{label}.typography: expected a non-empty array")
    roles_seen = set()
    for index, item in enumerate(pinned_fonts):
        exact_fields(
            item, set(schema["typography_entry_fields"]), f"{label}.typography[{index}]"
        )
        role = item["role"]
        if role not in fonts:
            fail(f"{label}.typography[{index}]: {role} is not a declared type role")
        if item["woff2_file"] != fonts[role]["woff2_file"]:
            fail(f"{label}.typography[{index}]: pins a file the manifest does not name")
        if item["woff2_sha256"] != fonts[role]["woff2_sha256"]:
            fail(f"{label}.typography[{index}]: pins a digest the manifest does not carry")
        roles_seen.add(role)
    if roles_seen != set(fonts):
        fail(f"{label}.typography: does not pin every declared type role")


# --------------------------------------------------------------------------
# the manifest
# --------------------------------------------------------------------------

def load_manifest(root: Path) -> dict[str, Any]:
    raw = read_text(root, MANIFEST_PATH)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"{MANIFEST_PATH}: invalid JSON: {error}")
    return exact_fields(value, MANIFEST_FIELDS, "manifest")


def check_geometry(geometry: dict[str, Any]) -> None:
    exact_fields(geometry, GEOMETRY_FIELDS, "manifest.geometry")
    field = whole(geometry["field"], "geometry.field", minimum=8)
    bar = whole(geometry["bar"], "geometry.bar")
    seam = whole(geometry["seam"], "geometry.seam")
    margin = whole(geometry["margin"], "geometry.margin")
    for name, expected in (
        ("top_bar", field - 2 * margin - bar - seam),
        ("stem_height", (field + bar) // 2 - margin),
        ("foot_width", (field - seam) // 2 - margin),
        ("foot_top", (field - bar) // 2),
    ):
        if geometry[name] != expected:
            fail(
                f"geometry.{name}: is {geometry[name]} but the field, the bar and "
                f"the seam force {expected}"
            )
    if geometry["half_turn_centre"] != [field // 2, field // 2]:
        fail("geometry.half_turn_centre: must be the centre of the field")
    if geometry["cap_height"] != field:
        fail("geometry.cap_height: the wordmark's cap height must equal the mark's field")
    if geometry["stroke"] != bar:
        fail("geometry.stroke: the wordmark's stroke must equal the mark's bar")
    if geometry["integer_coordinates_only"] is not True:
        fail("geometry.integer_coordinates_only: this identity is drawn on integers")
    radii = geometry["corner_radius"]
    exact_fields(radii, {"x_height", "cap", "spine"}, "geometry.corner_radius")
    for name, value in radii.items():
        if whole(value, f"geometry.corner_radius.{name}") <= bar:
            fail(f"geometry.corner_radius.{name}: must exceed the pen width")
    exact_fields(
        geometry["minimum_separation"], {"mark", "icon"}, "geometry.minimum_separation"
    )
    for name, value in geometry["minimum_separation"].items():
        if whole(value, f"geometry.minimum_separation.{name}") < seam:
            fail(f"geometry.minimum_separation.{name}: closer than one seam")
    whole(geometry["x_height"], "geometry.x_height")
    whole(geometry["crossbar"], "geometry.crossbar")
    whole(geometry["lockup_gap"], "geometry.lockup_gap")


def check_palette(palette: dict[str, Any], assets: dict[str, Asset]) -> set[str]:
    exact_fields(palette, PALETTE_FIELDS, "manifest.palette")
    roles = palette["roles"]
    if not isinstance(roles, dict) or not roles:
        fail("palette.roles: expected a non-empty object")
    values: dict[str, str] = {}
    for name, entry in roles.items():
        exact_fields(entry, {"value", "use"}, f"palette.roles.{name}")
        value = text_of(entry["value"], f"palette.roles.{name}.value")
        if COLOUR_RE.fullmatch(value) is None:
            fail(f"palette.roles.{name}.value: {value!r} is not an upper-case six-digit hex")
        text_of(entry["use"], f"palette.roles.{name}.use")
        values[name] = value

    permitted = palette["permitted_in_assets"]
    if not isinstance(permitted, list) or not permitted:
        fail("palette.permitted_in_assets: expected a non-empty array")
    for colour in permitted:
        if colour not in values.values():
            fail(f"palette.permitted_in_assets: {colour!r} is not a declared role value")
    for role in palette["asset_inks"]:
        if role not in values:
            fail(f"palette.asset_inks: {role!r} is not a declared role")
        if values[role] not in permitted:
            fail(f"palette.asset_inks: {role!r} is not permitted in an asset")

    states = palette["runtime_states"]
    exact_fields(
        states, {"statement", "permitted_in_assets", "roles"}, "palette.runtime_states"
    )
    text_of(states["statement"], "palette.runtime_states.statement")
    if states["permitted_in_assets"] is not False:
        fail("palette.runtime_states.permitted_in_assets: a runtime verdict is not a brand accent")
    state_values: set[str] = set()
    for name, entry in states["roles"].items():
        exact_fields(entry, {"value", "on", "ratio"}, f"palette.runtime_states.roles.{name}")
        value = text_of(entry["value"], f"runtime state {name}")
        if COLOUR_RE.fullmatch(value) is None:
            fail(f"palette.runtime_states.roles.{name}.value: not an upper-case six-digit hex")
        if entry["on"] not in values:
            fail(f"palette.runtime_states.roles.{name}.on: not a declared surface role")
        observed = round(contrast_ratio(value, values[entry["on"]]), 2)
        if observed != entry["ratio"]:
            fail(
                f"palette.runtime_states.roles.{name}.ratio: declared {entry['ratio']}, "
                f"computes {observed}"
            )
        if observed < 4.5:
            fail(f"palette.runtime_states.roles.{name}: contrast {observed} is below 4.5")
        state_values.add(value)
    overlap = state_values & set(permitted)
    if overlap:
        fail(f"palette: runtime verdict colours are permitted in assets: {sorted(overlap)}")

    pairs = palette["contrast_pairs"]
    if not isinstance(pairs, list) or len(pairs) < 2:
        fail("palette.contrast_pairs: expected at least two declared pairs")
    for index, pair in enumerate(pairs):
        exact_fields(pair, CONTRAST_FIELDS, f"palette.contrast_pairs[{index}]")
        for side in ("foreground", "background"):
            if pair[side] not in values:
                fail(f"palette.contrast_pairs[{index}].{side}: not a declared role")
        observed = round(contrast_ratio(values[pair["foreground"]], values[pair["background"]]), 2)
        if observed != pair["ratio"]:
            fail(
                f"palette.contrast_pairs[{index}]: declared {pair['ratio']}, "
                f"computes {observed}"
            )
        if observed < pair["minimum"]:
            fail(
                f"palette.contrast_pairs[{index}]: {observed} is below the declared "
                f"minimum {pair['minimum']}"
            )

    for relative, asset in assets.items():
        for colour in asset.colours():
            if colour in state_values:
                fail(f"{relative}: paints a runtime verdict colour into a brand asset")
            if colour not in permitted:
                fail(f"{relative}: paints the undeclared colour {colour}")
    return set(values)


def check_typography(typography: dict[str, Any]) -> None:
    exact_fields(typography, {"statement", "roles", "vendoring"}, "manifest.typography")
    text_of(typography["statement"], "typography.statement")
    text_of(typography["vendoring"], "typography.vendoring")
    roles = typography["roles"]
    if not isinstance(roles, list):
        fail("typography.roles: expected an array")
    observed = tuple(role.get("role") for role in roles if isinstance(role, dict))
    if observed != REQUIRED_TYPE_ROLES:
        fail(
            f"typography.roles: must declare exactly {list(REQUIRED_TYPE_ROLES)} in order, "
            f"observed {list(observed)}"
        )
    for role in roles:
        name = role["role"]
        exact_fields(role, TYPE_ROLE_FIELDS, f"typography.roles.{name}")
        for field in ("use", "family", "distribution", "release", "woff2_file"):
            text_of(role[field], f"typography.roles.{name}.{field}")
        if role["license"] not in ALLOWED_FONT_LICENSES:
            fail(
                f"typography.roles.{name}.license: {role['license']!r} is not one of "
                f"{sorted(ALLOWED_FONT_LICENSES)}"
            )
        if SHA256_RE.fullmatch(str(role["woff2_sha256"])) is None:
            fail(f"typography.roles.{name}.woff2_sha256: not a SHA-256 digest")
        if not isinstance(role["weight"], int) or not 100 <= role["weight"] <= 900:
            fail(f"typography.roles.{name}.weight: expected a numeric font weight")
        if role["style"] not in {"normal", "italic"}:
            fail(f"typography.roles.{name}.style: expected normal or italic")
        for field in ("upstream_project", "release_url"):
            url = text_of(role[field], f"typography.roles.{name}.{field}")
            if not url.startswith("https://"):
                fail(f"typography.roles.{name}.{field}: must be an https coordinate")
            if "github.com/" in url:
                fail(
                    f"typography.roles.{name}.{field}: this record does not carry "
                    f"third-party repository URLs"
                )
        if not role["woff2_file"].endswith(".woff2"):
            fail(f"typography.roles.{name}.woff2_file: must name a WOFF2 file")


def check_raster(
    derivatives: dict[str, Any], declared: set[str], palette: dict[str, Any]
) -> None:
    exact_fields(
        derivatives, {"renderer", "targets", "committed", "reason"},
        "manifest.raster_derivatives",
    )
    if derivatives["committed"] is not False:
        fail("raster_derivatives.committed: this record accepts UTF-8 text only")
    text_of(derivatives["reason"], "raster_derivatives.reason")
    renderer = exact_fields(
        derivatives["renderer"], RENDERER_FIELDS, "raster_derivatives.renderer"
    )
    for field in RENDERER_FIELDS:
        text_of(renderer[field], f"raster_derivatives.renderer.{field}")
    if RENDERER_VERSION_RE.fullmatch(renderer["version"]) is None:
        fail(
            f"raster_derivatives.renderer.version: {renderer['version']!r} is not a "
            f"pinned version"
        )
    for token in ("{source}", "{output}", "{width}", "{height}"):
        if token not in renderer["command"] + renderer["page"]:
            fail(f"raster_derivatives.renderer: the recipe never uses {token}")

    targets = derivatives["targets"]
    if not isinstance(targets, list) or not targets:
        fail("raster_derivatives.targets: expected a non-empty array")
    observed: dict[str, tuple[int, int]] = {}
    for index, target in enumerate(targets):
        exact_fields(target, RASTER_TARGET_FIELDS, f"raster_derivatives.targets[{index}]")
        name = text_of(target["target"], f"targets[{index}].target")
        width = whole(target["width"], f"targets[{index}].width")
        height = whole(target["height"], f"targets[{index}].height")
        if target["source"] not in declared:
            fail(f"targets[{index}]: source {target['source']} is not a declared asset")
        output = text_of(target["output"], f"targets[{index}].output")
        if f"{width}x{height}" not in output:
            fail(f"targets[{index}]: output name does not carry its {width}x{height} size")
        if not output.endswith(".png"):
            fail(f"targets[{index}]: output must name a PNG")
        surface = text_of(target["surface"], f"targets[{index}].surface")
        if surface not in palette["roles"]:
            fail(f"targets[{index}]: surface {surface!r} is not a declared palette role")
        # An asset with no inverse twin carries one ink, and one ink on the wrong
        # surface is an invisible logo. The icon is the case that matters: the
        # allowlist gives it no inverse, so every target that takes it must be
        # rendered onto the light surface.
        inverse = target["source"].replace(".svg", "-inverse.svg")
        if inverse not in declared and surface != "surface":
            fail(
                f"targets[{index}]: {target['source']} has no inverse variant, so it "
                f"may only be rendered onto the light surface"
            )
        if name in observed:
            fail(f"raster_derivatives.targets: {name} is declared twice")
        observed[name] = (width, height)
    for name, size in REQUIRED_RASTER_TARGETS.items():
        if name not in observed:
            fail(f"raster_derivatives.targets: required target {name} is missing")
        if observed[name] != size:
            fail(
                f"raster_derivatives.targets: {name} is {observed[name][0]}x"
                f"{observed[name][1]}, the surface takes {size[0]}x{size[1]}"
            )


def check_downstream(downstream: dict[str, Any]) -> None:
    exact_fields(downstream, DOWNSTREAM_FIELDS, "manifest.downstream")
    text_of(downstream["statement"], "downstream.statement")
    consumers = downstream["consumers"]
    if not isinstance(consumers, list) or len(consumers) < 3:
        fail("downstream.consumers: the landing, the client and the GitHub surfaces")
    rules = downstream["rules"]
    if not isinstance(rules, list) or len(rules) < 5:
        fail("downstream.rules: the adoption protocol has five parts")
    for rule in rules:
        text_of(rule, "downstream.rules")
    schema = exact_fields(
        downstream["pin_record_schema"], PIN_SCHEMA_FIELDS, "downstream.pin_record_schema"
    )
    if schema["schema_version"] != PIN_VERSION:
        fail("downstream.pin_record_schema.schema_version: wrong pin schema version")
    if tuple(schema["required_fields"]) != REQUIRED_PIN_FIELDS:
        fail(
            f"downstream.pin_record_schema.required_fields: must be exactly "
            f"{list(REQUIRED_PIN_FIELDS)}"
        )
    patterns = schema["field_patterns"]
    if not isinstance(patterns, dict):
        fail("downstream.pin_record_schema.field_patterns: expected an object")
    for field, pattern in patterns.items():
        if field not in REQUIRED_PIN_FIELDS:
            fail(f"pin_record_schema.field_patterns: {field} is not a pinned field")
        try:
            re.compile(pattern)
        except re.error as error:
            fail(f"pin_record_schema.field_patterns.{field}: {error}")
    if patterns.get("accepted_merge_commit") != COMMIT_RE.pattern:
        fail("pin_record_schema: the accepted merge commit must be pinned as a full commit")
    if patterns.get("manifest_sha256") != SHA256_RE.pattern:
        fail("pin_record_schema: the manifest digest must be pinned as a SHA-256")
    if schema["digest_pattern"] != SHA256_RE.pattern:
        fail("pin_record_schema.digest_pattern: must be a SHA-256 pattern")
    if tuple(schema["assets_entry_fields"]) != ("path", "sha256"):
        fail("pin_record_schema.assets_entry_fields: must be exactly path and sha256")
    if tuple(schema["typography_entry_fields"]) != ("role", "woff2_file", "woff2_sha256"):
        fail("pin_record_schema.typography_entry_fields: must bind role, file and digest")


def check_identity(root: Path = ROOT) -> tuple[str, int]:
    """Refuse on the first disagreement between the manifest and the files."""
    manifest = load_manifest(root)
    if manifest["schema_version"] != MANIFEST_VERSION:
        fail("manifest.schema_version: wrong manifest schema version")
    identity_version = text_of(manifest["identity_version"], "manifest.identity_version")
    if VERSION_RE.fullmatch(identity_version) is None:
        fail("manifest.identity_version: expected a two-part version")
    if manifest["product_name"] != PRODUCT_NAME:
        fail(f"manifest.product_name: must be exactly {PRODUCT_NAME!r}")
    if manifest["status"] not in {"review-candidate", "accepted", "superseded"}:
        fail("manifest.status: unknown status")
    if manifest["source_repository"] != "deedseal/deedseal":
        fail("manifest.source_repository: this identity is sourced from the public record")

    exact_fields(
        manifest["authority"],
        {"routing", "public_surface_authority", "legacy_exclusions", "non_donor_statement"},
        "manifest.authority",
    )
    for name, value in manifest["authority"].items():
        text_of(value, f"manifest.authority.{name}")
    idea = exact_fields(
        manifest["visual_idea"],
        {"statement", "construction", "rejected_shorthand"},
        "manifest.visual_idea",
    )
    text_of(idea["construction"], "visual_idea.construction")
    if not isinstance(idea["rejected_shorthand"], list) or len(idea["rejected_shorthand"]) < 8:
        fail("visual_idea.rejected_shorthand: name the shorthand this identity refuses")

    # The prose this packet publishes, read once. The builder is optional here
    # only because a caller may check an assets-only copy of the packet; when it
    # is present it is held to the same sentence as everything else.
    texts = {
        MANIFEST_PATH: read_text(root, MANIFEST_PATH),
        DOCUMENT_PATH: read_text(root, DOCUMENT_PATH),
        ASSETS_README: read_text(root, ASSETS_README),
    }
    if (root / BUILDER_PATH).is_file():
        texts[BUILDER_PATH] = read_text(root, BUILDER_PATH)
    check_visual_idea(idea, texts)

    check_geometry(manifest["geometry"])
    geometry = manifest["geometry"]

    # every declared asset, read once
    entries: dict[str, dict[str, Any]] = {}
    assets: dict[str, Asset] = {}
    boxes: dict[str, list[int]] = {}
    for index, entry in enumerate(manifest["assets"]):
        exact_fields(entry, ASSET_FIELDS, f"manifest.assets[{index}]")
        relative = text_of(entry["path"], f"assets[{index}].path")
        if relative in entries:
            fail(f"manifest.assets: {relative} is declared twice")
        entries[relative] = entry
    if set(entries) != set(REQUIRED_ASSETS):
        fail(
            "manifest.assets: asset set differs from the required set: "
            f"missing={sorted(set(REQUIRED_ASSETS) - set(entries))} "
            f"extra={sorted(set(entries) - set(REQUIRED_ASSETS))}"
        )
    present = sorted(
        path.relative_to(root).as_posix() for path in (root / "assets/svg").glob("*.svg")
    )
    if present != sorted(REQUIRED_ASSETS):
        fail(
            "assets/svg: tree differs from the required set: "
            f"missing={sorted(set(REQUIRED_ASSETS) - set(present))} "
            f"extra={sorted(set(present) - set(REQUIRED_ASSETS))}"
        )

    for relative, entry in entries.items():
        asset = Asset(relative, read_text(root, relative))
        assets[relative] = asset
        kind, group, square = REQUIRED_ASSETS[relative]
        if entry["asset"] != kind:
            fail(f"{relative}: declared as {entry['asset']!r}, expected {kind!r}")
        if entry["geometry_group"] != group:
            fail(f"{relative}: declared in geometry group {entry['geometry_group']!r}")
        if entry["sha256"] != asset.digest:
            fail(f"{relative}: digest is stale")
        inspect_asset(asset)
        box = view_box(asset)
        boxes[relative] = box
        if entry["view_box"] != box:
            fail(f"{relative}: declared viewBox {entry['view_box']} is not the file's {box}")
        if (box[2] == box[3]) is not bool(entry["square"]):
            fail(f"{relative}: the declared square flag is wrong")
        if group in SQUARE_GEOMETRIES and box[2] != box[3]:
            fail(f"{relative}: a {group} must have a square viewBox")
        if asset.attribute("data-identity-version") != identity_version:
            fail(f"{relative}: identity version disagrees with the manifest")
        if asset.attribute("data-asset") != kind:
            fail(f"{relative}: the asset attribute disagrees with the manifest")
        if asset.attribute("data-geometry") != group:
            fail(f"{relative}: the geometry attribute disagrees with the manifest")
        if not asset.attribute("aria-label").startswith(PRODUCT_NAME):
            fail(f"{relative}: accessible name does not name the product")
        if entry["ink_role"] not in manifest["palette"]["roles"]:
            fail(f"{relative}: ink role {entry['ink_role']!r} is not declared")
        text_of(entry["size_class"], f"{relative}: size class")

    groups = manifest["geometry_groups"]
    if set(groups) != {entry["geometry_group"] for entry in entries.values()}:
        fail("manifest.geometry_groups: does not cover exactly the declared groups")
    for name, group in groups.items():
        exact_fields(group, {"members", "shared"}, f"geometry_groups.{name}")
        text_of(group["shared"], f"geometry_groups.{name}.shared")
        members = group["members"]
        expected = sorted(
            path for path, entry in entries.items() if entry["geometry_group"] == name
        )
        if sorted(members) != expected:
            fail(f"geometry_groups.{name}.members: {sorted(members)} is not {expected}")
        shapes = {assets[member].geometry for member in members}
        if name != "board" and len(shapes) != 1:
            fail(f"geometry_groups.{name}: the variants have drifted apart")

    simplification = exact_fields(
        manifest["simplification"],
        {"asset", "parent", "rule", "reason", "applies_below_px"},
        "manifest.simplification",
    )
    for side in ("asset", "parent"):
        if simplification[side] not in entries:
            fail(f"simplification.{side}: {simplification[side]} is not a declared asset")
    text_of(simplification["rule"], "simplification.rule")
    text_of(simplification["reason"], "simplification.reason")
    whole(simplification["applies_below_px"], "simplification.applies_below_px")
    if assets[simplification["asset"]].geometry == assets[simplification["parent"]].geometry:
        fail("simplification: the icon does not simplify anything")

    check_palette(manifest["palette"], assets)
    check_typography(manifest["typography"])

    # the mark's and the icon's half-turn, and the wordmark's spelling
    separations = geometry["minimum_separation"]
    check_half_turn(assets["assets/svg/deedseal-mark.svg"], geometry["field"], separations["mark"])
    check_half_turn(assets["assets/svg/deedseal-mark-inverse.svg"], geometry["field"], separations["mark"])
    check_half_turn(assets["assets/svg/deedseal-icon.svg"], geometry["field"], separations["icon"])
    check_geometry_against_art(geometry, assets, boxes)
    check_board(
        assets[BOARD_PATH], assets, manifest["geometry_groups"], manifest["palette"]
    )

    wordmark = exact_fields(manifest["wordmark"], {"name", "glyphs"}, "manifest.wordmark")
    if wordmark["name"] != PRODUCT_NAME:
        fail(f"manifest.wordmark.name: must be exactly {PRODUCT_NAME!r}")
    glyphs = wordmark["glyphs"]
    if not isinstance(glyphs, list) or len(glyphs) != len(PRODUCT_NAME):
        fail(f"manifest.wordmark.glyphs: expected {len(PRODUCT_NAME)} glyphs")
    pen = -1
    for index, glyph in enumerate(glyphs):
        exact_fields(glyph, {"character", "origin", "width"}, f"wordmark.glyphs[{index}]")
        if glyph["character"] != PRODUCT_NAME[index]:
            fail(f"wordmark.glyphs[{index}]: declares {glyph['character']!r}")
        origin = whole(glyph["origin"], f"wordmark.glyphs[{index}].origin", minimum=0)
        whole(glyph["width"], f"wordmark.glyphs[{index}].width")
        if origin <= pen:
            fail(f"wordmark.glyphs[{index}]: origins must advance")
        pen = origin
    word_box = entries["assets/svg/deedseal-wordmark.svg"]["view_box"]
    if glyphs[-1]["origin"] + glyphs[-1]["width"] != word_box[2]:
        fail("manifest.wordmark.glyphs: the last glyph does not end at the wordmark's edge")

    check_wordmark(assets["assets/svg/deedseal-wordmark.svg"], wordmark)
    check_wordmark(assets["assets/svg/deedseal-wordmark-inverse.svg"], wordmark)

    mark_asset = assets["assets/svg/deedseal-mark.svg"]
    mark_extents = [
        extent(primitive(mark_asset, item)) for item in subpaths(mark_asset)
    ]
    mark_ink_width = max(high for _low, high in mark_extents) - min(
        low for low, _high in mark_extents
    )
    for variant in ("", "-inverse"):
        check_lockup(
            assets[f"assets/svg/deedseal-lockup{variant}.svg"],
            assets[f"assets/svg/deedseal-mark{variant}.svg"],
            assets[f"assets/svg/deedseal-wordmark{variant}.svg"],
            mark_ink_width + geometry["lockup_gap"],
        )
    lockup_box = entries["assets/svg/deedseal-lockup.svg"]["view_box"]
    if lockup_box[2] != mark_ink_width + geometry["lockup_gap"] + word_box[2]:
        fail("assets/svg/deedseal-lockup.svg: its width is not mark plus gap plus wordmark")

    clearspace = exact_fields(manifest["clearspace"], CLEARSPACE_FIELDS, "manifest.clearspace")
    if whole(clearspace["units"], "clearspace.units") * 4 != geometry["field"]:
        fail("clearspace.units: the rule is one quarter of the mark field")
    for name in ("unit", "relative_to", "rule"):
        text_of(clearspace[name], f"clearspace.{name}")

    minimums = manifest["minimum_sizes"]
    if set(minimums) != set(entries):
        fail("manifest.minimum_sizes: must cover exactly the declared assets")
    for relative, rule in minimums.items():
        exact_fields(rule, {"minimum_px", "measured"}, f"minimum_sizes.{relative}")
        whole(rule["minimum_px"], f"minimum_sizes.{relative}.minimum_px", minimum=8)
        if rule["measured"] not in {"width", "height"}:
            fail(f"minimum_sizes.{relative}.measured: expected width or height")
    if (
        minimums["assets/svg/deedseal-icon.svg"]["minimum_px"]
        >= minimums["assets/svg/deedseal-mark.svg"]["minimum_px"]
    ):
        fail("minimum_sizes: the icon exists to go smaller than the mark")
    if minimums["assets/svg/deedseal-icon.svg"]["minimum_px"] > 16:
        fail("minimum_sizes: the icon must survive a 16 px favicon")

    surfaces = manifest["surfaces"]
    if not isinstance(surfaces, list) or not surfaces:
        fail("manifest.surfaces: expected a non-empty array")
    for index, surface in enumerate(surfaces):
        exact_fields(surface, {"surface", "source", "format"}, f"manifest.surfaces[{index}]")
        text_of(surface["surface"], f"surfaces[{index}].surface")
        if surface["source"] not in entries:
            fail(f"surfaces[{index}]: source {surface['source']} is not a declared asset")
        if surface["format"] != "svg":
            fail(f"surfaces[{index}]: a vector surface takes the SVG master")

    check_raster(manifest["raster_derivatives"], set(entries), manifest["palette"])
    check_downstream(manifest["downstream"])

    legal = exact_fields(manifest["legal"], LEGAL_FIELDS, "manifest.legal")
    text_of(legal["statement"], "legal.statement")
    for flag in ("no_trademark_search", "no_clearance_claim", "no_registration_claim"):
        if legal[flag] is not True:
            fail(f"legal.{flag}: this packet makes no such claim, and must say so")
    if sorted(legal["symbols_forbidden"]) != ["registered-sign", "trademark-sign"]:
        fail("legal.symbols_forbidden: both symbols are forbidden")
    if legal["governing_notice"] != "NOTICE.md":
        fail("legal.governing_notice: the repository's own notice governs names and marks")

    for relative in (MANIFEST_PATH, DOCUMENT_PATH, ASSETS_README):
        check_prose(relative, texts[relative])
        violation = identity_alignment_violation(texts[relative], relative)
        if violation is not None:
            fail(f"{relative}: carries {violation}")
    check_non_donor(root, {**texts, **{name: asset.raw for name, asset in assets.items()}})

    for relative in (DOCUMENT_PATH, ASSETS_README):
        for required in (MANIFEST_PATH, "assets/svg/deedseal-lockup.svg"):
            if required not in texts[relative]:
                fail(f"{relative}: never points a reader at {required}")
        if LIVE_SURFACE_DISCLOSURE not in unwrapped(texts[relative]):
            fail(f"{relative}: missing the live wordmark and green-point disclosure")

    return identity_version, len(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(ROOT), help="repository root to check")
    parser.add_argument(
        "--pin", help="also check one downstream pin record against this manifest"
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    try:
        identity_version, count = check_identity(root)
        if args.pin:
            manifest = load_manifest(root)
            record = json.loads(Path(args.pin).read_text(encoding="utf-8"))
            check_pin_record(record, manifest, Path(args.pin).name)
    except BrandIdentityError as error:
        print(f"BRAND_IDENTITY_CHECK: FAIL: {error}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as error:
        print(f"BRAND_IDENTITY_CHECK: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"BRAND_IDENTITY_CHECK: PASS identity={identity_version} assets={count} "
        f"product={PRODUCT_NAME}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

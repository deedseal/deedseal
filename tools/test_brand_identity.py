#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Prove the brand identity checker refuses what it claims to refuse.

Every test below takes a working copy of the packet, breaks exactly one thing
a reviewer would look for, and asserts the refusal. A checker that only ever
says PASS is not evidence of anything, so the interesting assertions here are
the failures.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_brand_identity as brand  # noqa: E402

MANIFEST = "assets/brand-manifest.v1.json"
DOCUMENT = "assets/BRAND-IDENTITY-v1.0.md"
ASSETS_README = "assets/README.md"
MARK = "assets/svg/deedseal-mark.svg"
MARK_INVERSE = "assets/svg/deedseal-mark-inverse.svg"
WORDMARK = "assets/svg/deedseal-wordmark.svg"
LOCKUP = "assets/svg/deedseal-lockup.svg"
ICON = "assets/svg/deedseal-icon.svg"
BOARD = "assets/svg/deedseal-identity-board.svg"
BUILDER = "assets/src/build_brand_assets.py"


@contextmanager
def sandbox():
    """A throwaway copy of the packet, so no test can touch the real tree."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "packet"
        (root / "assets/src").mkdir(parents=True)
        shutil.copytree(ROOT / "assets/svg", root / "assets/svg")
        for name in (MANIFEST, DOCUMENT, ASSETS_README, BUILDER):
            shutil.copyfile(ROOT / name, root / name)
        yield root


def read_manifest(root: Path) -> dict:
    return json.loads((root / MANIFEST).read_text(encoding="utf-8"))


def write_manifest(root: Path, manifest: dict) -> None:
    (root / MANIFEST).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )


def write_asset(root: Path, relative: str, text: str) -> None:
    """Write an asset and re-sync its digest, so the digest rule stays out of the way."""
    (root / relative).write_text(text, encoding="utf-8")
    manifest = read_manifest(root)
    for entry in manifest["assets"]:
        if entry["path"] == relative:
            entry["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    write_manifest(root, manifest)


def write_pair(root: Path, stem: str, before: str, after: str) -> None:
    """Mutate a light/dark pair identically.

    Drifting one variant is its own refusal, and it fires first. To reach the
    rule underneath, a reviewer has to break both variants the same way.
    """
    for relative in (f"assets/svg/{stem}.svg", f"assets/svg/{stem}-inverse.svg"):
        text = (root / relative).read_text(encoding="utf-8")
        changed = text.replace(before, after, 1)
        assert changed != text, relative
        write_asset(root, relative, changed)


def pin_record(manifest: dict) -> dict:
    """A pin record a well-behaved consumer would write."""
    return {
        "schema_version": "deedseal.brand-pin-record/v1",
        "source_repository": "deedseal/deedseal",
        "accepted_merge_commit": "0" * 40,
        "identity_version": manifest["identity_version"],
        "manifest_path": MANIFEST,
        "manifest_sha256": "0" * 64,
        "assets": [
            {"path": entry["path"], "sha256": entry["sha256"]}
            for entry in manifest["assets"]
        ],
        "typography": [
            {
                "role": role["role"],
                "woff2_file": role["woff2_file"],
                "woff2_sha256": role["woff2_sha256"],
            }
            for role in manifest["typography"]["roles"]
        ],
    }


class BrandIdentityCheckerTests(unittest.TestCase):
    """The committed packet, and forty ways of breaking it."""

    def refuse(self, root: Path, fragment: str) -> None:
        with self.assertRaises(brand.BrandIdentityError) as caught:
            brand.check_identity(root)
        self.assertIn(fragment, str(caught.exception))

    def refuse_pin(self, record: dict, fragment: str) -> None:
        manifest = read_manifest(ROOT)
        with self.assertRaises(brand.BrandIdentityError) as caught:
            brand.check_pin_record(record, manifest)
        self.assertIn(fragment, str(caught.exception))

    # -- the packet as committed ------------------------------------------

    def test_committed_packet_passes(self) -> None:
        identity_version, count = brand.check_identity(ROOT)
        self.assertEqual(identity_version, "1.0")
        self.assertEqual(count, 8)

    def test_a_clean_copy_passes(self) -> None:
        with sandbox() as root:
            self.assertEqual(brand.check_identity(root), ("1.0", 8))

    def test_the_check_is_deterministic(self) -> None:
        with sandbox() as root:
            self.assertEqual(brand.check_identity(root), brand.check_identity(root))

    def test_the_checker_reaches_no_network(self) -> None:
        source = (ROOT / "tools/check_brand_identity.py").read_text(encoding="utf-8")
        for module in ("socket", "urllib", "http.client", "requests", "subprocess"):
            self.assertNotIn(f"import {module}", source)

    def test_a_well_formed_pin_record_passes(self) -> None:
        manifest = read_manifest(ROOT)
        brand.check_pin_record(pin_record(manifest), manifest)

    # -- the asset set ----------------------------------------------------

    def test_a_missing_asset_is_refused(self) -> None:
        with sandbox() as root:
            (root / ICON).unlink()
            self.refuse(root, "tree differs from the required set")

    def test_an_extra_asset_is_refused(self) -> None:
        with sandbox() as root:
            shutil.copyfile(root / MARK, root / "assets/svg/deedseal-spare.svg")
            self.refuse(root, "tree differs from the required set")

    def test_a_renamed_asset_is_refused(self) -> None:
        with sandbox() as root:
            (root / ICON).rename(root / "assets/svg/deedseal-glyph.svg")
            self.refuse(root, "tree differs from the required set")

    def test_an_undeclared_asset_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["assets"] = [
                entry for entry in manifest["assets"] if entry["path"] != ICON
            ]
            write_manifest(root, manifest)
            self.refuse(root, "asset set differs from the required set")

    def test_a_stale_digest_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            for entry in manifest["assets"]:
                if entry["path"] == MARK:
                    entry["sha256"] = "0" * 64
            write_manifest(root, manifest)
            self.refuse(root, "digest is stale")

    def test_an_edited_asset_without_a_new_digest_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            (root / MARK).write_text(text.replace('width="64"', 'width="65"'), encoding="utf-8")
            self.refuse(root, "digest is stale")

    # -- the product's name -----------------------------------------------

    def test_a_misdeclared_product_name_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["product_name"] = "DeedSeal"
            write_manifest(root, manifest)
            self.refuse(root, "must be exactly 'Deedseal'")

    def test_a_misspelled_name_in_prose_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / DOCUMENT).read_text(encoding="utf-8")
            (root / DOCUMENT).write_text(
                text.replace("## The name", "## The name\n\nDeed Seal is the product.\n"),
                encoding="utf-8",
            )
            self.refuse(root, "sets the product name as")

    def test_a_wordmark_label_that_stops_naming_the_product_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / WORDMARK).read_text(encoding="utf-8")
            write_asset(root, WORDMARK, text.replace('aria-label="Deedseal"', 'aria-label="Deedseal wordmark"'))
            self.refuse(root, "accessible name must be exactly")

    def test_a_glyph_sequence_that_spells_something_else_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["wordmark"]["glyphs"][0]["character"] = "B"
            write_manifest(root, manifest)
            self.refuse(root, "declares 'B'")

    def test_two_letters_drawn_the_same_are_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["wordmark"]["glyphs"][3]["character"] = "e"
            manifest["wordmark"]["name"] = "Deedseal"
            write_manifest(root, manifest)
            self.refuse(root, "declares 'e'")

    def test_a_wordmark_whose_repeated_letters_drifted_is_refused(self) -> None:
        with sandbox() as root:
            # move one bar of the second 'e'; the other two keep their shape
            write_pair(root, "deedseal-wordmark", "M140 18H156V28H140Z", "M140 19H156V29H140Z")
            self.refuse(root, "do not share")

    # -- the viewBox ------------------------------------------------------

    def test_a_non_numeric_view_box_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('viewBox="0 0 64 64"', 'viewBox="0 0 64 auto"'))
            self.refuse(root, "is not numeric")

    def test_a_short_view_box_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('viewBox="0 0 64 64"', 'viewBox="0 0 64"'))
            self.refuse(root, "exactly four values")

    def test_a_non_square_mark_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('viewBox="0 0 64 64"', 'viewBox="0 0 64 72"'))
            manifest = read_manifest(root)
            for entry in manifest["assets"]:
                if entry["path"] == MARK:
                    entry["view_box"] = [0, 0, 64, 72]
                    entry["square"] = False
            write_manifest(root, manifest)
            self.refuse(root, "must have a square viewBox")

    def test_a_view_box_the_manifest_does_not_declare_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            for entry in manifest["assets"]:
                if entry["path"] == LOCKUP:
                    entry["view_box"] = [0, 0, 525, 64]
            write_manifest(root, manifest)
            self.refuse(root, "is not the file's")

    # -- what an asset may contain ----------------------------------------

    def test_a_text_element_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace("</svg>", "<text>Deedseal</text></svg>"))
            self.refuse(root, "forbidden <text> element")

    def test_a_script_element_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace("</svg>", "<script>1</script></svg>"))
            self.refuse(root, "forbidden <script> element")

    def test_an_event_attribute_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace("<path ", '<path onclick="go()" '))
            self.refuse(root, "event attribute")

    def test_a_foreign_object_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace("</svg>", "<foreignObject/></svg>"))
            self.refuse(root, "forbidden <foreignObject> element")

    def test_an_animation_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace("</svg>", '<animate attributeName="opacity"/></svg>'))
            self.refuse(root, "forbidden <animate> element")

    def test_a_style_element_carrying_a_remote_font_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace("</svg>", "<style>x</style></svg>"))
            self.refuse(root, "forbidden <style> element")

    def test_a_linked_image_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / BOARD).read_text(encoding="utf-8")
            write_asset(root, BOARD, text.replace("</svg>", "<image/></svg>"))
            self.refuse(root, "forbidden <image> element")

    def test_an_external_url_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('fill="#141414"', 'fill="url(https://example.invalid/a)"'))
            self.refuse(root, "references")

    def test_an_absolute_local_path_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            # assembled, so this file does not itself carry a machine path
            elsewhere = "/" + "etc/passwd"
            write_asset(root, MARK, text.replace('aria-label="Deedseal mark"', f'aria-label="Deedseal mark {elsewhere}"'))
            self.refuse(root, "absolute local path")

    def test_an_embedded_secret_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            marker = "-----BEGIN " + "PRIVATE KEY-----"
            write_asset(root, MARK, text.replace('aria-label="Deedseal mark"', f'aria-label="Deedseal mark {marker}"'))
            self.refuse(root, "private key material")

    def test_a_commit_shaped_identifier_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('data-asset="mark"', f'data-asset="mark" data-note="{"a" * 40}"'))
            self.refuse(root, "commit-shaped identifier")

    def test_a_trademark_symbol_in_an_asset_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('aria-label="Deedseal mark"', 'aria-label="Deedseal mark ®"'))
            self.refuse(root, "registered sign")

    def test_a_non_integer_coordinate_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace("M6 6H42V16H6Z", "M6 6H42.5V16H6Z", 1))
            self.refuse(root, "non-integer value")

    def test_a_transform_that_is_not_a_translate_or_scale_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / BOARD).read_text(encoding="utf-8")
            write_asset(root, BOARD, text.replace('transform="translate(208 68) scale(6)"', 'transform="rotate(9)"', 1))
            self.refuse(root, "not a plain translate or scale")

    # -- the identity's own argument ---------------------------------------

    def test_a_broken_half_turn_is_refused(self) -> None:
        with sandbox() as root:
            write_pair(root, "deedseal-mark", "M22 48H58V58H22Z", "M23 48H58V58H23Z")
            self.refuse(root, "not the first turned half a turn")

    def test_a_closed_seam_is_refused(self) -> None:
        with sandbox() as root:
            write_pair(root, "deedseal-mark", "M6 27H29V37H6Z", "M6 27H35V37H6Z")
            write_pair(root, "deedseal-mark", "M35 27H58V37H35Z", "M29 27H58V37H29Z")
            self.refuse(root, "intersect")

    def test_a_seam_the_manifest_does_not_declare_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["geometry"]["minimum_separation"]["mark"] = 7
            write_manifest(root, manifest)
            self.refuse(root, "closest approach")

    def test_a_hand_edited_geometry_token_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["geometry"]["top_bar"] = 38
            write_manifest(root, manifest)
            self.refuse(root, "force")

    def test_geometry_drift_between_the_variants_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK_INVERSE).read_text(encoding="utf-8")
            write_asset(root, MARK_INVERSE, text.replace("M6 6H42V16H6Z", "M6 6H41V16H6Z", 1))
            self.refuse(root, "drifted apart")

    def test_a_redrawn_lockup_is_refused(self) -> None:
        with sandbox() as root:
            write_pair(root, "deedseal-lockup", "M0 6H36V16H0Z", "M0 7H36V17H0Z")
            self.refuse(root, "not the mark and the wordmark")

    def test_an_icon_that_simplifies_nothing_is_refused(self) -> None:
        with sandbox() as root:
            mark = (root / MARK).read_text(encoding="utf-8")
            icon = (root / ICON).read_text(encoding="utf-8")
            geometry = re.search(r'd="([^"]+)"', mark).group(1)
            write_asset(root, ICON, re.sub(r'd="[^"]+"', f'd="{geometry}"', icon))
            self.refuse(root, "does not simplify anything")

    # -- the identity version ----------------------------------------------

    def test_an_asset_from_another_identity_version_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('data-identity-version="1.0"', 'data-identity-version="2.0"'))
            self.refuse(root, "identity version disagrees")

    # -- colour ------------------------------------------------------------

    def test_an_undeclared_colour_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('fill="#141414"', 'fill="#123456"'))
            self.refuse(root, "undeclared colour")

    def test_green_used_as_a_brand_accent_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / MARK).read_text(encoding="utf-8")
            write_asset(root, MARK, text.replace('fill="#141414"', 'fill="#1F6F43"'))
            self.refuse(root, "runtime verdict colour into a brand asset")

    def test_permitting_a_runtime_colour_in_assets_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["palette"]["runtime_states"]["permitted_in_assets"] = True
            write_manifest(root, manifest)
            self.refuse(root, "not a brand accent")

    def test_a_misdeclared_contrast_ratio_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["palette"]["contrast_pairs"][0]["ratio"] = 21.0
            write_manifest(root, manifest)
            self.refuse(root, "computes")

    def test_a_palette_role_below_the_contrast_floor_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            for pair in manifest["palette"]["contrast_pairs"]:
                if pair["foreground"] == "muted" and pair["background"] == "surface":
                    pair["minimum"] = 10.0
            write_manifest(root, manifest)
            self.refuse(root, "below the declared minimum")

    # -- typography --------------------------------------------------------

    def test_a_missing_type_role_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["typography"]["roles"] = manifest["typography"]["roles"][:2]
            write_manifest(root, manifest)
            self.refuse(root, "must declare exactly")

    def test_a_type_role_without_an_upstream_pin_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            del manifest["typography"]["roles"][0]["release"]
            write_manifest(root, manifest)
            self.refuse(root, "unexpected field set")

    def test_a_type_role_without_a_licence_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["typography"]["roles"][1]["license"] = "All rights reserved"
            write_manifest(root, manifest)
            self.refuse(root, "is not one of")

    def test_a_missing_consumer_font_digest_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["typography"]["roles"][2]["woff2_sha256"] = ""
            write_manifest(root, manifest)
            self.refuse(root, "not a SHA-256 digest")

    def test_a_third_party_repository_url_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            # assembled, so this file does not itself carry a third-party repository URL
            elsewhere = "https://git" + "hub.com/example/font"
            manifest["typography"]["roles"][0]["upstream_project"] = elsewhere
            write_manifest(root, manifest)
            self.refuse(root, "third-party repository URLs")

    # -- derivatives, clearspace and minimum sizes -------------------------

    def test_an_unpinned_renderer_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["raster_derivatives"]["renderer"]["version"] = "latest"
            write_manifest(root, manifest)
            self.refuse(root, "not a pinned version")

    def test_a_wrong_derivative_dimension_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            for target in manifest["raster_derivatives"]["targets"]:
                if target["target"] == "github-repository-social-preview":
                    target["width"], target["height"] = 1200, 630
                    target["output"] = "deedseal-lockup-social-1200x630.png"
            write_manifest(root, manifest)
            self.refuse(root, "the surface takes 1280x640")

    def test_a_missing_raster_target_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["raster_derivatives"]["targets"] = [
                target for target in manifest["raster_derivatives"]["targets"]
                if target["target"] != "favicon-16"
            ]
            write_manifest(root, manifest)
            self.refuse(root, "required target favicon-16 is missing")

    def test_an_undeclared_derivative_surface_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["raster_derivatives"]["targets"][0]["surface"] = "chrome"
            write_manifest(root, manifest)
            self.refuse(root, "is not a declared palette role")

    def test_a_single_ink_asset_on_a_dark_surface_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            for target in manifest["raster_derivatives"]["targets"]:
                if target["source"] == ICON:
                    target["surface"] = "surface-inverse"
            write_manifest(root, manifest)
            self.refuse(root, "may only be rendered onto the light surface")

    def test_committing_rasters_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["raster_derivatives"]["committed"] = True
            write_manifest(root, manifest)
            self.refuse(root, "UTF-8 text only")

    def test_a_missing_clearspace_rule_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            del manifest["clearspace"]["rule"]
            write_manifest(root, manifest)
            self.refuse(root, "unexpected field set")

    def test_a_clearspace_that_is_not_a_quarter_field_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["clearspace"]["units"] = 12
            write_manifest(root, manifest)
            self.refuse(root, "one quarter of the mark field")

    def test_a_missing_minimum_size_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            del manifest["minimum_sizes"][ICON]
            write_manifest(root, manifest)
            self.refuse(root, "must cover exactly the declared assets")

    def test_an_icon_that_cannot_reach_a_favicon_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["minimum_sizes"][ICON]["minimum_px"] = 24
            write_manifest(root, manifest)
            self.refuse(root, "16 px favicon")

    # -- the identity's one-sentence argument -------------------------------
    #
    # The argument is the deliverable a reader selects on, and it names a
    # measurable fact. An earlier candidate said the two forms met along a seam
    # "of constant width" while the drawn corridor is six units at the feet and
    # eleven across the reaches, and nothing in the packet could catch it. These
    # are the cases that must stay caught.

    def test_the_old_constant_width_statement_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["visual_idea"]["statement"] = (
                "Two congruent forms, each the other turned half a turn, meet along "
                "one stepped seam of constant width and never touch, because Deedseal "
                "binds one bounded authority before an action to one matching record "
                "after it and keeps the two apart so the correspondence can be checked."
            )
            write_manifest(root, manifest)
            self.refuse(root, "claims a corridor of constant width")

    def test_a_padlock_and_rings_statement_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["visual_idea"]["statement"] = (
                "Three concentric rings in a padlock, because Deedseal is a padlock."
            )
            write_manifest(root, manifest)
            self.refuse(root, "names the rejected shorthand")

    def test_a_shield_and_checkmark_statement_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["visual_idea"]["statement"] = (
                "A shield carrying a checkmark, because Deedseal protects your work."
            )
            write_manifest(root, manifest)
            self.refuse(root, "names the rejected shorthand")

    def test_an_unreviewed_edit_to_the_statement_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["visual_idea"]["statement"] = (
                "Two congruent forms that never touch, because Deedseal binds an "
                "authority recorded before an action to the record produced after it."
            )
            write_manifest(root, manifest)
            self.refuse(root, "is not the canonical statement")

    def test_a_statement_claiming_a_uniform_corridor_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["visual_idea"]["statement"] = brand.CANONICAL_STATEMENT.replace(
                "a six-unit closest approach", "a uniform width of six units"
            )
            write_manifest(root, manifest)
            self.refuse(root, "claims a uniform corridor")

    def test_the_document_losing_the_canonical_statement_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / DOCUMENT).read_text(encoding="utf-8")
            changed = text.replace("face across a\n> stepped corridor", "sit beside a\n> stepped corridor", 1)
            self.assertNotEqual(changed, text)
            (root / DOCUMENT).write_text(changed, encoding="utf-8")
            self.refuse(root, "does not carry the canonical statement verbatim")

    def test_the_builder_reasserting_a_constant_width_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / BUILDER).read_text(encoding="utf-8")
            changed = text.replace(
                "The corridor is a staircase, so it has no single width.",
                "The corridor is of constant width.",
                1,
            )
            self.assertNotEqual(changed, text)
            (root / BUILDER).write_text(changed, encoding="utf-8")
            self.refuse(root, "claims a corridor of constant width")

    def test_the_builder_losing_the_canonical_statement_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / BUILDER).read_text(encoding="utf-8")
            changed = text.replace("face across a stepped", "sit beside a stepped", 1)
            self.assertNotEqual(changed, text)
            (root / BUILDER).write_text(changed, encoding="utf-8")
            self.refuse(root, "does not carry the canonical statement verbatim")

    def test_the_committed_packet_carries_the_canonical_statement_everywhere(self) -> None:
        manifest = read_manifest(ROOT)
        self.assertEqual(manifest["visual_idea"]["statement"], brand.CANONICAL_STATEMENT)
        for relative in (DOCUMENT, BUILDER):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn(brand.CANONICAL_STATEMENT, brand.unwrapped(text))

    # -- review-candidate and live-surface authority -----------------------

    def test_an_adopted_identity_claim_is_refused_by_name(self) -> None:
        with sandbox() as root:
            path = root / DOCUMENT
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nBrand Identity v1.0 is the adopted identity.\n",
                encoding="utf-8",
            )
            self.refuse(root, "an adopted, deployed or canonical public identity")

    def test_a_current_public_identity_claim_is_refused_by_name(self) -> None:
        with sandbox() as root:
            path = root / ASSETS_README
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nBrand Identity v1.0 is the current public identity.\n",
                encoding="utf-8",
            )
            self.refuse(root, "an adopted, deployed or canonical public identity")

    def test_downstream_placement_authority_is_refused_by_name(self) -> None:
        with sandbox() as root:
            path = root / DOCUMENT
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nThese assets authorize downstream placement.\n",
                encoding="utf-8",
            )
            self.refuse(root, "an authorization of downstream placement")

    def test_the_live_lockup_becoming_a_permanent_canon_is_refused(self) -> None:
        with sandbox() as root:
            path = root / DOCUMENT
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nThe Deedseal wordmark and one green point form the permanent identity.\n",
                encoding="utf-8",
            )
            self.refuse(root, "settled as a specified permanent canon")

    def test_each_packet_document_must_carry_the_live_surface_disclosure(self) -> None:
        for relative in (DOCUMENT, ASSETS_README):
            with self.subTest(relative=relative), sandbox() as root:
                path = root / relative
                text = path.read_text(encoding="utf-8")
                changed = brand.unwrapped(text)
                self.assertIn(brand.LIVE_SURFACE_DISCLOSURE, changed)
                path.write_text(
                    text.replace("continues to use", "may later use", 1),
                    encoding="utf-8",
                )
                self.refuse(root, "missing the live wordmark and green-point disclosure")

    def test_truthful_identity_denials_are_accepted(self) -> None:
        truthful = (
            "Brand Identity v1.0 is not the adopted identity.",
            "Brand Identity v1.0 is not the current public identity.",
            "These assets do not authorize downstream placement.",
            "The wordmark and one green point are not a permanent identity.",
        )
        for sentence in truthful:
            with self.subTest(sentence=sentence):
                self.assertIsNone(brand.identity_alignment_violation(sentence))

    # -- the manifest's geometry, against the drawing ------------------------
    #
    # `check_geometry` re-solves the manifest's own table. That proves the table
    # is consistent, not that it describes this mark. An earlier candidate could
    # move a token, recompute everything that depends on it, leave every SVG
    # untouched, and pass. These mutations are internally consistent by
    # construction; each must still be refused against the art.

    def _resolved(self, manifest: dict, **overrides) -> dict:
        """A geometry table with a token moved and every dependent value re-solved."""
        geometry = manifest["geometry"]
        geometry.update(overrides)
        field = geometry["field"]
        bar = geometry["bar"]
        seam = geometry["seam"]
        margin = geometry["margin"]
        geometry["top_bar"] = field - 2 * margin - bar - seam
        geometry["stem_height"] = (field + bar) // 2 - margin
        geometry["foot_width"] = (field - seam) // 2 - margin
        geometry["foot_top"] = (field - bar) // 2
        geometry["stroke"] = bar
        return manifest

    def test_a_consistent_manifest_only_bar_mutation_is_refused_against_the_art(self) -> None:
        with sandbox() as root:
            manifest = self._resolved(read_manifest(root), bar=12)
            write_manifest(root, manifest)
            # the table itself is beyond reproach; only the drawing disagrees
            brand.check_geometry(manifest["geometry"])
            self.refuse(root, "the drawn pen is 10 units wide, but geometry.bar declares 12")

    def test_a_consistent_manifest_only_margin_mutation_is_refused_against_the_art(self) -> None:
        with sandbox() as root:
            manifest = self._resolved(read_manifest(root), margin=7)
            write_manifest(root, manifest)
            brand.check_geometry(manifest["geometry"])
            self.refuse(root, "the drawn ink is inset [6] from the field, but geometry.margin declares 7")

    def test_a_consistent_manifest_only_field_mutation_is_refused_against_the_art(self) -> None:
        # The field reaches the art through the half turn: turning form A about
        # a centre the drawing does not have cannot land on form B.
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["geometry"]["half_turn_centre"] = [36, 36]
            manifest = self._resolved(manifest, field=72)
            manifest["geometry"]["cap_height"] = 72
            write_manifest(root, manifest)
            brand.check_geometry(manifest["geometry"])
            self.refuse(root, "not the first turned half a turn")

    def test_a_seam_token_the_drawing_does_not_hold_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["geometry"]["minimum_separation"]["mark"] = 5
            manifest = self._resolved(manifest, seam=5)
            write_manifest(root, manifest)
            brand.check_geometry(manifest["geometry"])
            self.refuse(root, "closest approach")

    def test_a_band_the_mark_stopped_drawing_is_refused(self) -> None:
        # The mutation is on the other side: the drawing moves and the manifest
        # does not. The top bar is shortened by two units in both forms, so the
        # half turn, the pen, the inset and the six-unit approach all survive --
        # and `geometry.top_bar` is now a number nothing draws.
        with sandbox() as root:
            write_pair(root, "deedseal-mark", "M6 6H42V16H6Z", "M6 6H40V16H6Z")
            write_pair(root, "deedseal-mark", "M22 48H58V58H22Z", "M24 48H58V58H24Z")
            self.refuse(root, "geometry.top_bar: declares 36, but the committed mark draws 34")

    def test_a_second_pen_width_in_the_mark_is_refused(self) -> None:
        # Thickened on both sides of the half turn, so the symmetry survives and
        # the figure simply stops being one pen.
        with sandbox() as root:
            write_pair(root, "deedseal-mark", "M6 6H42V16H6Z", "M6 6H42V18H6Z")
            write_pair(root, "deedseal-mark", "M22 48H58V58H22Z", "M22 46H58V58H22Z")
            self.refuse(root, "more than one pen width")

    def test_the_committed_geometry_is_what_the_mark_draws(self) -> None:
        manifest = read_manifest(ROOT)
        geometry = manifest["geometry"]
        mark = brand.Asset(MARK, (ROOT / MARK).read_text(encoding="utf-8"))
        measured = brand.measure_forms(mark, geometry["half_turn_centre"])
        self.assertEqual(measured["bar"], geometry["bar"])
        self.assertEqual(measured["closest_approach"], geometry["seam"])
        self.assertEqual(measured["closest_approach"], 6)
        self.assertEqual(measured["left"], geometry["margin"])
        bands = brand.measure_mark_bands(mark)
        for name, drawn in bands.items():
            self.assertEqual(geometry[name], drawn, name)

    # -- the identity board, read as the claim it is -------------------------
    #
    # The manifest publishes no inverse icon, and an earlier candidate's board
    # painted the icon in inverse ink on a dark panel anyway. Recomputing the
    # board's digest hid it, because nothing read what the board drew.

    def _board_with(self, root: Path, before: str, insertion: str) -> None:
        text = (root / BOARD).read_text(encoding="utf-8")
        self.assertIn(before, text)
        write_asset(root, BOARD, text.replace(before, before + insertion, 1))

    def _icon_figure(self, root: Path, ink: str, x: int, y: int) -> str:
        geometry = re.search(r'd="([^"]+)"', (root / ICON).read_text(encoding="utf-8")).group(1)
        return (
            f'<g transform="translate({x} {y}) scale(1)">'
            f'<path fill="{ink}" fill-rule="nonzero" d="{geometry}"/></g>'
        )

    def test_a_reintroduced_inverse_icon_board_panel_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / BOARD).read_text(encoding="utf-8")
            panel = (
                '<g data-panel="icon-sizes-dark">'
                '<path fill="#141414" d="M800 800H1600V1080H800Z"/>'
                + "".join(
                    self._icon_figure(root, "#FAFAF7", 900 + index * 90, 860)
                    for index in range(3)
                )
                + "</g>"
            )
            # the digest is recomputed, exactly as a careless repair would
            write_asset(root, BOARD, text.replace("</svg>", panel + "</svg>", 1))
            self.refuse(root, "not the reviewed board")

    def test_an_inverse_icon_smuggled_into_an_existing_dark_panel_is_refused(self) -> None:
        with sandbox() as root:
            self._board_with(
                root,
                '<g data-panel="lockup-dark"><path fill="#141414" d="M0 1360H1600V1640H0Z"/>',
                self._icon_figure(root, "#FAFAF7", 1200, 1420),
            )
            self.refuse(root, "paints assets/svg/deedseal-icon.svg in the inverse ink")

    def test_the_icon_on_a_dark_panel_in_its_own_ink_is_refused(self) -> None:
        with sandbox() as root:
            self._board_with(
                root,
                '<g data-panel="mark-sizes-dark"><path fill="#141414" d="M0 800H1600V1080H0Z"/>',
                self._icon_figure(root, "#141414", 1200, 860),
            )
            self.refuse(root, "on the dark surface")

    def test_the_icon_repainted_in_the_inverse_ink_is_refused(self) -> None:
        with sandbox() as root:
            geometry = re.search(
                r'd="([^"]+)"', (root / ICON).read_text(encoding="utf-8")
            ).group(1)
            text = (root / BOARD).read_text(encoding="utf-8")
            changed = text.replace(
                f'<path fill="#141414" fill-rule="nonzero" d="{geometry}"/>',
                f'<path fill="#FAFAF7" fill-rule="nonzero" d="{geometry}"/>',
                1,
            )
            self.assertNotEqual(changed, text)
            write_asset(root, BOARD, changed)
            self.refuse(root, "in the inverse ink")

    def test_a_figure_drawn_before_a_panel_lays_its_surface_is_refused(self) -> None:
        with sandbox() as root:
            self._board_with(
                root,
                '<g data-panel="lockup-dark">',
                self._icon_figure(root, "#FAFAF7", 1200, 1420),
            )
            self.refuse(root, "does not lay its surface down first")

    def test_a_dropped_board_panel_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / BOARD).read_text(encoding="utf-8")
            start = text.index('<g data-panel="palette">')
            write_asset(root, BOARD, text[:start] + text[text.index("</svg>"):])
            self.refuse(root, "not the reviewed board")

    def test_a_reordered_board_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / BOARD).read_text(encoding="utf-8")
            swapped = {
                "mark-sizes-light": "icon-sizes-light",
                "icon-sizes-light": "mark-sizes-light",
            }
            changed = re.sub(
                r'data-panel="(mark-sizes-light|icon-sizes-light)"',
                lambda found: f'data-panel="{swapped[found.group(1)]}"',
                text,
            )
            self.assertNotEqual(changed, text)
            write_asset(root, BOARD, changed)
            self.refuse(root, "not the reviewed board")

    def test_the_committed_board_demonstrates_no_inverse_icon(self) -> None:
        board = brand.Asset(BOARD, (ROOT / BOARD).read_text(encoding="utf-8"))
        manifest = read_manifest(ROOT)
        signature = brand.figure_signature(
            brand.Asset(ICON, (ROOT / ICON).read_text(encoding="utf-8")).geometry
        )
        inverse_surface = manifest["palette"]["roles"]["surface-inverse"]["value"]
        inverse_ink = manifest["palette"]["roles"]["ink-inverse"]["value"]
        names = []
        for name, surface, drawn in brand.board_panels(board):
            names.append(name)
            for fill, data in drawn:
                if brand.figure_signature(data) == signature:
                    self.assertNotEqual(surface, inverse_surface, name)
                    self.assertNotEqual(fill, inverse_ink, name)
        self.assertEqual(tuple(names), brand.REQUIRED_BOARD_PANELS)
        self.assertNotIn("icon-sizes-dark", names)

    def test_no_inverse_icon_asset_was_added(self) -> None:
        self.assertFalse((ROOT / "assets/svg/deedseal-icon-inverse.svg").exists())
        present = sorted(
            path.name for path in (ROOT / "assets/svg").glob("*.svg")
        )
        self.assertEqual(len(present), 8)
        self.assertNotIn("deedseal-icon-inverse.svg", present)

    # -- the non-donor and legal boundaries --------------------------------

    def test_a_restored_retired_generator_is_refused(self) -> None:
        with sandbox() as root:
            (root / "assets/src/build_mark.py").write_text("# retired\n", encoding="utf-8")
            self.refuse(root, "retired generator is still present")

    def test_a_retired_palette_coordinate_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / DOCUMENT).read_text(encoding="utf-8")
            (root / DOCUMENT).write_text(text + "\nA retired value: `#34A873`.\n", encoding="utf-8")
            self.refuse(root, "retired palette coordinate")

    def test_a_retired_type_family_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / ASSETS_README).read_text(encoding="utf-8")
            (root / ASSETS_README).write_text(text + "\nSet in Geist Mono.\n", encoding="utf-8")
            self.refuse(root, "retired type family")

    def test_a_trademark_claim_in_prose_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / DOCUMENT).read_text(encoding="utf-8")
            (root / DOCUMENT).write_text(text + "\nDeedseal is a registered trademark.\n", encoding="utf-8")
            self.refuse(root, "trademark claim")

    def test_a_trademark_symbol_in_prose_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / DOCUMENT).read_text(encoding="utf-8")
            (root / DOCUMENT).write_text(text + "\nDeedseal™ ships soon.\n", encoding="utf-8")
            self.refuse(root, "trademark sign")

    def test_dropping_a_legal_flag_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["legal"]["no_registration_claim"] = False
            write_manifest(root, manifest)
            self.refuse(root, "makes no such claim")

    # -- the manifest's own shape ------------------------------------------

    def test_an_extra_manifest_field_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["mood"] = "confident"
            write_manifest(root, manifest)
            self.refuse(root, "unexpected field set")

    def test_a_wrong_manifest_schema_version_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["schema_version"] = "deedseal.brand-identity-manifest/v2"
            write_manifest(root, manifest)
            self.refuse(root, "wrong manifest schema version")

    def test_a_manifest_that_is_not_json_is_refused(self) -> None:
        with sandbox() as root:
            (root / MANIFEST).write_text("{ not json", encoding="utf-8")
            self.refuse(root, "invalid JSON")

    def test_a_document_that_never_points_at_the_manifest_is_refused(self) -> None:
        with sandbox() as root:
            text = (root / DOCUMENT).read_text(encoding="utf-8")
            (root / DOCUMENT).write_text(text.replace("assets/brand-manifest.v1.json", "the manifest"), encoding="utf-8")
            self.refuse(root, "never points a reader at")

    # -- the downstream pin record -----------------------------------------

    def test_a_pin_with_a_malformed_commit_is_refused(self) -> None:
        manifest = read_manifest(ROOT)
        record = pin_record(manifest)
        record["accepted_merge_commit"] = "not-a-commit"
        self.refuse_pin(record, "accepted_merge_commit")

    def test_a_pin_with_a_wrong_asset_digest_is_refused(self) -> None:
        manifest = read_manifest(ROOT)
        record = pin_record(manifest)
        record["assets"][0]["sha256"] = "1" * 64
        self.refuse_pin(record, "a digest the manifest does not carry")

    def test_a_pin_that_omits_an_asset_is_refused(self) -> None:
        manifest = read_manifest(ROOT)
        record = pin_record(manifest)
        record["assets"] = record["assets"][:-1]
        self.refuse_pin(record, "does not pin every declared asset")

    def test_a_pin_that_omits_a_type_role_is_refused(self) -> None:
        manifest = read_manifest(ROOT)
        record = pin_record(manifest)
        record["typography"] = record["typography"][:-1]
        self.refuse_pin(record, "does not pin every declared type role")

    def test_a_pin_from_another_identity_version_is_refused(self) -> None:
        manifest = read_manifest(ROOT)
        record = pin_record(manifest)
        record["identity_version"] = "9.9"
        self.refuse_pin(record, "does not match the manifest")

    def test_a_pin_with_an_extra_field_is_refused(self) -> None:
        manifest = read_manifest(ROOT)
        record = pin_record(manifest)
        record["vendored_at"] = "today"
        self.refuse_pin(record, "unexpected field set")

    def test_a_pin_naming_a_font_file_the_manifest_does_not_name_is_refused(self) -> None:
        manifest = read_manifest(ROOT)
        record = pin_record(manifest)
        record["typography"][0]["woff2_file"] = "web/Something-Else.woff2"
        self.refuse_pin(record, "pins a file the manifest does not name")

    def test_a_weakened_pin_schema_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            manifest["downstream"]["pin_record_schema"]["field_patterns"]["accepted_merge_commit"] = "^.*$"
            write_manifest(root, manifest)
            self.refuse(root, "must be pinned as a full commit")

    def test_a_pin_schema_missing_a_required_field_is_refused(self) -> None:
        with sandbox() as root:
            manifest = read_manifest(root)
            schema = manifest["downstream"]["pin_record_schema"]
            schema["required_fields"] = [
                name for name in schema["required_fields"] if name != "manifest_sha256"
            ]
            write_manifest(root, manifest)
            self.refuse(root, "must be exactly")


class BrandAssetConstructionTests(unittest.TestCase):
    """The committed SVGs must be exactly what the construction produces."""

    def test_the_committed_assets_match_the_construction(self) -> None:
        sys.path.insert(0, str(ROOT / "assets/src"))
        import build_brand_assets as builder

        documents = builder.asset_documents()
        self.assertEqual(len(documents), 8)
        for name, expected in documents.items():
            observed = (ROOT / "assets/svg" / name).read_text(encoding="utf-8")
            self.assertEqual(observed, expected, f"{name} is not what the construction produces")

    def test_the_construction_is_stable_across_runs(self) -> None:
        sys.path.insert(0, str(ROOT / "assets/src"))
        import build_brand_assets as builder

        self.assertEqual(builder.asset_documents(), builder.asset_documents())

    def test_the_manifest_carries_the_construction_digests(self) -> None:
        sys.path.insert(0, str(ROOT / "assets/src"))
        import build_brand_assets as builder

        documents = builder.asset_documents()
        manifest = read_manifest(ROOT)
        for entry in manifest["assets"]:
            name = entry["path"].rsplit("/", 1)[-1]
            digest = hashlib.sha256(documents[name].encode("utf-8")).hexdigest()
            self.assertEqual(entry["sha256"], digest, f"{name} digest is not the construction's")


if __name__ == "__main__":
    unittest.main(verbosity=2)

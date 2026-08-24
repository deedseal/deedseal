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


@contextmanager
def sandbox():
    """A throwaway copy of the packet, so no test can touch the real tree."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "packet"
        (root / "assets").mkdir(parents=True)
        shutil.copytree(ROOT / "assets/svg", root / "assets/svg")
        for name in (MANIFEST, DOCUMENT, ASSETS_README):
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

    # -- the non-donor and legal boundaries --------------------------------

    def test_a_restored_retired_generator_is_refused(self) -> None:
        with sandbox() as root:
            (root / "assets/src").mkdir(parents=True)
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

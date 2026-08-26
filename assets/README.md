# Brand assets

Deedseal's identity is kept as source. This repository is a text-only public
record -- its validation gate rejects binary files, because bytes that cannot
be read cannot be reviewed for disclosure -- and design follows the same rule as
everything else here: the construction is committed, the image is derived.

The mechanically qualified review candidate and engineering design study is
defined in [BRAND-IDENTITY-v1.0.md](BRAND-IDENTITY-v1.0.md) and bound by digest
in `assets/brand-manifest.v1.json` ([manifest](brand-manifest.v1.json)). It is
not the Owner-selected, adopted, deployed or current public identity, and it
authorizes no downstream placement. Read the document for the idea, geometry,
type system, colour roles, clearspace, minimum-size and accessibility rules,
and the candidate downstream contract. What follows is only where things are
and how to check them.

The public release surface continues to use the existing Deedseal wordmark and
one green point, pending a later Owner brand decision. This repository does not
specify, version or publish an asset for that lockup.

## What is here

| Path | What it is |
| --- | --- |
| [`svg/deedseal-mark.svg`](svg/deedseal-mark.svg) | the mark, light surface |
| [`svg/deedseal-mark-inverse.svg`](svg/deedseal-mark-inverse.svg) | the mark, dark surface |
| [`svg/deedseal-icon.svg`](svg/deedseal-icon.svg) | the small-context icon, 16 px and up |
| [`svg/deedseal-wordmark.svg`](svg/deedseal-wordmark.svg) | the wordmark, light surface |
| [`svg/deedseal-wordmark-inverse.svg`](svg/deedseal-wordmark-inverse.svg) | the wordmark, dark surface |
| `assets/svg/deedseal-lockup.svg` ([file](svg/deedseal-lockup.svg)) | the lockup, light surface |
| [`svg/deedseal-lockup-inverse.svg`](svg/deedseal-lockup-inverse.svg) | the lockup, dark surface |
| [`svg/deedseal-identity-board.svg`](svg/deedseal-identity-board.svg) | the specimen sheet |
| [`brand-manifest.v1.json`](brand-manifest.v1.json) | every digest, token and pin |
| [`src/build_brand_assets.py`](src/build_brand_assets.py) | the construction that produces all eight files |

Every SVG is UTF-8 text with integer coordinates only. None of them references
a script, a style sheet, a font, a link or an external image, so each one
renders from its own bytes and can be reviewed by reading it.

## Checking it

Standard library only, offline, no renderer required:

```
python3 assets/src/build_brand_assets.py --check
python3 tools/check_brand_identity.py
python3 tools/test_brand_identity.py
```

The generator's `--check` proves the committed SVGs are exactly what the
construction produces. The checker proves the files and the manifest agree.
The tests mutate a copy of the tree and prove each mutation is refused.

## Regenerating

```
python3 assets/src/build_brand_assets.py
python3 assets/src/build_brand_assets.py --digests
```

The generator rewrites all eight SVGs; `--digests` prints the SHA-256 of each,
which is what the manifest's `assets` entries carry. Change the construction
and both the assets and those digests change together, or the checker refuses.

Raster derivatives are produced outside this tree, because this record accepts
text only. The manifest pins the renderer, the recipe and the exact dimensions
of every target.

## What used to be here

The generators that produced the previous mark and card were removed in this
change, and none of their properties survive into this identity: not the
geometry, not the palette, not the type pairing, not the slogan. They were a
live observation of what had been published, never a design authority. The
checker enforces the mechanical half of that boundary by refusing any file in
this packet that carries a retired palette coordinate or a retired type family.

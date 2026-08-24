# Deedseal Brand Identity v1.0

The canonical, portable, machine-checkable source for the Deedseal identity.
Everything a landing page, an application client or a repository setting needs
in order to present this product is defined here, generated from one committed
construction, and bound by digest in [the manifest](brand-manifest.v1.json).

This document is a design record. It is not an approval, not a deployment, and
not a legal opinion. It makes no trademark claim of any kind.

## The name

The canonical prose spelling is exactly `Deedseal`: one word, one capital.

`DeedSeal`, `Deed Seal`, `DEEDSEAL` and lowercase `deedseal` are not the
product's name. Lowercase survives in exactly two places, because those are
identifiers rather than prose: repository coordinates such as
`deedseal/deedseal`, and asset file names such as `deedseal-lockup.svg`.

The checker refuses any other spelling in this packet.

## The idea

> Two congruent forms, each the other turned half a turn, meet along one
> stepped seam of constant width and never touch.

Because Deedseal binds one bounded authority recorded before an action to one
matching record produced after it, and keeps the two apart so that the
correspondence between them can be checked rather than assumed.

That is the whole argument, and it is the reason for every decision below.
Turning one form onto the other is what verification is: not a resemblance, an
equality. Holding them apart is what independence is: a passport that had to
touch the run to mean anything would prove nothing about the run. The seam is
the boundary the gate holds while work happens.

### What this identity refuses

A shape that could belong to any other product says nothing about this one. The
following were available and are not used, because none of them has a
construction specific to what Deedseal does: a ring or concentric rings, a
shield, a padlock, a checkmark, a document stamp, a monogram, a robot, a brain,
a network of dots, a sparkle, a chat bubble, a circuit trace, an appliance
silhouette, a passport booklet, and a gradient asked to carry the meaning.

Nothing in this identity is inherited from the assets it replaces. The retired
mark, its palette, its type pairing and its slogan are a live observation of
what used to be published here, not a design authority, and this packet takes
no property from them. The mechanical half of that boundary is enforced: the
retired generators are deleted, and the checker refuses any file in this packet
that carries a retired palette coordinate or a retired type family. The
vocabulary half stays a reviewer's judgement.

## The mark

One square field of 64 units. Form A is a bar across the top, a stem down the
left, and a foot back to the right. Form B is form A rotated 180 degrees about
the centre of the field. The two never intersect, and their closest approach is
the seam.

Every dimension is forced by three numbers, so there is nothing here to take on
trust:

| Token | Units | Forced by |
| --- | --- | --- |
| field | 64 | the square the mark is drawn on |
| bar | 10 | the pen |
| seam | 6 | the gap the two forms hold |
| margin | 6 | equal to the seam, so one value governs both |
| top bar | 36 | `field - 2 x margin - bar - seam` |
| stem height | 31 | `(field + bar) / 2 - margin` |
| foot width | 23 | `(field - seam) / 2 - margin` |
| foot band top | 27 | `(field - bar) / 2`, so the seam is centred |

Change the seam and the whole mark re-solves. The checker recomputes each
forced value and refuses a manifest that declares any of them by hand.

- Source: [`assets/svg/deedseal-mark.svg`](svg/deedseal-mark.svg) and
  [`assets/svg/deedseal-mark-inverse.svg`](svg/deedseal-mark-inverse.svg).
- `viewBox` is `0 0 64 64`, square and numeric.
- Ink coverage is 34 per cent of the field, which is what lets the mark hold at
  an avatar size without a container.
- Minimum size is 32 px. Below that, use the icon.

## The icon

At 16 px the mark's foot and its two 6-unit seams fall below one and a half
device pixels and grey out. The icon exists for exactly that reason, and it is
the only simplification this identity authorises.

[`assets/svg/deedseal-icon.svg`](svg/deedseal-icon.svg) is the mark with the
foot omitted. Every remaining coordinate is the mark's, so the half turn still
reads and the two forms are still congruent. Minimum size is 16 px.

The icon ships in one ink, because the allowlist for this packet carries no
inverse twin for it. That is a bounded rule rather than an oversight, and it is
enforced: every declared raster target that takes the icon renders it onto the
light surface, and the checker refuses a manifest that points a single-ink
source at a dark one. A small dark-surface context takes
[`assets/svg/deedseal-mark-inverse.svg`](svg/deedseal-mark-inverse.svg) at 32 px
or above instead. An inverse icon, if a consumer ever genuinely needs one, is a
change to this packet rather than a file somebody adds downstream.

Nothing else may be simplified. A consumer that needs a different reduction
returns here rather than drawing one.

## The wordmark

`Deedseal` is constructed, not typeset: bars and quarter turns of one pen on
the same 64-unit field as the mark, with cap height equal to the mark's field
and stroke equal to the mark's bar. Every curve in the wordmark is the same pen
turning the same corner.

The consequence matters more than the method. A typeset wordmark is a promise
that some font was installed; a constructed one is geometry, so
[`assets/svg/deedseal-wordmark.svg`](svg/deedseal-wordmark.svg) renders
identically everywhere, needs no font to draw and no font to verify, and can be
checked by reading its coordinates.

- `viewBox` is `0 0 440 64`. The ink fills it exactly: no padding is baked in.
- Cap height 64, x-height 46, stroke 10, baseline at 64.
- Corner radii: 16 at x-height, 22 at cap height, 14 on the `s` spine.
- Visual casing is one capital and seven lowercase letters, always.
- Optical corrections are carried in the sidebearings, which are 8 units beside
  a flat stem and 6 beside a curve, so `D`-`e` closes to 12 and `a`-`l` opens to
  16.
- Minimum size is 120 px wide, which puts the cap height at about 17 px.
- Monochrome is the only mode: one ink, no outline, no shadow, no fill effect.

The manifest declares where each of the eight glyphs sits. The checker uses
those boxes to prove that the letters repeat exactly where the name repeats:
the second, third and sixth glyphs are one letter and must be one geometry, and
no two different letters may share a shape. A wordmark that stopped spelling
the product's name fails that test.

## The lockup

One horizontal lockup, and no other. The mark's ink sits at the origin; the
wordmark begins exactly half a field -- 32 units -- after the mark's ink ends.
The mark's own 6-unit margin supplies the optical inset, so its ink stands at
52 units against a cap height of 64.

- Source: [`assets/svg/deedseal-lockup.svg`](svg/deedseal-lockup.svg) and
  [`assets/svg/deedseal-lockup-inverse.svg`](svg/deedseal-lockup-inverse.svg).
- `viewBox` is `0 0 524 64`, which is mark ink plus gap plus wordmark. The
  checker recomputes that sum.
- The light and dark variants share identical path data. They differ in one
  attribute: the declared ink role.
- The lockup's geometry is the mark's and the wordmark's, translated. The
  checker proves it, so a lockup redrawn by hand fails rather than ships.
- Minimum size is 160 px wide.
- There is no vertical lockup, no stacked lockup, and no slogan. This packet
  authorises no tagline. If one is ever wanted, it is a separate Owner
  decision, not a variant somebody adds downstream.

## Typography

A closed system of three roles. The wordmark is not set in any of them.

| Role | Family | Weight | Use |
| --- | --- | --- | --- |
| display | InterDisplay | 600 | product statement and headline |
| interface | Inter | 400 | interface and body text |
| technical | IBM Plex Mono | 400 | evidence, digests, passports, any byte a reader compares |

Both families are licensed under the SIL Open Font License 1.1, which permits
redistribution. The manifest carries, for each role, the upstream project, the
immutable release, the exact WOFF2 file inside that release, and the SHA-256 of
those bytes:

| Role | Release | File | SHA-256 |
| --- | --- | --- | --- |
| display | `inter-ui` 4.1.1 | `display/InterDisplay-SemiBold.woff2` | `d9f63a82...91e8277a` |
| interface | `inter-ui` 4.1.1 | `web/Inter-Regular.woff2` | `e06f6b1b...1b0ae085` |
| technical | `@ibm/plex-mono` 2.5.0 | `fonts/complete/woff2/IBMPlexMono-Regular.woff2` | `ba204497...7214b350` |

The manifest carries each digest in full. Both releases were fetched from their
publishers' own distribution channels, and the Inter files were additionally
compared byte for byte against the author's own site; the two sources agree.

This record is text only and vendors no font binary. A consumer vendors exactly
the file named above and verifies its digest against the manifest before use.

## Colour

The identity carries no colour of its own.

That is a decision about this product rather than a preference. In Deedseal a
colour is a runtime verdict, and a brand that spent green on decoration would
be spending a signal the product needs to keep truthful. So every asset is one
ink on one surface, and the mark's meaning survives a monochrome fax.

| Role | Value | Use |
| --- | --- | --- |
| ink | `#141414` | assets on a light surface |
| surface | `#FAFAF7` | the light surface |
| ink-inverse | `#FAFAF7` | assets on a dark surface |
| surface-inverse | `#141414` | the dark surface |
| muted | `#5C5C57` | secondary text and diagram rules, light |
| muted-inverse | `#9C9C93` | secondary text and diagram rules, dark |

Six roles, three values in the assets. Contrast, computed rather than claimed:

| Pair | Ratio | Minimum |
| --- | --- | --- |
| ink on surface | 17.62 | 4.5 |
| ink-inverse on surface-inverse | 17.62 | 4.5 |
| muted on surface | 6.43 | 4.5 |
| muted-inverse on surface-inverse | 6.66 | 4.5 |

### Runtime state colours are not brand colours

`GREEN`, `AMBER` and `RED` are declared in the manifest so that every consumer
samples the same values, and they may not appear in any brand asset. The
checker refuses a mark, a wordmark, a lockup, an icon or the identity board
that paints one of them.

| Role | Value | On | Ratio |
| --- | --- | --- | --- |
| state-pass | `#1F6F43` | surface | 5.88 |
| state-pass-inverse | `#5BC98D` | surface-inverse | 8.93 |
| state-hold | `#8A5A00` | surface | 5.67 |
| state-hold-inverse | `#E0A63A` | surface-inverse | 8.50 |
| state-block | `#9B1C1C` | surface | 7.79 |
| state-block-inverse | `#F08A8A` | surface-inverse | 7.64 |

Every one of these is a state readout, never an accent, never a hover, never a
gradient stop, and never the colour of a button that merely happens to be the
primary one.

## Clearspace and minimum sizes

Clearspace is one quarter of the mark field -- 16 units in each asset's own
coordinate space -- on every side of the mark, the icon, the wordmark and the
lockup. Nothing enters that band: no rule, no edge, no other logo, no text.

| Asset | Minimum | Measured |
| --- | --- | --- |
| mark | 32 px | width |
| icon | 16 px | width |
| wordmark | 120 px | width |
| lockup | 160 px | width |
| identity board | 800 px | width |

## Light, dark and monochrome

Each of the mark, the wordmark and the lockup ships as a pair. The pair shares
identical path data and differs only in the declared ink role, which is what
makes "the dark version" a fact rather than a hope: the checker refuses a pair
whose geometry has drifted.

None of the assets carries a background. The consumer supplies the surface,
which is why the same file works on a page, in an application chrome, and in a
one-colour print export. For a monochrome export, use any asset and substitute
the single ink.

## Misuse

None of the following is permitted, on any surface:

- recolouring an asset to anything but a declared ink role;
- painting a runtime verdict colour into an asset;
- adding a background, container, outline, shadow, glow or gradient;
- rotating, shearing, stretching or otherwise changing the aspect;
- redrawing the lockup, or setting the wordmark in an installed font;
- reordering the lockup, or building a vertical or stacked arrangement;
- adding a tagline, a slogan, or a descriptor line;
- placing anything inside the clearspace band;
- setting the mark below 32 px, or the icon below 16 px;
- adding `®` or `™`, which this packet does not authorise.

## Accessibility

- Every asset declares `role="img"` and an accessible name that begins with the
  product's name. An asset embedded as an image supplies its own alternative
  text at the point of use.
- Every declared contrast pair meets 4.5 to 1, computed above.
- No meaning is carried by colour alone: the mark works in one ink, and a
  runtime state is named in text wherever its colour appears.
- No asset animates, so there is no motion to reduce.
- The wordmark needs no font, so it does not disappear when a font fails to
  load or a reader substitutes their own.

## Formats

The SVG sources in [`assets/svg/`](svg/deedseal-mark.svg) are canonical. They
are UTF-8 text, every coordinate is an integer, and none of them references a
script, a style sheet, a font, a link, an external image or any other byte
outside itself.

Raster derivatives are produced outside this tree from those sources, because
this record's publication gate accepts text only. The manifest pins the
renderer, the recipe, and the exact dimensions of each target:

| Target | Source | Size |
| --- | --- | --- |
| favicon | icon | 16x16, 32x32 |
| Apple touch icon | mark | 180x180 |
| PWA icon | mark | 192x192, 512x512 |
| GitHub organisation avatar | mark | 512x512 |
| GitHub repository social preview | lockup | 1280x640 |
| application icon raster | mark | 1024x1024 |
| monochrome print proof | lockup | 2048x250 |

Vector surfaces -- the landing header and footer, the application header and
icon, and monochrome print and export -- take the SVG master directly.

The SVG sources are the canonical bytes. Raster output is reproducible for a
fixed renderer version; byte equality across renderer versions is not claimed.

## The identity board

[`assets/svg/deedseal-identity-board.svg`](svg/deedseal-identity-board.svg) is
one specimen sheet, 1600 by 2400, carrying every asset at every declared size
on both surfaces, the clearspace construction drawn rather than asserted, and
the palette.

It sets no type it cannot draw. The size labels are constructed numerals from
the same pen as the wordmark, which is why the board carries the same guarantee
as the assets it displays. Its panels are named in the file itself, as
`data-panel` attributes: `mark-light`, `mark-dark`, `mark-sizes-light`,
`icon-sizes-light`, `mark-sizes-dark`, `icon-sizes-dark`, `lockup-light`,
`lockup-dark`, `wordmark-light`, `clearspace` and `palette`.

## The manifest and the checks

`assets/brand-manifest.v1.json` is the machine-readable form of everything
above: the identity version, the canonical name, every asset path and digest,
the shared geometry groups, the numeric viewBoxes and size classes, the palette
roles and computed contrast pairs, the type roles with their upstream pins and
expected consumer digests, the raster targets with their renderer and
dimensions, the clearspace and minimum-size tokens, and the downstream pin
schema.

Three commands, all offline, all deterministic:

```
python3 assets/src/build_brand_assets.py --check
python3 tools/check_brand_identity.py
python3 tools/test_brand_identity.py
```

The generator's `--check` proves that the committed SVGs are exactly what the
construction produces. `tools/check_brand_identity.py` proves that the files
and the manifest agree. `tools/test_brand_identity.py` mutates a copy of the
tree the way a hostile reviewer would and proves that each mutation is refused.

The checker fails closed on a missing, extra or renamed asset; a stale digest;
a wrong product-name spelling; a malformed or non-numeric viewBox; a mark or
icon that is not square; a `<text>` element, a script, an event attribute, a
`foreignObject`, an animation, an external URL, a linked image, a remote font,
an absolute local path or an embedded secret; geometry drift between a light
and a dark variant; an asset whose identity version disagrees with the
manifest; an undeclared colour; a runtime verdict colour used as a brand
accent; a missing type role, upstream pin, licence or expected consumer font
digest; an unpinned raster renderer or a wrong derivative dimension; a missing
clearspace or minimum-size rule; and a malformed downstream pin record.

It also checks the identity's own argument: that form B is form A turned half a
turn, that the two forms never intersect, that their closest approach is the
declared seam, that every coordinate is an integer, that the wordmark spells
the product's name by its repeat structure, and that the lockup is its
components rather than a redrawing of them.

## Adopting this identity downstream

This packet defines adoption and performs none of it. No consumer is edited
here.

1. A consumer vendors only the assets and fonts declared in the manifest.
2. A consumer records one local pin file: the source repository, the accepted
   merge commit, the identity version, the manifest path and digest, every
   asset path and digest, and every type role, file and digest.
3. That consumer's continuous integration verifies its local bytes against its
   own pin, offline.
4. The landing, the application client and the GitHub settings surfaces do not
   each invent a variant. A needed variant returns here as a change to this
   manifest.
5. A later convergence check reports exact digest equality or a named mismatch.
   Visual similarity is not evidence.

The pin record's schema is declared in the manifest, and
`python3 tools/check_brand_identity.py --pin <path>` checks one against it.

The named consumers are `deedseal/deedseal-portal`,
`deedseal/deedseal-cockpit-client`, and the GitHub organisation and repository
settings surfaces.

## Authority

- Routing: `deedseal/deedseal-portal#63`.
- Non-visual public-surface authority:
  `docs/product-1/PRODUCT-1-PUBLIC-SURFACE-AUTHORITY-v1.0.md` in
  `deedseal/deedseal-portal`.
- Prohibited legacy donors:
  `docs/product-1/product-1-legacy-exclusions-v1.json` in
  `deedseal/deedseal-portal`.
- The product name `Deedseal` is the Owner's selection recorded in repository
  authority.

The canonical one-sentence public product category is not part of this packet.
A visual rationale is not landing copy, and this document must not be mined for
one.

## Legal boundary

This packet records a design. It makes no claim about trademark searching,
clearance, registrability, ownership, exclusivity or infringement, and it does
not use `®` or `™`. The patent application referenced elsewhere in this
repository establishes no rights in a name or a mark, and nothing here should
be read as suggesting it does. Any legal assessment is a separate evidence
track resting on separate authority. The repository's [NOTICE.md](../NOTICE.md)
governs names and marks, and this packet changes no legal text.

## Known limitations

- The checker verifies that the wordmark's letters repeat where the name
  repeats. It does not read letterforms, so it cannot tell you that the glyph
  declared `s` looks like an `s`. That remains a human judgement, which is what
  the identity board is for.
- The non-donor boundary is enforced mechanically for retired palette
  coordinates, retired type families and the retired generators. The
  vocabulary and motif half of that boundary is a reviewer's judgement.
- The icon has no inverse variant in this version, so it cannot be placed
  directly on a dark surface. The rule above covers that case, and the checker
  enforces it, but a consumer wanting a dark-surface icon at 16 px has no asset
  here and must come back for one.
- Raster byte equality across renderer versions is not claimed.
- Contrast is computed for the declared pairs only. A consumer that places an
  asset on some third surface owes its own measurement.
- Font digests pin the bytes this packet examined. They are not a licence
  audit, and they say nothing about a future release of either family.
- This identity is a candidate. It is not accepted, not adopted, and not
  deployed until the Owner selects and merges it.

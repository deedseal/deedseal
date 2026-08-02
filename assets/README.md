# Brand assets

Deedseal's visual identity, kept as source. This repository is a text-only public record — its validation gate deliberately rejects binary files, because bytes that cannot be read cannot be reviewed for disclosure. Design artifacts follow the same rule as everything else here: the generator is committed; the image is derived. Rendered files are uploaded where they are used (repository social preview, organization avatar, site favicon) and can be reproduced at any time from `src/`.

## The mark

A counterseal: two concentric rings with a single luminous green point at the center. The mark carries no letters, so it survives every size. Below 64 pixels the inner ring is dropped and the point goes solid; the outer ring and the point remain.

## What the mark means

Nothing in the mark is decoration; each element is the product translated into geometry.

- **The dark field is deny-by-default.** By default, nothing is trusted and nothing is permitted; the emptiness is held ground.
- **The rings are the seal.** A deed becomes a fact when it is sealed; a run becomes a fact when it is closed into a signed passport. The thin engraved rings are the instrument — the gate, the broker, the discipline.
- **The green point is the PASS verdict.** The verifier answers exactly PASS or BLOCK. The point is the single colored element in the entire identity, and it carries a single meaning: proven. Never decoration, never emphasis, never "success" in general.
- **The glow is liveness** (the "Signal" treatment). Verification is not an archived note; a passport can be checked right now, offline, by anyone. On light fields the point stays solid — light does not glow on paper.
- **The position is a countersign.** The mark stands after the name at cap height, where a stamp lands next to a signature.

## The lockup

The wordmark `deedseal`, set in Bricolage Grotesque Bold, lowercase, with slight negative tracking, sitting on a hairline exactly as wide as the wordmark-plus-mark group. The mark stands after the name at cap height, like a countersign. The slogan is set in Geist Mono under the line.

## Slogan

> Proof over trust.

One line, fixed. It is the product's thesis: verification does not ask for belief.

## Palette

| Role | Dark field | Light field |
| --- | --- | --- |
| Field | `#0B0F14` | `#F4F6F8` |
| Name | `#F2F5F8` | `#10151B` |
| Muted text | `#8C98A3` | `#6E7883` |
| Hairline | `#171E27` | `#CED4DB` |
| Rings | `#28323E` | `#6E7883` |
| Verified point | `#34A873` | `#1A7F55` |
| Point core (dark field only) | `#60D69C` | — |

The green point is the only color, and it means exactly one thing: proven. Anywhere the identity extends — site, documents, interfaces — this green marks a verified state and nothing else.

## Typography

- Wordmark: [Bricolage Grotesque](https://fonts.google.com/specimen/Bricolage+Grotesque) Bold (OFL).
- Slogan and technical text: [Geist Mono](https://fonts.google.com/specimen/Geist+Mono) Regular (OFL).

Fonts are not vendored here; download them from their upstream repositories.

## Clearspace and sizes

- Clearspace around the lockup and the standalone mark: half the mark's diameter on every side.
- The mark: two rings and a luminous point at 64 px and above; one ring and a solid point below 64 px.
- Do not add letters to the mark, do not recolor the point, do not use the green for anything but a verified state, do not set the wordmark in another face.

## Regenerating

```
python3 src/build_card.py --fonts <dir-with-ttf> --out card-dark.png
python3 src/build_card.py --fonts <dir-with-ttf> --light --out card-light.png
python3 src/build_mark.py --size 500 --out avatar-500.png
python3 src/build_mark.py --size 32 --out favicon-32.png
```

Rendered artifacts are deterministic up to the font rasterizer version. Where each artifact goes:

- `card-dark.png` (1280x640) — repository settings, social preview.
- `avatar-500.png` — organization profile picture.
- `favicon-*.png` — the product site.

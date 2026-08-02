# 0003 — Public text is English-only, enforced by the validation gate

- Status: accepted
- Date: 2026-08-01

## Context

The project operates for an English-speaking market. Mixed-language fragments in public material read as accidental leakage of internal working language and undermine the impression of a controlled publication boundary.

## Decision

All public text in this repository is English. The validation gate treats Cyrillic characters in any public file as a disclosure violation, the same class as an email address or a private path. The banned character range is assembled from code points so the gate file does not itself contain the characters it bans.

## Consequences

- The rule holds mechanically for every future author and every future file, including generated ones.
- Translations, if ever wanted, would be a deliberate new decision with its own maintenance model — not an ad-hoc file.

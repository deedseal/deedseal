# Release and tagging policy

## Status

Adopted for future Deedseal public versions. This policy prepares release mechanics; it does not authorize or perform a tag or GitHub Release.

## Decision

Future public semantic-version tags are annotated and signed by the Owner's designated release key. That release-signing identity is registered: the Owner account holds one Ed25519 SSH signing key whose public fingerprint is `SHA256:5EAseYajdN8AATd6zX3f2EUUnfhrNn1XPpLWyHeohHE`, recorded with its GitHub read-back and its local annotated-tag verification in [Issue #71](https://github.com/deedseal/deedseal/issues/71). That exact fingerprint is the release identity; no other fingerprint stands in for it, and none may be invented or inferred.

Every GitHub Release remains a prerelease with `prerelease: true` until general availability is separately evidenced and Owner-approved. A version number, a closed engineering workstream or a passing check is not evidence of general availability.

A published tag target is immutable. A published tag is never moved or deleted, and its name is never reused. An error in published content is corrected by a new tag and Release, with the earlier Release body pointing forward when useful; the original tag remains at its original object.

`DS-2026.08.2` remains an evidence-snapshot identifier. It is not a semantic version tag and must not be presented as one.

The existing `v0.1.0` tag is historical. It must not be moved, replaced, deleted or retroactively signed. Its current history is evidence of what was published, including limitations in the release practice at that time.

## Release procedure

1. Select an exact source commit already accepted on `main`, and require every release check to bind to that commit.
2. Require a clean worktree at that exact commit and run the complete public-record, Brand Identity, verifier-agreement, offline and release-manifest suites.
3. Generate the release manifest and `SHA256SUMS` twice into separate external directories, prove byte identity and independently recompute every listed digest.
4. Have the Owner verify the release signing identity against the registered public fingerprint `SHA256:5EAseYajdN8AATd6zX3f2EUUnfhrNn1XPpLWyHeohHE` evidenced in [Issue #71](https://github.com/deedseal/deedseal/issues/71). A tag signed by any other key is not a Deedseal release signature.
5. Create an annotated, signed semantic-version tag at the accepted commit. This step is an Owner action and is not delegated to preparation tooling.
6. Create the GitHub Release from that exact immutable tag with `prerelease: true`, exact-SHA proof links, release assets and checksums. Publishing is a separate Owner-authorized action.

The release-manifest tool never creates a tag, signs, calls the network or publishes. Its output is an inventory, not a signature or provenance attestation.

## Corrections

A documentation-only clarification may be made in Release prose if it does not change the meaning of the tagged bytes. Incorrect tagged content is corrected in a new patch version. Unsafe content may cause the Release presentation to be withdrawn while the tag remains immutable, followed by a new correction record and version. No correction path rewrites, moves or deletes a published tag.

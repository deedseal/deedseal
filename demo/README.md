# Demonstration target

This directory is the target of publicly verifiable supervised runs.

**No run has been performed yet.** When one is, an AI coding agent will modify the contract test below under an owner-signed work grant, and the accepted run will close into a run passport published in this repository under `examples/verified/`, together with the offline verifier and a byte-tampered twin of the passport. A reader will then be able to check the passport and resolve the commit it binds without leaving this repository.

The state of that work is tracked in [docs/status.md](../docs/status.md); the decision to publish the verifier is [decision 0006](../docs/decisions/0006-publish-the-verifier-under-apache-2.md). What a passport proves — and what it does not — is in [docs/passport.md](../docs/passport.md).

Nothing here is product source. The contract test exists to give a supervised run something real and bounded to change, and it is not a human contribution surface.

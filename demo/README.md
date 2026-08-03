# Demonstration target

This directory is the target of publicly verifiable supervised runs.

**One run has been performed and published.** An AI coding agent, working under an owner-signed work grant, modified the contract test below in exactly the bounded way the grant authorized: it added one test method, `test_demonstration_marker_is_present`. The accepted run closed into a run passport published at [`examples/verified/run-passport.json`](../examples/verified/run-passport.json), together with the offline verifier ([`tools/verify_run_passport.py`](../tools/verify_run_passport.py)) and a byte-tampered twin of the passport. The commit the passport binds landed in this repository's history through a real merge commit, so a reader can check the passport and resolve the commit it binds without leaving this repository. The walkthrough — commands, expected verdicts, and how to make your own tampered twin — is [docs/verify.md](../docs/verify.md).

The seed shipped one passing test, `test_seed_is_present`; it is still here, unchanged. The contract test exists to give a supervised run something real and bounded to change, and it is not a human contribution surface. Nothing here is product source.

The workstreams that produced this — the public verifier release and the published demonstration — are recorded in [docs/status.md](../docs/status.md); the decision to publish the verifier is [decision 0006](../docs/decisions/0006-publish-the-verifier-under-apache-2.md). What a passport proves — and what it does not — is in [docs/passport.md](../docs/passport.md).

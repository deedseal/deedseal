# Contributing

Questions are welcome as GitHub issues.

Pull requests are accepted for corrections, clarity, and typo fixes only. Feature and design proposals cannot be accepted here: the engineering repositories stay private, and this repository is documentation and a public evidence record. The one product file published here is the offline verifier ([decision 0006](docs/decisions/0006-publish-the-verifier-under-apache-2.md)).

`demo/` is the target of supervised runs, not a human contribution surface. Please do not send changes to it.

Every change runs the public-record validation gate (`tools/test_public_record.py` and `tools/validate_public_record.py`) in CI; a change must keep it green. A correction should identify the exact public statement it fixes and must not introduce private source, identities, or security-sensitive material.

Commit messages follow the repository convention: an imperative subject line of at most 72 characters, a body that explains what changed and why, and no internal identifiers. Significant decisions about this repository are recorded in [docs/decisions/](docs/decisions/README.md).

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), not through an issue or pull request.

This repository operates under the same model as the product: automation and AI tooling may propose changes; only the owner reviews, approves, and merges.

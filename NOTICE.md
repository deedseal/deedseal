# Rights and source availability

Copyright (c) 2026 Deedseal.

## What is licensed here

- Documentation, schemas, and evidence records in this repository are licensed under **CC BY 4.0** (`LICENSE`). Attribute as "Deedseal", with a link to this repository.
- Executable files carry an SPDX identifier declaring their own license. Tooling written for this repository is CC BY 4.0. The offline run-passport verifier, [`tools/verify_run_passport.py`](tools/verify_run_passport.py), is **Apache-2.0** — a code license with an explicit patent grant, per [decision 0006](docs/decisions/0006-publish-the-verifier-under-apache-2.md). It is the only Apache-2.0 file here; everything else follows the split above.

## What is not licensed here

The underlying product source — the private execution layer and the private engineering control plane — is not distributed by this repository, with the single deliberate exception of the offline verifier described above. No license to that private source, its implementation, internal artifacts, names, or marks is granted by publication of this material.

Unless a file explicitly states otherwise, all rights not expressly granted are reserved. Public visibility does not make the underlying product open source.

# Passport conformance suite v1

This directory contains the published passport verifier's passing fixture and
47 refusal cases as language-neutral filesystem inputs. It lets another
implementation demonstrate that it returns the same verdict and process exit
code for every committed case.

Passing means agreement on these inputs only. It does not establish correctness
for inputs outside this suite, and it does not establish that an implementation
is safe to trust. Review the implementation, its trust anchors, and its operating
environment separately.

## Manifest contract

`manifest.json` is one JSON object with exactly these top-level members:

- `schema_version`: `deedseal.passport-conformance/v1`.
- `specification`: `docs/passport-spec-v1.md`.
- `vectors`: a non-empty array of vector objects.

Each vector has `id`, `why`, `input`, `input_kind`, `expect_verdict`, and
`expect_exit_code`. A file refusal also has `expect_reason`. The PASS vector and
the unreadable-path vectors omit `expect_reason`. Vector `input` paths are
relative to the directory containing the manifest.

`input_kind` has a closed set of three values:

- `file` means the path is a committed regular file whose exact bytes are the
  verifier input. This includes zero-byte files; zero bytes are a valid test
  input and are not a suite error. `file` is the default if the field is omitted,
  although every vector in this version states it explicitly.
- `absent` means nothing exists at the path. The runner passes that path unchanged
  and the verifier must refuse it as unreadable. An `absent` vector has no
  committed file **by design**; it is not a broken or incomplete suite.
- `directory` means the input path is a directory. Git retains it through a
  `.gitkeep` file inside. The runner passes the directory path unchanged and the
  verifier must refuse it as unreadable.

An unknown `input_kind` is a suite failure. An implementation passes when every
vector produces the named PASS or BLOCK verdict and exact exit code, plus the
named `block_*` reason when `expect_reason` is present. Nothing more is required
and nothing less is accepted. For `absent` and `directory`, operating systems may
append different error text after the required `passport_unreadable` reason.

Run the reference consumer from the repository root:

```text
python3 tools/check_conformance.py
```

Regenerate the suite only from the corpus definitions:

```text
python3 tools/build_publication.py generate-conformance
```

## Reasons without vectors

Four declared refusal reasons cannot be reached by changing the published
passport bytes: `block_custody_outcome_not_success`,
`block_grant_id_binding_mismatch`,
`block_public_run_passport_contract_malformed`, and
`block_supervised_agent_capture_failed`. Reaching those paths requires a
differently signed owner grant or custody record. The private signing keys are
not available to suite users, so this suite does not fabricate such records.

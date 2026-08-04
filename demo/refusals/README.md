# Refusal corpus

The published verifier declares 39 `block_*` reason strings. This corpus
demonstrates 35 of them by applying named mutations to a temporary copy of
`examples/verified/run-passport.json` and asserting each exact final verdict
line and exit code.

The other four are not demonstrable from the published bytes. Three require a
different owner grant or custody record to pass its signature check before the
verifier can reach the later refusal, which requires the private signing keys:
`block_custody_outcome_not_success`, `block_grant_id_binding_mismatch`, and
`block_public_run_passport_contract_malformed`.
`block_supervised_agent_capture_failed` is a signed custody failure value
declared in the verifier source, but it is not returned as a passport-verifier
verdict.

Run both mechanical checks from the repository root:

```text
python3 demo/refusals/test_refusals.py
python3 tools/survey_refusals.py
```

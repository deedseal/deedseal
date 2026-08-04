# Passport verifier implementations

`go/` contains a second implementation of the run passport verifier, written
in Go from `docs/passport-spec-v1.md` and checked against the same published
conformance vectors as the Python verifier. The trust-anchor bytes, which the
specification intentionally omits, were copied from the Python verifier. Passing
establishes that the remaining specification is complete enough for both
project-built implementations to produce the same verdicts on those inputs; it
does not establish independence, correctness beyond the vector set, or
trustworthiness, because this project writes and maintains both implementations.

Build and run the Go verifier from the repository root:

```text
cd verifiers/go
go build -o verify-run-passport .
./verify-run-passport ../../examples/verified/run-passport.json
```

Run all published vectors with:

```text
verifiers/go/run_conformance.sh
```

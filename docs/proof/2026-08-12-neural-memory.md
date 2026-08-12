# Receipts, not promises — seven facts from one night of live work

On 2026-08-12 a live path inside the private engineering system was exercised
end to end for the read side of a derived graph memory. Seven bounded things
were observed. All seven are published here, each with a sanitized evidence
record, the SHA-256 digest of that record's bytes, and a limitation naming what
the fact does not prove.

Six of the seven are refusals or corrections. That is the shape of the night,
and it is published in that shape rather than summarized into a success.

One of them deserves stating plainly, because it is the least flattering. A live
call showed that the retrieval client was reading the model's answer from a
response field the installed broker does not populate, so an answer that had
already been paid for was thrown away. The focused test suite had been reporting
that client as working — its in-process broker double answered in the same wrong
shape, so the suite agreed with the client instead of checking it. The passing
result was false. Live execution against the real component is what exposed it;
the suite could not have, because the double carried the same defect. Both were
corrected to the shape the installed broker actually returns, and the false
green is preserved in the record rather than replaced by the corrected result.
This is a description of what the code did and what the record shows, not a
claim that any system noticed anything about itself.

## What band these facts sit in

Every claim below is `internally-verified`. That is the weakest band this
project publishes for an engineering result, and it is the correct one here:

- the observations come from a **frozen private source snapshot**, summarized
  into public records — the source is not published;
- a reader of this repository **cannot re-execute** any of them;
- nothing here is `public-reproducible`; it is not independently reviewed, not
  independently certified, and not independently audited;
- none of it is production-ready, none of it is customer-deployed, and no
  accepted candidate output is claimed.

The stronger, publicly reproducible claims in this repository are the passport
demonstrations, the refusal survey, the boundary probe and the conformance
result. Those are unrelated to this page and are unchanged by it. See the
[claim table](../../README.md) for the full set and
[the publication policy](../publication-policy.md) for what each band means.

## What the digests do and do not bind

Each `Record digest` below is the SHA-256 of the public sanitized record's exact
bytes, and it is the same value the [evidence ledger](../../evidence/ledger-v1.json)
indexes for that record. It binds the public record bytes and nothing else. It
does not bind private source truth, it does not make the record immutable — both
files can be changed together — and it is not independent certification.

## The seven facts

### CLM-0014 — refused at the input bound, before any model call

A live controlled request traversed the owner-grant and broker path and was refused at the configured input bound; no completion was accepted.

- Band: `internally-verified`
- Evidence: [`EVD-OFFICE-0002`](../../evidence/records/EVD-OFFICE-0002.json)
- Record digest: `020fae20542b1a6c11b3d10aa50fc96ef064737b5e7501de577086347e47d112`
- Limitation: One controlled request on one day was observed. This does not establish that every oversized input is refused, and a refusal at the input bound says nothing about whether any later stage of the path is correct.

### CLM-0015 — the cell kept digests, not words

A live model-read receipt retained digests rather than the response body in the disposable cell; retaining words required a separate bounded retrieval step into quarantine.

- Band: `internally-verified`
- Evidence: [`EVD-OFFICE-0003`](../../evidence/records/EVD-OFFICE-0003.json)
- Record digest: `fdaad3be1e64bf7ed739a9938bd3f1fd474997792e4d6ceb668cf3374276c4ea`
- Limitation: The receipt is digest-bound rather than signed; it detects drift against the bytes it covers and is not offered as forgery resistance. What the disposable cell retains is not a statement about retention anywhere else.

### CLM-0016 — one byte apart, and refused for it

A one-byte mismatch between grant-covered prompt bytes and transmitted prompt bytes was refused; one normalized byte source now feeds both legs.

- Band: `internally-verified`
- Evidence: [`EVD-OFFICE-0004`](../../evidence/records/EVD-OFFICE-0004.json)
- Record digest: `a12a53fbf9d226c8693e230d8c949b3add6aabd9d0e996431a3645ac51584dfa`
- Limitation: The refusal was correct before the correction — the defect was in the caller, and no boundary was relaxed to admit the request. One shared byte source removes one class of disagreement between the two legs; it is not a proof of end-to-end byte custody.

### CLM-0017 — a passing test that was agreeing, not checking

A live call exposed that the retrieval client and its passing test double read the completion from the wrong response field; both were corrected to the actual broker contract.

- Band: `internally-verified`
- Evidence: [`EVD-OFFICE-0005`](../../evidence/records/EVD-OFFICE-0005.json)
- Record digest: `e51b7361e45934165b3a73e07f048fb3ff2b172b803596e0837ec053e823b6c6`
- Limitation: The suite result recorded before the correction was a false green and is preserved as such. The correction removes one observed disagreement between a test double and the component it stands in for; it does not establish fidelity in any other respect, and it does not establish that live execution will expose the next defect.

### CLM-0018 — the loader enforced a shape the request had only described

Quarantine refused prose when the committed candidate contract required structured JSON; the request was corrected to state the enforced shape.

- Band: `internally-verified`
- Evidence: [`EVD-OFFICE-0006`](../../evidence/records/EVD-OFFICE-0006.json)
- Record digest: `d7b44934a0fac1b320a58b0d13773193cbe8560ac29bccb2258c503d95c78e30`
- Limitation: One refusal of an unstructured answer was observed; this does not establish that every malformed answer is refused. Stating the enforced shape in the request does not guarantee a conforming answer — the loader remains the only thing that decides.

### CLM-0019 — read the envelope, never repair the contents

The retrieval boundary can extract one balanced JSON object without editing its contents and refuses truncated objects or unstructured prose; the focused source-snapshot suite passed 17/17.

- Band: `internally-verified`
- Evidence: [`EVD-OFFICE-0007`](../../evidence/records/EVD-OFFICE-0007.json)
- Record digest: `067d75c40f4ef27b2873ef4e03267507f298a848b5bab26fe3722c57dc453c3d`
- Limitation: The 17/17 result is a recorded internal suite outcome over a frozen private source snapshot; a reader of this repository cannot re-execute it, and it is not presented as publicly reproducible. The suite runs against an in-process double rather than a live model, and extracting one balanced object is a transport behaviour that says nothing about whether the extracted content is true, useful or accepted.

### CLM-0020 — cut off at the output bound, and refused rather than guessed

A structured live answer that exceeded the admitted output bound was refused rather than guessed complete; the request envelope was narrowed to fit the bound. No later successful accepted candidate set is claimed.

- Band: `internally-verified`
- Evidence: [`EVD-OFFICE-0008`](../../evidence/records/EVD-OFFICE-0008.json)
- Record digest: `9d5f22d1617d7d4d504ad8fa4fda88b17ee7a3da256848df9577f4dfee730956`
- Limitation: No accepted candidate set is claimed by this snapshot; the record stops at the refusal and the narrowing that followed it. Refusing a truncated object is a boundary behaviour, not evidence that the retrieval path has produced any accepted result.

## What is deliberately absent

The private source, its coordinates and its file paths; the grants, prompts and
completions; the refusal receipts and exact refusal codes; the exact configured
limits; the host, machine, account and transport identities. Those are withheld
under the redaction classes each record carries, and the records name what they
omit.

One further item from the same night is withheld in full rather than published
in sanitized form, because its operational detail could not be reduced to a
bounded public sentence. It is not counted among the seven.

Sanitized records are summaries. A reader who wants a fact this page does not
carry should treat it as absent rather than assume it.

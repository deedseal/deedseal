# Verify the demonstration

This repository publishes a real run passport, a byte-tampered twin of it, and the offline verifier that renders the verdict. This page walks through checking all of it yourself. Verification needs no account, no network, no running service, and no trust in the machine that produced the passport — only the files in this repository and a standard Python interpreter.

The passport was produced by a supervised run: an AI coding agent, working under an owner-signed work grant, added one test function — `test_demonstration_marker_is_present` — to a single named file, and the accepted run closed into the passport. The run identifier bound in the passport is `deedseal-public-demonstration-v1.0`.

**The run happened in a private engineering repository, and that repository is not published.** This is stated plainly because it changes what you can check: you cannot inspect the run's commit. What you can do is stronger than taking our word for it — the exact bytes of the changed file, before and after, are published here, and the passport's own signed digests are computed over those bytes. Hashing the published file and comparing it to the signed digest is a check you perform, not a claim you accept. The last section shows how.

**Scope of this walkthrough.** This page covers the one run that is publicly checkable end to end: the passport under `examples/verified/`. The repository also records a second controlled run (`CLM-0009`), which published its exact result bytes and a sanitized internal attestation but no passport; the passport verification procedure on this page does not apply to it.

## Three ways to check, easiest first

**1. In the browser — no terminal at all.** Every change to this repository re-runs the whole demonstration in the [Actions tab](https://github.com/deedseal/deedseal/actions): open the latest green run and read the `Re-prove the published demonstration` step — the PASS on the passport, the BLOCK on the twin, and the one-byte difference are in the log, produced on infrastructure we do not operate. To run it under your own account instead of watching ours: fork this repository, enable workflows in your fork, and trigger the same run there. Then try to break it — open `examples/verified/run-passport.json` in the web editor of **your fork**, change any single character, commit, and watch the run turn red with a plain explanation. You have just broken a cryptographic seal from a browser tab.

**2. Hand it to your AI assistant.** If you work with an AI coding agent, paste this and read the output:

> Clone https://github.com/deedseal/deedseal and run `python3 tools/check_demonstration.py` from the repository root. Report the verdict lines verbatim. Then copy `examples/verified/run-passport.json`, change one byte of the copy, run `python3 tools/verify_run_passport.py` on it, and report what happens.

The product this repository documents is controlled execution for AI coding agents — it is fitting that an AI coding agent can check the proof.

**3. Yourself, from a terminal.** Maximum distrust, two commands, standard Python. The rest of this page is that path, in full detail.

## What is published

| File | Role | SHA-256 |
|---|---|---|
| [`examples/verified/run-passport.json`](../examples/verified/run-passport.json) | The real passport | `044ada54…4678` |
| [`examples/verified/run-passport.tampered.json`](../examples/verified/run-passport.tampered.json) | The same bytes with exactly one byte changed | `afdb416d…893e` |
| [`examples/verified/target-before`](../examples/verified/target-before) | The changed file's exact bytes before the run | `11ad307b…82e7` |
| [`examples/verified/target-after`](../examples/verified/target-after) | The changed file's exact bytes after the run | `941793d7…bc71` |
| [`tools/verify_run_passport.py`](../tools/verify_run_passport.py) | The offline verifier — one file, standard library only, Apache-2.0 | `26100954…859c` |

The digests in this table bind the page to the artifact bytes in the same checkout. Because page and artifacts can be changed together, they are a consistency check, not an independent anchor — no verdict below depends on them.

The two target files carry no licence header and no added newline, because a single added byte would change their digests and break the very check they exist for. They are artifact bytes, not source files.

## What you need

- A checkout of this repository — `git clone https://github.com/deedseal/deedseal` — or a downloaded archive. Git is never needed for a verdict.
- Python 3.9 or newer. The verifier uses only the standard library; there is nothing to install.

All commands below run from the repository root. On Windows the interpreter is typically `python` rather than `python3`.

## Verify the real passport

```
python3 tools/verify_run_passport.py examples/verified/run-passport.json
```

Expected output:

```
owner_trust_anchor_key_id: kbp-owner-ed25519-v0.2
custody_trust_anchor_key_id: kbp-service-custody-ed25519-v0.1
RUN_PASSPORT_VERDICT: PASS
```

Exit code `0`. The last stdout line is the verdict; scripts should read the exit code, not the text.

The two trust-anchor lines name the public keys the verdict was rendered against. Both are baked into the verifier source as literals — there are no separate key files, and no flag, environment variable, or field inside the passport can substitute a key. A public key carried inside a record is treated as attacker-controlled data. If you do not want to take the pinned keys on faith, the verifier is one auditable file: read it.

## Verify the tampered twin

`examples/verified/run-passport.tampered.json` is byte-for-byte identical to the real passport except for exactly one changed byte.

```
python3 tools/verify_run_passport.py examples/verified/run-passport.tampered.json
```

The output ends with:

```
RUN_PASSPORT_VERDICT: BLOCK block_owner_authorization_signature_invalid
```

Exit code `1`. The reason code is stable for this file because the changed byte is fixed.

You do not have to trust that the twin really differs by one byte, either. Continuous integration re-proves the whole demonstration on every change to this repository, and so can you, with the same command it runs:

```
python3 tools/check_demonstration.py
```

It requires the passport to PASS with exit code `0`, the twin to BLOCK with exit code `1`, and the twin to differ from the passport at **exactly one byte** — and it prints the offset of that byte. The third check is what makes the second meaningful: a refusal of a wholly rewritten file would prove nothing.

## Make your own tampered twin

Do not take the published twin's word for it. Copy the real passport, change any single byte, and verify the copy:

```
cp examples/verified/run-passport.json my-tampered.json
```

Open `my-tampered.json` in any editor and change one character of any value — one hex digit of a digest, one letter of a path — then:

```
python3 tools/verify_run_passport.py my-tampered.json
```

The verdict is `BLOCK`, exit code `1`. The reason code you get depends on which byte you changed, because the verifier checks in a fixed order and stops at the first broken link: a byte in the grant breaks the grant signature, a byte in the custody record breaks the custody signature, a byte that malforms the JSON is rejected at parse. A passport is a verdict over exactly its bytes; a file that differs in one byte is a different — and here failing — input.

A missing argument exits with code `2` and is not a verdict. An unreadable or nonexistent path is treated fail-closed: the verifier prints `RUN_PASSPORT_VERDICT: BLOCK passport_unreadable` and exits `1`.

The [refusal corpus](../demo/refusals/README.md) shows which declared BLOCK reasons can be reproduced from the published bytes and which require records signed with unavailable private keys.

Implementers of another verifier can run the [language-neutral conformance suite](../examples/verified/conformance/README.md) to compare exact verdicts and exit codes on the published vector set.

For an implementation-level definition of the envelope, canonical bytes,
signature payloads, cross-bindings, verdict protocol, and generated refusal
vocabulary, see [Run passport specification v1](passport-spec-v1.md).

## What a PASS proves

A PASS is a statement about the signed chain over exactly the bytes you verified:

- **The owner grant.** The run was authorized before it happened, by a grant signed with the pinned owner key: pinned repository state, a validity window, the exact allowed file set, the exact task prompt.
- **The custody record.** A service-signed record that authorization existed before any effect, and a service-signed success outcome after it. The custody key is deliberately not the owner's key, and a validly signed failure can never verify as a success.
- **The execution identity.** The identity of the run that produced these effects is bound into the record — this passport is evidence about that run and no other.
- **The committed file hashes.** The complete changed-path set of the resulting commit exactly equals the granted file set, with per-file digests of the committed bytes. A passport cannot present a flattering subset of what happened.
- **The applied kernel boundary.** The write boundary the kernel actually enforced during the run is recorded: which filesystem rights were denied by default, which exact files were re-permitted, and the one non-grant scratch class the agent needs in order to start. It is bound to the digest of the grant it was derived from, so a boundary belonging to some other run cannot be presented with this one.
- **The owner closure.** The owner signed the assembled record as the final act, and the closure cannot launder a summary that disagrees with the signed custody record.

## What a PASS does not prove

- **Not semantic quality.** The passport proves the change was authorized, bounded, observed, and sealed. It does not prove the change is good code. Correctness review remains the owner's job.
- **Nothing about other runs.** One passport is evidence about one run. It says nothing about any run it does not bind, and nothing about general behavior of the system that produced it.
- **Not the contents of a repository you cannot see.** The passport binds a commit in a private repository. It proves what that commit changed, by digest; it does not open the repository, and nothing here asks you to assume anything else about it.

A PASS also does not, by itself, prove the run occurred as described to an independent observer: the signing keys, the verifier, the passport, and the continuous integration are today controlled by the same owner. What it establishes is that the record is internally consistent and tamper-evident against keys pinned in a verifier you can read in full.

A passport that does not verify is treated as no passport at all — deny by default applies to evidence too.

## The flag you will find in the argv, and why it is there

Read the passport and you will find this in `custody.argv`:

```
--dangerously-bypass-approvals-and-sandbox
```

That word deserves an explanation rather than a footnote, so here it is in full.

The agent binary ships its own filesystem sandbox. It is switched off for this run **on purpose**, and what replaced it is stricter, not looser: before the agent process starts, the kernel is given a ruleset built from the owner's signed grant. Ten classes of filesystem write are denied everywhere by default; exactly the files the owner granted are re-permitted, plus one recorded scratch directory the agent needs to exist at all. The ruleset is applied after fork and before exec, it cannot be widened by the process it constrains, and every child process inherits it.

The vendor's own documentation names this arrangement: the option is *"intended solely for … externally sandboxed"* execution. This run is externally sandboxed — by a boundary derived from bytes the owner signed.

Why not run both? Because a nested sandbox needs operational capability of its own — scratch paths, marker files, helper processes — and a boundary derived from a signed file set has no way to authorize capability the owner never granted. Two live runs proved the point: with the nested sandbox in one configuration the agent could not start, and in another its own editing tool aborted and the run completed having changed nothing. Both times the boundary refused the result, correctly. Widening the kernel rules to accommodate a second sandbox would have traded the property this repository claims for a redundant layer.

You do not have to take that on trust either. The argv, the applied ruleset, and the grant the ruleset was derived from are all inside the same signed bytes. Print them together:

```
python3 -c "import json; d=json.load(open('examples/verified/run-passport.json')); b=d['custody']['runner_report']['os_boundary']; print(d['custody']['argv'][7]); print(b['default_for_handled_access'], b['handled_access_fs']); print(b['rules']); print(b['runtime_scratch'])"
```

The flag says the vendor's sandbox is off. The lines beneath it say what the kernel enforced instead — and that record is signed.

## Check the bytes the run produced

This is the part that does not require trusting the private repository at all.

The passport records, under `committed_binding.committed_file_hashes`, a SHA-256 for each path the run was allowed to change — computed over the committed bytes. The published `target-after` file is those exact bytes. So hash it yourself and compare:

Note: the path the passport names, `app/product/demo/test_demonstration_contract.py`, also exists in this repository — but as the target of the *second* controlled run, with different bytes and a different purpose. The bytes the published passport binds are the ones in `examples/verified/target-after`, and nowhere else. Do not hash the repository path expecting a match.

```
python3 -c "import hashlib,sys; print(hashlib.sha256(open('examples/verified/target-after','rb').read()).hexdigest())"
```

Then read the digest the passport signs for that path:

```
python3 -c "import json; d=json.load(open('examples/verified/run-passport.json')); print(d['committed_binding']['committed_file_hashes'])"
```

The two must be equal. If they are, then the file in front of you is, byte for byte, what the signed and verified passport says the run produced — and you established that with a hash function and two files, not with permission to see anything private.

Read the change itself:

```
diff examples/verified/target-before examples/verified/target-after
```

The difference is the addition of `test_demonstration_marker_is_present` and nothing else — the same single-file scope the grant inside the passport allows, which you can read there directly:

```
python3 -c "import json; d=json.load(open('examples/verified/run-passport.json')); print(d['authorization']['allowed_files'], d['authorization']['task_prompt'], sep='\n\n')"
```

The prompt printed there is the exact text the agent was given, signed by the owner before the run. Compare it to the diff.

## Demonstrate the recorded write boundary on your kernel

Run the command below to apply the boundary recorded in the passport to a temporary directory and observe your own kernel permit the recorded file write while refusing file creation, directory creation, symbolic-link creation, and unlink. This probe applies the recorded rules; it does not re-run the supervised run. On a platform without Landlock, it prints a prominent skip explaining that kernel enforcement could not be checked; that skip is not a demonstrated boundary.

```
python3 tools/boundary_probe.py
```

## Limits

- The passport format is not frozen. Field names in the published passport are those of the current draft format; a versioned public specification is a tracked workstream in [status.md](status.md). What a passport binds is described in [passport.md](passport.md).
- This is a demonstration of one supervised run. It is not a release, and the availability status of Deedseal is unchanged by it — see [status.md](status.md).
- The run's own repository is private, so the commit is not independently inspectable. The byte check above is what stands in its place, and it is bounded exactly as described: it proves the published bytes match the signed digests, not that the private repository contains nothing else.
- The trust decision is the pinned keys inside the verifier you run. If someone hands you a passport and a verifier together, read the verifier before trusting its verdict — it is one short file, and that is deliberate.

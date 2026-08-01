# FAQ

**Is Deedseal an agent framework?**

No. Deedseal does not run, prompt, or orchestrate agents. It is the authority layer an agent runs under: what a run may change is decided before it starts, and what it did change is sealed after it ends. Any agent stack can, in principle, sit on top.

**Why not just seccomp, AppArmor, or SELinux?**

Those confine what a process may do while it runs, and they are good at it. Deedseal answers two different questions: was this run authorized, and what exactly did it change — with evidence that survives leaving the host. The two layers compose, and Deedseal's own status page lists kernel-level confinement of the agent as an open objective rather than pretending the kernel layer is already covered.

**Why not a sandbox like gVisor or Firecracker?**

Complementary, not competing. A sandbox contains a workload; it does not tell you whether the workload was authorized or prove afterward what it changed. Deedseal does not sandbox the workload — to run possibly-malicious code, pair it with exactly such a sandbox or a virtual machine.

**How is a run passport different from an audit log?**

An audit log is trusted because of where it sits and who ran the collector; move it, and its authority stays behind. A run passport carries its own verifiability: signatures over the grant, the custody records, and the complete changeset, checkable offline against pinned keys by someone who has never seen the producing machine.

**Why not build on Sigstore or in-toto?**

Honest answer: they solve neighboring problems well. Sigstore signs and transparently logs released artifacts; in-toto attests supply-chain steps. Deedseal binds authorization *before* execution to evidence *after* it, for individual AI-agent runs — the grant pins the exact files and the exact prompt, and the passport must equal that grant. Whether passport formats should converge with those ecosystems later is an open design question, not a settled rivalry.

**Can I use Deedseal today?**

No. Deedseal is in active development, the passport format is not frozen, and there is no public release. The honest state of each workstream is in [status.md](status.md).

**What does a passing verification actually prove?**

That the run was authorized by the owner before it happened, stayed inside the granted file set, produced the exact changeset bound in the passport, and that nothing in the evidence chain was substituted or tampered with afterward. It does not prove the change is semantically correct, and it does not prove the workload was sandboxed.

**What happens when verification fails?**

The verifier answers BLOCK with one reason code, and the passport is treated as no passport at all. Deny by default applies to evidence too: an unverifiable claim of success is a claim, not evidence.

**Who is Deedseal for?**

Teams that want AI coding agents to do real work under authority they can prove — to themselves, to reviewers, to auditors — rather than under authority they assume.

# 0005 — Minimal dependency surface: standard-library tooling, pinned actions

- Status: accepted
- Date: 2026-08-01

## Context

This repository is a publication boundary for a product whose subject is controlled execution. Every dependency in the publication pipeline is attack surface and a trust statement; a supply-chain incident in a linter would be a poor look for a repository about verifiable evidence.

## Decision

The validation tools use the Python standard library only — no packages, no lockfiles, no package manager. Continuous integration uses exactly one external action, pinned to a full commit SHA, with read-only permissions and credential persistence disabled; matrix legs use the runners' preinstalled Python rather than a setup action. Dependabot watches the single pin.

## Consequences

- The whole publication pipeline can be audited by reading two Python files and one workflow file.
- Cross-platform behavior relies on the runners' provided Python versions rather than exact pinned interpreters — an accepted trade against adding a setup action.
- Convenience tooling (link checkers, linters) must be implemented in the gate itself rather than pulled in as dependencies; the gate grows deliberately instead of the dependency list growing silently.

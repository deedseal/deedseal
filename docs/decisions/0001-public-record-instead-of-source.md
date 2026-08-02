# 0001 — Publish a documentation and evidence record, not product source

- Status: accepted
- Date: 2026-08-01

## Context

The Deedseal product is developed in private repositories. A public presence must let investors and engineers evaluate the work without exposing source, internal identities, infrastructure, or unresolved security work. A source mirror was not an option; an empty marketing page would carry no evidence.

## Decision

This repository is a reviewed public projection: narrative documentation plus a machine-validated record of bounded claims and sanitized evidence. No product source is published here, and the repository says so plainly rather than letting readers discover the absence.

## Consequences

- Readers can evaluate discipline and claims, but cannot reproduce internal verification from this repository alone; every claim status says so explicitly.
- The publication boundary needs its own enforcement — which is why the validation gate exists and runs on every change.
- The repository must be judged by documentation-repo standards; source-repo metrics (coverage, build matrices for a product) do not apply here.

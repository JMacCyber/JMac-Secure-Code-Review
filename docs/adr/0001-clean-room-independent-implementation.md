# ADR 0001 — Clean-room, independent implementation

**Status:** Accepted
**Date:** 2026-09-20

## Context

AI code review is a crowded field, and several implementations are open
source. Reading one would be the fastest way to a working tool. It would also
make every later claim about this tool's security properties a claim about
someone else's code, inherited without evidence, under someone else's licence.

## Decision

Every line here is written independently. No third-party source was copied,
adapted, translated or transcribed into this repository.

Existing tools were used as **behavioural** reference only — what such a tool
is expected to do, what its output looks like, what users expect of the
command line. Behaviour, interfaces and ideas are not copyrightable; source
is. The boundary held to is: observe what a tool does, never read how it does
it and then write it down.

Analysis tooling used while designing this was used on this repository and on
its own output. No analysis tool is a runtime component, and none ships here.

## Consequences

- Slower to a first version, and some conventions are re-derived.
- Every security property in `docs/security-requirements.md` is a property of
  code in this repository, verifiable by reading it.
- No inherited licence obligations beyond Apache-2.0 on our own work.
- A design free to be stricter than its peers: deny-by-default egress and
  zero runtime dependencies are both choices that a port of an existing tool
  would have found hard to make.

See `PROVENANCE.md` for the statement of independence that accompanies releases.

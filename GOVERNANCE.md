# Governance

Small, honest, and accurate about its size.

## Now

Maintainer: JMacCyber. Decisions are made in the open on GitHub issues and
pull requests. Anyone may propose anything.

Pre-1.0, changes land by maintainer review. This is stated plainly rather
than dressed up as a committee that does not exist.

## Decisions that need an ADR

A record in `docs/adr/` is required for any change that:

- adds, removes or widens a capability;
- changes a default in a way that widens what the tool may do;
- adds a runtime dependency (see ADR 0004 — this would need to overturn it);
- changes the trust model or the boundary rules;
- changes what leaves the machine.

An ADR states context, decision, and consequences, including the ones we do
not like. Superseded ADRs are marked Superseded and kept. They are not deleted.

## Becoming a maintainer

Sustained, high-quality contribution — code, review, documentation or
security work. Invited by existing maintainers, announced on an issue. There
is no quota and no minimum commit count.

## Releases

Semantic versioning. Pre-1.0, minor versions may change behaviour, and the
changelog says so at the top. Every release carries a changelog entry,
hashes, an SBOM and a provenance statement.

A release that changes a security default is called out in its own section of
the changelog, in plain words, at the top.

## Security

`SECURITY.md` governs vulnerability handling and takes precedence over normal
process. Embargoed fixes may be developed privately and land as a single
commit with the advisory.

## Code of conduct

`CODE_OF_CONDUCT.md` applies everywhere the project is. Enforcement is by the
maintainers.

## Forking

Apache-2.0. Fork it. If you fork it and weaken a default, please rename it —
the name is a claim about the defaults.

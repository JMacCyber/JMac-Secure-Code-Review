# Provenance

## Statement of independence

Every line of source in this repository was written independently for this
project. No source code from any other project was copied, adapted,
translated or transcribed into it.

Other tools in this field were used as **behavioural** reference: what a tool
of this kind is expected to do, what its output looks like, what users expect
of a command line. Behaviour and interfaces are not copyrightable; source is.
The line held to was: observe what a tool does; never read how it does it and
then write it down.

Static analysis tooling was used while designing this, applied to this
repository and to its own output. No such tool is a runtime component, and
none ships here. See [ADR 0001](docs/adr/0001-clean-room-independent-implementation.md).

## Third-party code

**None.** `pyproject.toml` declares `dependencies = []`. The shipped package
imports only the Python standard library. This is verifiable by reading the
imports, and is the subject of [ADR 0004](docs/adr/0004-zero-runtime-dependencies.md).

Optional development extras (`ruff`, `mypy`) are never imported by the
package. External scanners (`semgrep`, `gitleaks`, `trivy`, `osv`) are
separate programs, disabled by default, invoked through the policy layer, and
not distributed here.

## Licence

Apache-2.0 for everything in this repository. `NOTICE` accompanies it.

## Releases

Each release carries:

- **Hashes** — SHA-256 for every artifact, in the release notes.
- **SBOM** — CycloneDX. It is short, because there is nothing in it but this
  package.
- **Signature / attestation** — produced by the release workflow in
  `.github/workflows/release.yml`, which builds from a tagged commit in this
  repository and nowhere else.

Verify a downloaded artifact against the published SHA-256 before installing it.

## Reproducing a build

```
git checkout v<version>
python -m build
```

The build uses `setuptools` from the build environment and nothing from this
repository beyond `pyproject.toml`. There is no build-time code generation
and no network access at build time.

## AI assistance

Parts of this codebase were written with AI assistance, directed and reviewed
by the maintainer. Every security property is implemented in code in this
repository and covered by tests in `tests/`; nothing here rests on an
assurance that cannot be read or run.

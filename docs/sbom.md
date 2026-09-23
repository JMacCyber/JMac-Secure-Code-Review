# Bill of materials

`jscr sbom` writes a CycloneDX 1.5 document describing what a repository
**declares**. It is a reading of the manifests in the tree. It is not a
reading of what an install would produce, and not a reading of what a
running system loads.

That distinction is the whole document. An SBOM whose limits are unstated
invites the reader to treat it as complete, and a reader who believes a
partial inventory is complete is worse off than one who has none.

## Running it

```sh
jscr sbom --output sbom.json
jscr sbom --repo /path/to/project --project my-project --output sbom.json
```

Exit codes follow the rest of the tool: `0` it ran, `2` it could not run.
Finding nothing is not a failure — see [Zero is an answer](#zero-is-an-answer).

## What it reads

Every reader is a manifest parser. None of them resolve, install or fetch.

| File | Ecosystem | What is read |
|---|---|---|
| `package-lock.json` | npm | Every entry under `packages`, at its pinned version |
| `package.json` | npm | `dependencies` and `devDependencies`, at the declared range |
| `requirements.txt` (and `requirements*.txt`) | PyPI | Each requirement line, at the declared specifier |
| `pyproject.toml` | PyPI | `project.dependencies` and optional-dependency groups |
| `go.mod` | Go | The `require` block |
| `Cargo.toml` | crates.io | `dependencies` and `dev-dependencies` |

`package-lock.json` is the **only** lock file read. That is why npm is the
only ecosystem for which the output is a pinned transitive set. Every other
ecosystem yields direct declarations at whatever version the manifest names,
which may be a range rather than a version.

## What each component carries

| Field | Source |
|---|---|
| `name`, `version` | The manifest entry, unchanged |
| `purl` | Built from the ecosystem and name; not resolved against a registry |
| `scope` | `required` or `optional`, from which section declared it |
| `jscr:declared-in` | The manifest file the entry came from |
| `jscr:scope` | The declaring section, spelled out |

Licences appear only when a manifest states one. An absent licence field
means the manifest was silent, not that the component is unlicensed.

## What it does not do

- **No transitive resolution.** Outside `package-lock.json`, a dependency's
  own dependencies are absent. A `requirements.txt` naming one package
  produces one component.
- **No registry lookup.** The engine opens no socket. Nothing is enriched,
  verified, or scored against a vulnerability feed. An SBOM from this tool
  has no vulnerability column, and its absence is not an all-clear.
- **No runtime view.** Scripts a page fetches at load, packages installed
  outside the repository, and anything the build host supplies are all
  outside the boundary.
- **No source inventory.** First-party files are not components. A repository
  with hundreds of its own JavaScript files and one manifest entry has one
  component, and that is correct.

## Zero is an answer

A repository can genuinely declare nothing. Run `jscr sbom` on this
repository and it reads `pyproject.toml`, finds `dependencies = []`, and
returns zero components. It exits `0` and says so on stderr, so a pipeline
can tell "declared nothing" apart from "could not run".

Testing an inventory tool only against a repository that declares nothing
proves nothing. Run it against a target with real manifests before trusting
the output. One such run over a site repository read three manifests and
returned 21 components — 20 npm entries matching all 20 entries in its lock
file, and one PyPI entry — while several hundred first-party source files in
the same tree correctly produced no components at all.

## The document states its own limits

The metadata carries `jscr:resolution`, `jscr:network`, `jscr:manifests` and
a note, so the file remains honest once separated from this page. A reader
who receives only `sbom.json` can still see that no network call was made and
which manifests were read.

## Release artefacts

There is no release yet. When there is, its SBOM will be a different
document, built from the installed environment rather than the manifests, so
it will include the resolved transitive set. `.github/workflows/release.yml`
is set to publish `SHA256SUMS` and `sbom.json` beside the artefacts when a
`v*` tag is pushed. That is requirement SR-31 in
[security requirements](security-requirements.md).

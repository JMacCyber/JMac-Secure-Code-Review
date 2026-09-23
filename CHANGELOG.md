# Changelog

Format follows Keep a Changelog. Versioning is semantic. Pre-1.0, minor
versions may change behaviour.

**Changes to security defaults get their own section, at the top of the
release, in plain words.**

## Unreleased

### Fixed

- `jscr review --commit` on a repository's first commit failed with "bad
  revision", because a first commit has no parent. It now reviews
  everything that commit adds, and the report header names it as a first
  commit instead of a parent range that does not exist. A revision that does
  not exist still fails.

### Added

- `jscr review --all` checks every tracked file at `--head` (default `HEAD`),
  not just a change. It diffs against git's empty tree, so the same engine
  and rules run. Use it to check a repository before you depend on it.
  Uncommitted edits are left out, and it refuses to be combined with
  `--commit`, `--base`, `--staged` or `--worktree`.
- A ground-truth corpus, and a CI job that scores the scanners against it.
  `tests/ground_truth.py` builds 59 files at run time: 52 carry a planted
  defect paired with the rule that must name it, 55 pairs in all, and 7 are
  decoys that must stay quiet. `tools/ground_truth.py` runs the internal scanners over it and
  prints recall, misses and false positives. Nothing vulnerable and no
  credential is committed: every matchable line is assembled from fragments
  at run time. Measured on the first run: 55 of 55, no false positives, with
  the two misses below fixed first.
- Five internal scanners, on by default, none of which starts another
  process: `workflow-permissions`, `manifest`, `iac`, `artefacts`,
  `licences`. Twenty-two new rules in total.
- `jscr sbom` writes a CycloneDX 1.5 document for what the repository
  declares. It states in the document that resolution was declared-only and
  that no registry was contacted, so an empty or thin bill of materials
  cannot be read as a complete one.
- `jscr.supply`: dependency inventory across npm, PyPI, Go and Cargo
  manifests, and SPDX licence classification into seven categories.

### Fixed

- The secret scanner could not see a private key. It read one line at a
  time, and the private-key rule spans many lines, so the most serious rule
  it has never matched a real key block. It now scans the whole file and
  maps the offset back to a line. Found by the ground-truth corpus.
- The unpinned-action rule missed nearly every workflow. It required
  `uses:` at the start of a line, but a step is a list item, so real
  workflows write `- uses:`. Found by the ground-truth corpus.

- Anchoring threw away true findings. It checked a finding against the
  context bundle, which is capped at 40 files and 400,000 bytes, so a
  finding in a file the budget left out was rejected as unverifiable.
  Anchoring now reads the file through the boundary and keeps the bundle's
  copy only as a fallback.
- A file edited while a review was running made the scanner look wrong. The
  scanner quotes the line it matched, so when that quote turns up at a
  different line, the finding is moved to it instead of being rejected.
  Model findings in the same position are still rejected, because a model
  can invent a line number.
- `import jscr.scanners.base` failed with a circular import unless another
  module had been imported first. `jscr.review` now resolves the engine on
  first use, and `jscr.scanners.base` imports `Finding` for typing only.

## 0.1.0 - not yet released

The first version. Not tagged and not published; the version number is the
one in `pyproject.toml`. The security properties are implemented and tested; the rule
set and provider coverage are early.

### Security defaults

Everything ships closed. No network, no execution of repository code, no
tools, metadata-only persistence, no telemetry, no update check. Enabling any
of these is an explicit act and is documented in
[docs/configuration.md](docs/configuration.md).

### Added

- Review pipeline: repository boundary, git diff, bounded context engine,
  redaction, egress guard, provider gateway, anchoring and verification.
- Policy layer: eight capabilities, one decision point, printable with
  `jscr policy`.
- Repository boundary using `realpath` and `commonpath`, symlinks refused by
  default.
- Egress guard: allowlisted hosts and ports; every resolved address
  validated; connection pinned to the validated address with SNI preserved;
  private, loopback, link-local and cloud-metadata ranges refused; redirects
  off.
- Secret detection with block-on-secret by default: a detected secret stops
  the send rather than sanitising it.
- Committed-secret scanner reading the same rules as redaction: a credential
  in the change is reported as a Critical finding
  (`jscr/committed-secret`, CWE-798). The finding never repeats the value;
  it carries a short preview and a fingerprint.
- Deterministic built-in rule set, plus optional external scanners
  (`semgrep`, `gitleaks`, `trivy`, `osv`), each off until enabled and
  reported as not run when absent.
- Prompt injection handling: nonce-delimited content blocks, instructions
  repeated after content, injection markers reported as findings
  (`jscr/prompt-injection-attempt`, CWE-1427), and invisible or
  direction-steering Unicode made visible and reported
  (`jscr/hidden-characters`, CWE-1007).
- Deterministic anchoring: a finding must quote evidence present in the
  material provided, or it is rejected and recorded as rejected.
- Adversarial verification pass in which only an explicit rejection rejects.
- Providers: `null` (default, no network), `anthropic`, `openai_compatible`.
  No fallback chain.
- Reports: text, JSON, SARIF 2.1.0. Every report states what ran and what did
  not.
- Exit codes 0/1/2/3, where 3 means the run was incomplete and must not be
  read as clean.
- CLI: `review`, `init`, `config`, `policy`, `doctor`.
- `tools/egress_audit.py`: AST proof that only one module can reach the
  network. Runs in CI.
- 195 tests, offline, no dependencies, including 51 adversarial tests.
- Documentation: capability map, behaviour, threat model, security
  requirements (SR-1 to SR-31), architecture, data flow, acceptance tests,
  configuration, and four ADRs.

### Known limits

- The built-in rule set is small and conservative.
- Model findings are probabilistic. Anchoring removes fabrications that quote
  nothing real; it cannot make a judgement correct.
- Absence of findings is never evidence of absence of vulnerabilities, and
  the tool never claims otherwise.



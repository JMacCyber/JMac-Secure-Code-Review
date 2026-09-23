# Adversarial Acceptance Tests

The suite is the specification in executable form. It runs offline, with no
installed dependencies, on Python 3.9 or newer:

```
make test
```

885 tests. Counts below are of test methods, taken from the files named.

## Principles

**Every test runs offline.** A test that skips when the machine has no
network is not a control; it is a control that disappears exactly when you
stop watching. DNS is stubbed; the stub is the test's own.

**No credential-shaped literal exists in this repository.** Every fixture
secret is assembled at runtime from fragments in `tests/support.py`. A
scanner pointed at this repository finds nothing, because there is nothing.

**Tests assert refusals, not just successes.** The interesting assertion is
usually "nothing was sent", "the path was refused", "the finding was
rejected with a reason".

## Map

| Module | Tests | What it holds to account |
|---|---|---|
| `tests/adversarial/test_path_escape.py` | 18 | SR-1, SR-2 |
| `tests/adversarial/test_exfiltration.py` | 19 | SR-5, SR-7, SR-8, SR-9, SR-11, SR-12 |
| `tests/adversarial/test_prompt_injection.py` | 14 | SR-20, SR-21 |
| `tests/test_policy.py` | 25 | The capability map, SR-18, SR-24 |
| `tests/test_config.py` | 21 | SR-25 |
| `tests/test_redaction.py` | 19 | SR-11, SR-12 |
| `tests/test_verify.py` | 23 | SR-22, SR-23 |
| `tests/test_engine.py` | 14 | The pipeline end to end |
| `tests/test_diff.py` | 11 | Diff parsing and line-number fidelity |
| `tests/test_report.py` | 13 | SR-27, SR-28 |
| `tests/test_cli.py` | 15 | SR-26 and the exit codes |

## Attacks asserted

**Path escape.** `../` in diff headers; absolute paths; a symlink pointing
out of the tree; a sibling directory whose name shares the root's prefix
(`/repo-evil` against a root of `/repo`, the case that defeats `startswith`);
names that normalise differently than they render; paths through an excluded
directory.

**Exfiltration.** A connection attempted while egress is closed. A host not
in the allowlist. An allowed host that resolves to loopback, to a private
range, and to a cloud metadata address. A name that resolves to several
addresses where only one is bad. A redirect to a new host. A secret present
in the change, asserting `provider.prompts == []` — nothing was sent at all —
and that the error text says so.

**Prompt injection.** Instructions inside a source file, a comment, a commit
message and a Markdown file. Text forging the end of the content block. Text
impersonating the system prompt. Invisible and direction-steering Unicode.
In every case the assertion is the same: the text is reported as a finding,
the real findings still appear, and the instruction has no effect on what
the tool does — because the tool's behaviour was never the model's to choose.

**A hostile model.** A finding citing `/etc/passwd`, a file the model was
never shown: rejected. A finding quoting evidence that appears nowhere:
rejected. Prose instead of JSON: deterministic findings survive, a warning
is recorded. A verifier that rejects everything: findings move to `rejected`
with reasons, never silently.

**Silent degradation.** A provider configured while egress is closed: exit 3,
an explicit error, deterministic findings still reported, and no fallback. An
empty change: reported as empty, not as clean.

## Structural check

```
make egress-audit
```

Parses every module in `src`, `tools` and `tests` and fails if any module
other than `src/jscr/egress/http.py` can reach the network. It is a build
gate, not a report: it runs in CI on every push. Current result: 83 modules
checked, none can reach the network.

## Ground truth

```
make ground-truth
```

Coverage counts lines that ran. This counts defects that were named. The
corpus in `tests/ground_truth.py` is written to a temporary directory at run
time, never committed: 52 files each carrying one planted defect, paired with
the rule that must report it, and 7 decoys that must produce nothing.

A decoy is the half that makes the number mean something. Recall alone can be
bought by reporting everything, so each decoy is code a careless pattern would
confuse with the defect and which is in fact the recommended fix: an argument
list instead of a shell string, `yaml.safe_load`, a parameterised query, an
action pinned to a commit, a placeholder in an example file.

Nothing vulnerable and no credential is committed. Every matchable line is
assembled from fragments at run time, for the same reason the test fixtures
are: a pattern this tool detects must not sit in this tool's own source.

Current result: 55 of 55 planted defects reported, no finding on any decoy.
It is a build gate, not a report. Two false negatives were found by writing
it and fixed before it first passed: the secret scanner read one line at a
time and so could never match a multi-line private key block, and the
unpinned-action rule required `uses:` at the start of a line when a workflow
step is written as `- uses:`.

External scanners are not scored here. Semgrep, Gitleaks and Trivy carry
their own rules, so their recall is theirs to measure.

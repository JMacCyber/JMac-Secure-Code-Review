# Behavioural Specification

What the tool does, in the order it does it, and what each step guarantees.
This is the contract. The tests in `tests/` assert it; `src/jscr/review/engine.py`
implements it.

## The pipeline

A review is eleven steps. Steps 1, 3, 4, 5, 7 and 9 happen whether or not a
model is involved, which is why a run with no model configured is still a
review and not a no-op.

1. **Resolve the repository boundary.** The root is canonicalised with
   `os.path.realpath`. Every later path is admitted only if
   `os.path.commonpath` puts it under that root. Symlinks are refused unless
   `repository.follow_symlinks` is true.
2. **Read the change.** `git diff` for the requested range, staged set or
   single commit. Nothing else in the repository is read yet.
3. **Parse the diff.** Unified diff, preserving old-file and new-file line
   numbers for every hunk, plus file status (new, deleted, renamed).
4. **Build the context bundle.** Deterministic expansion outward from the
   changed lines — imports, tests, schemas — under hard limits
   (`context.max_files`, `context.max_total_bytes`, `context.max_expansion_rounds`).
   The limits are not advisory. When a limit is reached, expansion stops and
   the report says so.
5. **Run deterministic scanners.** The built-in rule set always. External
   scanners only if both installed and enabled in `scanners`. A scanner that
   is enabled but not installed is reported as not run, never as clean.
6. **Inspect for prompt injection.** Text in the change that tries to address
   the reviewer becomes a finding (`jscr/prompt-injection-attempt`, High,
   CWE-1427). It is reported, not obeyed. This is a detector, not the control;
   the control is that the model cannot do anything.
7. **Redact.** The whole assembled prompt is passed through the secret
   detector. With `redaction.block_on_secret` true (the default) a detected
   secret stops the send: nothing goes out. With it false, the value is
   replaced before the send.
8. **Ask the model.** Only if a provider is configured and `net.connect`
   allows the destination. No fallback.
9. **Anchor every finding.** A finding must quote evidence that exists in the
   material the model was given. If the evidence is present but the line
   number is wrong, the line number is corrected. If the evidence is absent,
   the finding is rejected and recorded as rejected.
10. **Verify.** A second pass may reject a finding. Only an explicit rejection
    rejects; silence, prose, a malformed answer or an unreachable verifier
    all leave the finding standing.
11. **Order and report.** Deduplicate, drop anything under
    `review.min_confidence`, sort by severity then location, truncate at
    `review.max_findings`, render.

## Exit codes

The exit code is an interface. CI reads it.

| Code | Meaning |
|---|---|
| 0 | The review completed and nothing at or above `--fail-on` was found |
| 1 | The review completed and findings were reported |
| 2 | The tool could not run: bad configuration, no repository, unreadable input |
| 3 | The review ran but is incomplete: something that was meant to run did not |

Code 3 exists so that a pipeline cannot read "the model was unreachable" as
"no issues found". An error is never reported as a clean review.

## What a clean result means

It means these checks, on this change, found nothing. The text report says so
in those words. It is not a statement about the code, and the tool never
prints one.

## Guarantees

- No outbound connection is attempted while `egress.enabled` is false. This
  is proven structurally: `tools/egress_audit.py` walks every module's AST and
  fails if any module other than `src/jscr/egress/http.py` can reach the network.
- No content leaves the machine without passing the redactor first.
- No process is started that the policy layer did not name.
- No file outside the repository root is read.
- Nothing is written to the repository under review.
- No usage data is sent anywhere, ever. `src/jscr/telemetry.py` is a documented no-op.

## Non-guarantees

Stated plainly, because a security tool that overstates itself is worse than
none:

- Findings from a model are probabilistic. Anchoring and verification remove
  fabrications that quote nothing real; they cannot make a judgement correct.
- The built-in rule set is small and deliberately conservative. It is a floor,
  not a substitute for a dedicated static analyser.
- Absence of a finding is not evidence of absence of a vulnerability.

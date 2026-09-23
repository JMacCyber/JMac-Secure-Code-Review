# Security Requirements

Numbered so they can be cited in review and in tests. Each requirement states
what must hold, where it is implemented, and how it is checked. "Checked by"
names a test or a tool, not an intention.

RFC 2119 keywords are used with their usual meaning.

## Boundary

**SR-1.** The tool MUST resolve the repository root with `os.path.realpath`
before any other path work, and MUST admit a path only if `os.path.commonpath`
places it under that root. Prefix comparison MUST NOT be used.
*Where:* `src/jscr/boundary/fs.py`. *Checked by:* `tests/adversarial/test_path_escape.py`.

**SR-2.** The tool MUST NOT follow symbolic links unless
`repository.follow_symlinks` is true, and MUST refuse a link whose target
resolves outside the root even when it is true.

**SR-3.** The tool MUST NOT write to the repository under review.

**SR-4.** The tool MUST apply `repository.max_file_bytes` and the `context`
limits as hard ceilings, and MUST report when a ceiling was reached.

## Egress

**SR-5.** The tool MUST NOT open any outbound connection while
`egress.enabled` is false.
*Checked by:* `tests/adversarial/test_exfiltration.py`, and structurally by
`tools/egress_audit.py`.

**SR-6.** Exactly one module MAY perform network I/O. Every other module MUST
NOT import a network module. The build MUST fail if this stops being true.
*Where:* `src/jscr/egress/http.py`. *Checked by:* `tools/egress_audit.py` in CI.

**SR-7.** A destination MUST come from configuration. It MUST NOT be derived
from repository content, diff content, model output, or a redirect.

**SR-8.** The guard MUST resolve a hostname once, MUST validate every address
returned, and MUST connect to the validated address it pinned. TLS
verification MUST continue to use the hostname.

**SR-9.** Loopback, private, link-local, multicast, reserved and
cloud-metadata addresses MUST be refused unless
`egress.allow_private_addresses` is true.

**SR-10.** Redirects MUST be refused unless `egress.allow_redirects` is true.

## Data protection

**SR-11.** Every byte assembled for a provider MUST pass the redactor before
the send is attempted.

**SR-12.** When `redaction.block_on_secret` is true, a detected secret MUST
stop the send entirely. The tool MUST report that nothing was sent.

**SR-13.** Persisted state MUST default to metadata only, and MUST stay
inside `persistence.directory`.

**SR-14.** The tool MUST NOT send usage, crash or analytics data anywhere,
under any configuration.

**SR-15.** No credential-shaped literal may exist anywhere in this
repository, including in tests and fixtures. Test credentials MUST be
assembled at runtime from fragments. *Where:* `tests/support.py`.

## Execution

**SR-16.** The tool MUST NOT execute code from the repository under review
unless `execution.allow_repository_code` is true.

**SR-17.** Git MUST be invoked with hooks, system configuration, pagers and
external diff drivers suppressed, and with a minimal environment.
*Where:* `src/jscr/vcs/git.py`.

**SR-18.** A process MAY be started only if the policy layer named it. An
external scanner MUST be governed by its own `scanners.<name>` setting, and
enabling one MUST NOT imply permission to run repository code.

**SR-19.** All subprocesses MUST be invoked without a shell, with an argument
list, and under `scanners.timeout_seconds`.

## Model handling

**SR-20.** Repository content MUST be treated as untrusted data in prompts:
delimited with a per-run nonce, with instructions repeated after the content.

**SR-21.** Model output MUST NOT be executed, and MUST NOT influence any
capability decision, destination or path.

**SR-22.** A finding from a model MUST quote evidence present in the material
the model was given, or be rejected. Rejected findings MUST be recorded with
a reason, not discarded.

**SR-23.** Only an explicit rejection from the verification pass MUST reject
a finding. Silence, prose, malformed output or an unreachable verifier MUST
leave findings standing.

**SR-24.** The tool MUST NOT fall back to another provider, model or
endpoint when the configured one fails.

## Configuration and reporting

**SR-25.** Configuration MUST use a closed schema. An unknown key MUST be an
error, not a warning. *Checked by:* `tests/test_config.py`.

**SR-26.** A run that did not complete MUST exit 3 and MUST NOT be presented
as a clean review. *Checked by:* `tests/test_cli.py`.

**SR-27.** Every report MUST state what ran and what did not, including
scanners that were enabled but absent, and whether a model was used.

**SR-28.** The tool MUST NOT report an absence of findings as a statement
that the code is safe.

## Supply chain

**SR-29.** The tool MUST have zero mandatory runtime dependencies.
*Checked by:* `pyproject.toml`, and by the test suite running with nothing installed.

**SR-30.** The tool MUST NOT check for, download or apply an update to itself.

**SR-31.** Releases MUST carry hashes and an SBOM, and the release workflow
MUST be reproducible from the repository.

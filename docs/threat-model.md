# Threat Model

The asset is the source code and the secrets in and around it. The tool is
pointed at a repository, given a model endpoint, and run inside CI or on a
developer's machine. That places it between the two things an attacker most
wants: the code, and a network connection.

## Trust levels

| Party | Trust |
|---|---|
| The operator running the tool | Trusted. They chose the configuration. |
| The configuration file | Trusted, but validated. Unknown keys are rejected. |
| **The repository under review** | **Untrusted.** Content, filenames, paths, diffs, commit messages, config files inside it. |
| **Model output** | **Untrusted.** Parsed as data; never executed, never used to choose a destination. |
| The model provider | Semi-trusted. It receives what is sent. It cannot reach back in. |
| External scanners | Semi-trusted, explicitly named, explicitly enabled. |

The repository is the input, and inputs are hostile until proven otherwise.
This is the single assumption most review tooling gets wrong.

## Adversaries

**A1 — Malicious repository.** Someone opens a pull request to a project whose
CI runs a review tool. They control every byte the tool reads.

**A2 — Compromised dependency of the tool.** Anything the tool imports at
runtime can do what the tool can do. Answered by having no mandatory runtime
dependencies at all — see [ADR 0004](adr/0004-zero-runtime-dependencies.md).

**A3 — Hostile or compromised model endpoint.** The endpoint returns whatever
it likes, including instructions, including fabricated findings.

**A4 — Network-position attacker.** Between the tool and the provider, or in
control of DNS.

**A5 — The operator's own mistake.** A misconfiguration that quietly widens
what the tool may do.

## Threats and controls

### T1 — Source code exfiltration (A1, A3, A4)

The tool reads private code and can open sockets. That is an exfiltration
primitive if the destination can be influenced.

Controls: `net.connect` denied by default; destinations come only from
`egress.allow_hosts`, never from repository content or model output; one
network module, proven by `tools/egress_audit.py`; every prompt redacted
before sending; `block_on_secret` stops the send rather than sanitising it.

Tests: `tests/adversarial/test_exfiltration.py`.

### T2 — Prompt injection (A1)

Repository content is placed in a prompt. It will contain text addressed to
the reviewer.

Controls, in order of how much they are relied on. The real control is last.

1. Content is delimited with a per-run nonce; instructions are repeated after
   the content, not only before it.
2. Injection markers are reported as findings.
3. Invisible and direction-controlling Unicode is stripped from prompts.
4. **The model has no capabilities.** It cannot read a file, open a socket,
   start a process or call a tool. A successful injection yields text, and
   text is parsed by code that can only produce findings.

Tests: `tests/adversarial/test_prompt_injection.py`.

### T3 — Path escape (A1)

A repository can contain symlinks, `..` sequences, absolute paths in diff
headers, and names that normalise differently than they read.

Controls: `realpath` then `commonpath` — never `startswith`, which accepts
`/repo-evil` for a root of `/repo`. Symlinks refused by default. `repository.exclude`
applied after canonicalisation. Size ceiling per file.

Tests: `tests/adversarial/test_path_escape.py`.

### T4 — SSRF and DNS rebinding (A1, A4)

An allowed hostname can resolve to a loopback address, a private range, or
cloud instance metadata; and can resolve differently on the second lookup.

Controls: resolve once; validate **every** address the name returns, not just
the first; reject loopback, link-local, private, multicast and reserved
ranges unless `egress.allow_private_addresses`; connect to the pinned address
while keeping the hostname as SNI so TLS verification still binds to the name;
redirects off by default.

### T5 — Untrusted code execution (A1)

Build scripts, git hooks, plugin manifests, test suites. Running any of them
runs the attacker's code with the tool's privileges.

Controls: `execution.allow_repository_code` false by default; git invoked
with hooks suppressed; external scanners run only when both installed and
enabled, and the policy layer distinguishes "run a named scanner" from "run
repository code" so that enabling one never implies the other.

### T6 — Fabricated findings (A3)

A hostile endpoint floods the report with plausible findings, or hides a real
one among them.

Controls: anchoring — evidence must exist in the material actually provided;
rejected findings are recorded, with reasons, rather than silently dropped;
`review.max_findings`; deterministic scanners run independently of the model,
so a hostile endpoint cannot suppress them.

### T7 — Silent degradation (A5, A3)

The most dangerous failure is a run that looks clean because something did
not happen.

Controls: exit code 3; the text report opens with what ran **and what did
not**; a scanner that is enabled but absent is reported; no provider fallback;
the word "clean" is never printed without the qualifier.

### T8 — Secret persistence (A5)

Caches and logs outlive the run.

Controls: `persistence.mode` is `metadata_only` by default — findings
metadata and hashes, not file content; nothing is written outside
`persistence.directory`; no credential-shaped literal exists anywhere in this
repository, including in its tests.

## Out of scope

- A compromised host. If the machine running the tool is owned, nothing here helps.
- A malicious operator. Someone who can edit the configuration can open egress.
- The provider's own handling of what it is sent. That is the provider's policy
  and the operator's choice. The tool tells you exactly what it sent and to whom.
- Denial of service against the provider or the host.

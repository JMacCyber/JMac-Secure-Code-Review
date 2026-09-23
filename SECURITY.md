# Security Policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories:
**https://github.com/JMacCyber/JMac-Secure-Code-Review/security/advisories/new**

Please do not open a public issue for a vulnerability first.

Include what you need to make it reproducible: version, configuration, the
steps, and what you expected instead. A proof of concept helps and is not
required.

**Response targets.** Acknowledgement within 3 working days; an initial
assessment within 10 working days; a fix or a stated position before
disclosure. This is a small project — these are the targets it holds itself
to, not a contractual guarantee.

**Disclosure.** Coordinated. We will agree a date with you, credit you unless
you prefer otherwise, and publish an advisory with the fix.

## In scope

Anything that breaks a requirement in
[docs/security-requirements.md](docs/security-requirements.md). In particular:

- Reading or writing outside the repository root (SR-1 to SR-3)
- Any outbound connection while `egress.enabled` is false (SR-5)
- Any path to network I/O other than `src/jscr/egress/http.py` (SR-6)
- A destination influenced by repository content or model output (SR-7)
- SSRF, DNS rebinding, or an unvalidated address (SR-8, SR-9)
- Content reaching a provider without passing the redactor (SR-11, SR-12)
- Execution of repository code without `execution.allow_repository_code` (SR-16)
- **Any prompt injection that causes an action rather than a finding** (SR-21)
- A finding that survives without anchored evidence (SR-22)
- An incomplete run presented as clean (SR-26)
- Secrets in persisted state, logs or reports (SR-13)

## Out of scope

- A missed vulnerability in reviewed code. The tool is a floor, not an oracle,
  and [docs/behaviour.md](docs/behaviour.md) says so.
- A false positive, unless it is fabricated evidence that passed anchoring.
- A prompt injection that changes what the *model says*, without causing an
  action. Injected text being reported as a finding is the tool working.
- A configuration that deliberately widens the tool (`egress.enabled`,
  `execution.allow_repository_code`, `tools.allow`) behaving as documented.
- A compromised host or a malicious operator.
- Denial of service against a provider.
- The provider's own handling of content sent to it.

## Supported versions

The latest release. Pre-1.0, fixes land on the current minor.

## This project's own posture

- Zero mandatory runtime dependencies. The dependency graph is the attack
  surface, so there isn't one ([ADR 0004](docs/adr/0004-zero-runtime-dependencies.md)).
- No credential-shaped literal exists anywhere in this repository, including
  in tests. Fixtures are assembled at runtime (SR-15).
- `tools/egress_audit.py` runs in CI and fails the build if any module other
  than the one network module can reach the network.
- Releases carry hashes, an SBOM and provenance.

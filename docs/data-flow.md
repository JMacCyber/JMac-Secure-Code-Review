# Data Flow and Trust Boundaries

## Boundaries

There are four places where data changes trust level. Everything security
relevant happens at one of them.

**B1 — Filesystem into process.** Crossing requires a canonical path under
the repository root. Content that crosses is untrusted for the rest of its life.

**B2 — Process to subprocess.** Crossing requires a policy decision naming
the program. Arguments are a list; no shell. Git crosses with a minimal
environment and hooks suppressed.

**B3 — Process to network.** Crossing requires `net.connect` allowed, a
configured host and port, a resolution in which every address validates, and
a prompt the redactor has already cleared. One module implements the crossing.

**B4 — Model output into the report.** Crossing requires anchoring: the
evidence must exist in what was actually sent. Output never crosses into a
capability decision, only into findings.

## The path of a review

```
 repository files ──B1──▶ diff ──▶ bundle ──▶ prompt ──▶ redactor
                                                            │
                                    blocked if a secret is found (default)
                                                            │
                                                          ──B3──▶ provider
                                                            │
                                            model text ◀────┘
                                                            │
                                                          ──B4──▶ findings ──▶ report
 repository files ──B1──▶ bundle ──▶ builtin rules ─────────────▶ findings ──┘
 repository files ──B1──▶ bundle ──▶ secret rules ──────────────▶ findings ──┘
 repository files ──B1──▶ manifests, workflows, IaC, artefacts ──▶ findings ──┘
 repository files ──B1──▶ path ──B2──▶ external scanner ────────▶ findings ──┘
```

Note the three lower paths. They do not pass through B3 or B4. That is why a
run with no model still produces a review, and why a hostile provider cannot
suppress deterministic findings.

The supply-chain lane reads manifests, lockfiles, workflow files and
infrastructure files through B1 like any other source file. It resolves no
versions and contacts no registry, so a package that is absent from the public
index is something it reports as unchecked rather than as safe. `jscr sbom`
writes the same inventory as a CycloneDX document and records, in the
document itself, that resolution was declared-only and the network was never
used.

## What leaves the machine

Only this, and only when a network provider is configured and egress is open:

- The system prompt and instruction text, which is in this repository.
- The diff for the requested range.
- The content of files the context engine selected, within the configured budget.
- Findings and evidence for the verification pass.

After redaction. Never:

- Files outside the bundle.
- Environment variables, other than the API key sent as an auth header.
- Paths outside the repository.
- Usage statistics, timings, identifiers or crash reports, under any configuration.

## What stays

With `persistence.mode` at its default of `metadata_only`, the cache holds
findings metadata and content digests, not file content. It stays inside
`persistence.directory`.

## Inspecting it

`jscr review --format json` reports the egress list — every connection the
run made, or an empty list if it made none — along with the policy decisions
that produced it. That is the evidence, and it comes from the same objects
the run used.

# Architecture

## Shape

```
                 ┌──────────────────────────────────────────┐
   CLI  ───────▶ │                 Policy                   │ ◀── Config
                 │  one decision point for every capability │     (closed schema)
                 └───────────────┬──────────────────────────┘
                                 │  every arrow below asks first
   ┌──────────┬──────────┬───────┴────┬───────────┬───────────┐
   ▼          ▼          ▼            ▼           ▼           ▼
 boundary    vcs      scanners    redaction     egress    providers
  (fs.py)  (git,diff)  (builtin,  (secrets)    (guard,   (null, anthropic,
                        external)               http)     openai_compatible)
   │          │          │            │           │           │
   └──────────┴──────────┴─────┬──────┴───────────┴───────────┘
                               ▼
                       review/engine.py
                  (order of operations, findings)
                               │
                               ▼
                  report (text, json, sarif, html)
```

## Modules

| Module | Responsibility | May not |
|---|---|---|
| `config.py` | Load and validate a closed schema | Apply defaults silently for unknown keys |
| `policy.py` | Decide every capability | Ask anything else for permission |
| `boundary/fs.py` | Canonicalise and contain paths | Read outside the root |
| `vcs/git.py` | Invoke git safely | Run hooks or read system config |
| `vcs/diff.py` | Parse unified diff | Touch the filesystem |
| `context/expand.py`, `context/bundle.py` | Choose what to include, under budget | Exceed a limit |
| `scanners/` | Deterministic rules and external tools | Run anything the policy did not name |
| `redaction/secrets.py` | Find and remove secrets | Decide whether to send |
| `egress/guard.py` | Validate a destination | Open a connection |
| `egress/http.py` | The only network I/O in the project | Choose a destination |
| `providers/` | Speak a provider's protocol | Fall back to another provider |
| `review/` | Order of operations, anchoring, verification | Hold a capability |
| `report/` | Render | Omit what did not run |
| `gate.py` | Name the marker, branch and next steps for the commit gate | Run git, render, or decide a capability |

## The commit gate

`gate.py` holds names and text: the stamp, the report path, the tag and
branch names, the count line, the next steps. It calls git only through the
`Git` object the caller hands it, and renders nothing. `cli.py` runs the
review, writes the report and decides the exit code.

The pass at commit time forces three settings off, whatever the repository
config says: `provider.name` to `null`, `provider.allow_cli` to false,
`egress.enabled` to false. The gate must finish in seconds or people turn it
off. `--deep` drops the forcing and runs what the repository allows.

Approval is additive by construction. `save_marker` uses `git stash create`,
which writes a commit object for the index and working tree and prints its
id without touching the tree, the index or the stash list, then tags that id.
`start_branch` cuts a branch from there. No commit, no delete, no rewrite.

## The rule that shapes everything

**The model is never the security boundary. Models may request actions;
deterministic policy decides whether those actions are possible.**

Practically: no module under `review/` or `providers/` can read a file, open
a socket or start a process on its own. They are handed what they are allowed
to have. This is why a successful prompt injection produces a wrong finding
at worst, and never an action.

## Separation of destination from transport

`egress/guard.py` decides where a connection may go and may resolve names. It
cannot connect. `egress/http.py` connects and cannot decide. Neither is
useful alone, and `tools/egress_audit.py` enforces the split by walking the
AST of every module in `src`, `tools` and `tests`: any module other than
`http.py` that imports a network module fails the build, and `guard.py` fails
if it contains a connection call.

## Failure posture

Every failure is closed and loud.

- Unknown configuration key: exit 2. No run.
- Egress denied: no attempt, recorded in the report's policy section.
- Provider unreachable: recorded as an error, deterministic findings still
  reported, exit 3.
- Scanner enabled but not installed: named in the report as not run.
- Secret found with `block_on_secret`: nothing is sent, and the report says
  nothing was sent.

## Why stdlib only

Every runtime dependency is a party that can do anything the tool can do. For
a tool that reads private source code and has a network module, that is the
largest single risk, and it is one the design can simply remove. See
[ADR 0004](adr/0004-zero-runtime-dependencies.md).

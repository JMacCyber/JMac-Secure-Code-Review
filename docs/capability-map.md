# Capability Map

Every capability this tool can hold, what it is for, whether it is on by
default, and the single place that decides it.

A capability is anything the process can do that reaches outside its own
memory: read a file, open a socket, start another program, write to disk.
There are eight. Each one has exactly one name, and every request to use one
goes through `Policy.check(action, subject)` in `src/jscr/policy.py`. There is
no second path.

| Action | What it covers | Default | Governed by |
|---|---|---|---|
| `fs.read` | Reading a file from the repository under review | Allowed inside the repository root only | `repository.root`, `repository.follow_symlinks`, `repository.exclude`, `repository.max_file_bytes` |
| `net.connect` | Opening any outbound connection | **Denied** | `egress.enabled`, `egress.allow_hosts`, `egress.allow_ports`, `egress.allow_private_addresses` |
| `provider.use` | Sending a prompt to a model provider | `null` provider (no network) | `provider.name`, and `net.connect` for any network provider; `egress.enabled` for `claude_cli`, whose child process sends the prompt |
| `exec.run` | Starting another process | **Denied** | `scanners.<name>` for a known scanner; `provider.allow_cli` for the `claude_cli` provider; `execution.allow_repository_code` for anything else |
| `tool.call` | A tool or MCP server the model may invoke | **Denied**, empty allowlist | `tools.allow` |
| `persist.write` | Writing anything to disk between runs | Metadata only | `persistence.mode`, `persistence.directory` |
| `telemetry.send` | Sending usage data anywhere | **Denied**, and not implemented | `telemetry.enabled` |
| `update.check` | Contacting a server to look for a new version | **Denied** | `update.check` |

## What is not a capability

The model is not on this list, because the model is not a capability holder.
It produces text. Text becomes an action only when something deterministic
acts on it, and the only things that act on model output are the finding
parser and the anchoring verifier, neither of which can read a file, open a
socket or start a process. See [ADR 0002](adr/0002-model-is-not-the-security-boundary.md).

## The one capability JSCR hands to something it cannot watch

The `claude_cli` provider answers by starting the operator's `claude`
command, which opens its own connection. That connection is outside
`net.connect`: JSCR did not make it and cannot inspect it, so
`egress.allow_hosts` does not constrain it. Two separate switches are
therefore required, `egress.enabled` and `provider.allow_cli`, and neither
implies the other. The child is started in an empty directory with MCP
servers off and its tools refused, so it cannot read the repository under
review. See [configuration.md](configuration.md#the-claude_cli-provider).

## Reading the live state

The map above is the default. The map for a particular repository and
configuration is printed by:

```
jscr policy --repo /path/to/repo
```

That command asks the same `Policy` object the review uses, so it cannot
drift from behaviour. Each row gives the decision and the reason for it.

## Capabilities deliberately absent

These were considered and are not built. Their absence is a design decision,
not a gap to be filled later without an ADR.

- **Writing to the repository under review.** No autofix, no commits, no
  branch creation. A review tool that can edit the code it is reviewing has
  to be trusted with the code, and nothing here needs that trust.
- **Reading outside the repository root.** Not a global config file in the
  home directory, not an environment-wide ruleset. The one exception is the
  API key, which is read from the environment variable named by
  `provider.api_key_env` and is never read from a file and never written to one.
- **A fallback provider chain.** If the configured provider cannot be used,
  the run reports that and exits 3. It does not quietly try another.
- **Self-update.** The tool never replaces its own code.

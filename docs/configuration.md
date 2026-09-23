# Configuration

One JSON file at the repository root, `jscr.json`. The schema is **closed**:
an unknown key is an error and the run stops. A typo must never silently
become a default. Start one with `jscr init`.

Read the effective value of any key:

```
jscr config egress.enabled
```

Override for a single run (the same validation applies):

```
jscr review --set review.min_confidence=0.8
```

## Defaults

Every default is the closed choice.

```json
{
  "version": 1,
  "repository": {
    "root": ".",
    "follow_symlinks": false,
    "max_file_bytes": 1048576,
    "exclude": [".git", "node_modules", ".venv", "dist", "build"]
  },
  "context": {
    "max_files": 40,
    "max_total_bytes": 400000,
    "max_expansion_rounds": 2,
    "expand_imports": true,
    "expand_tests": true,
    "expand_schemas": true,
    "expand_callers": false
  },
  "redaction": { "enabled": true, "block_on_secret": true, "extra_patterns": [] },
  "egress": {
    "enabled": false,
    "allow_hosts": [],
    "allow_ports": [443],
    "allow_private_addresses": false,
    "allow_redirects": false,
    "timeout_seconds": 30
  },
  "provider": {
    "name": "null",
    "model": "",
    "endpoint": "",
    "api_key_env": "",
    "max_output_tokens": 4096,
    "temperature": 0.0,
    "allow_cli": false,
    "cli_binary": "claude",
    "cli_timeout_seconds": 600
  },
  "scanners": { "workflow-permissions": true, "manifest": true, "iac": true,
                "artefacts": true, "licences": true,
                "semgrep": false, "gitleaks": false, "trivy": false,
                "timeout_seconds": 300 },
  "execution": { "allow_repository_code": false, "allow_repository_hooks": false },
  "tools": { "allow": [] },
  "persistence": { "mode": "metadata_only", "directory": ".jscr-cache" },
  "telemetry": { "enabled": false },
  "update": { "check": false },
  "review": { "verify_findings": true, "min_confidence": 0.6, "max_findings": 200,
              "verify_batch_bytes": 80000, "max_verify_batches": 4 }
}
```

## Scanners

The five internal scanners are on by default. They read files inside the
boundary and start no other process, so switching one off can only lose
findings; it cannot make a run safer. The four external ones are off by
default because each is a separate program, and running one is an execution
decision the policy layer has to permit.

| Key | Reads | Reports |
| --- | ----- | ------- |
| `workflow-permissions` | `.github/workflows/*.yml` | Missing, `write-all` and broad token permissions |
| `manifest` | `package.json`, `.npmrc`, requirements files | Install hooks, dangerous install commands, registry overrides, unscoped internal names |
| `iac` | Terraform, Kubernetes, Compose, CloudFormation | Open ingress, public buckets, privileged containers, mounted runtime sockets |
| `artefacts` | Source files | Packed, obfuscated, hex-escaped and minified content that other rules cannot read |
| `licences` | Manifests and lockfiles | Copyleft obligations that reach your own source, and undeclared licences |

## Keys that change the security posture

Four settings widen what the tool may do. Each is listed with what it opens
and what it costs.

**`egress.enabled`** — turns on the network. Nothing else opens a socket.
With it off, the tool is deterministic scanning only, and that is a complete
and useful mode. Turning it on requires `egress.allow_hosts` as well: enabling
egress without naming a host allows nothing.

**`execution.allow_repository_code`** — lets the tool run code from the
repository under review. On a repository you did not write, this is the
same as running that repository. Enabling a named scanner does **not** need
this and does not imply it.

**`tools.allow`** — names tools or MCP servers the model may invoke. Empty by
default. Every entry is a capability handed to a component that cannot be
trusted with one. Add nothing here you would not add to a shell profile.

**`redaction.block_on_secret`** — true means a detected secret stops the send.
Setting it false means the value is redacted and the send proceeds, which is
strictly more dangerous: redaction is pattern matching, and pattern matching
misses things.

## Hosts

`egress.allow_hosts` accepts exact names and single-label wildcards.
`*.example.com` matches `api.example.com`; it does not match
`a.b.example.com` and it does not match `example.com`. An IP address in the
list is matched as an address. The resolved address is validated regardless
of how the host was matched.

## Providers

| Name | Network | Notes |
|---|---|---|
| `null` | No | The default. Deterministic scanning only. |
| `anthropic` | Yes | Requires `model`, `api_key_env`, and an allowed host. |
| `openai_compatible` | Yes | Requires `endpoint`, `model`, `api_key_env`, and an allowed host. |
| `claude_cli` | Yes, from a child process | Requires `egress.enabled` and `provider.allow_cli`. No API key. |

The API key is read from the environment variable named by
`provider.api_key_env`. It is never read from the configuration file, never
written anywhere, and never appears in a report. An unknown provider name is
an error. There is no fallback chain: if the configured provider cannot be
used, the run says so and exits 3.

## The `claude_cli` provider

This one does not open a socket. It starts the operator's `claude` command
in print mode, writes the prompt to its standard input, and reads the JSON
envelope the CLI prints back. The credential is the sign-in that command
already holds, so no API key is read, stored or passed anywhere.

Two switches must both be on, and neither implies the other:

- **`egress.enabled`** — the operator's statement that prompt content may
  leave the machine. The child process sends it, so the statement is still
  needed.
- **`provider.allow_cli`** — the operator's statement that JSCR may start a
  program to get an answer. Starting a program is `exec.run`, and it gets
  its own switch rather than riding on a scanner's.

What the child is allowed to be:

| Setting | Default | What it decides |
|---|---|---|
| `provider.cli_binary` | `claude` | The command that answers. Found on `PATH`. |
| `provider.model` | empty | Passed as `--model`. Empty means the CLI's own default. |
| `provider.cli_timeout_seconds` | `600` | How long one call may take before the run fails. |

`provider.max_output_tokens` and `provider.temperature` are ignored here,
because the CLI takes neither. The code says so rather than accepting them
and quietly dropping them.

### What the child cannot do

It starts in an empty temporary directory, so it has no repository to find
and no project settings to pick up from the tree under review. MCP servers
are switched off with `--strict-mcp-config`. Its tools are refused by name:
Bash, Read, Write, Edit, NotebookEdit, Glob, Grep, WebFetch, WebSearch and
Task. The prompt already carries the code, so a tool call could only be the
child reading something JSCR did not choose and redaction never saw.

### Two limits, stated rather than hidden

1. **`egress.allow_hosts` is not enforced for this provider.** The egress
   guard inspects connections JSCR makes, and JSCR makes none here. The
   child decides where it goes, and JSCR cannot see or constrain that.
2. **The child inherits the environment JSCR was started with.** The
   external scanners run with a cut-down environment; this provider cannot,
   because a cut-down environment loses the CLI's sign-in — measured, the
   CLI answers "Not logged in · Please run /login". Whatever is exported in
   the operator's shell is visible to the CLI they chose to run.

Everything sent has been through redaction first, exactly as for the
networked providers.

### Getting JSON back rather than prose

The CLI's own system prompt is written for a person at a terminal, and it
survives `--append-system-prompt`. Left in place, it shapes the model
towards conversation: measured, a review that asked for JSON came back as
10,645 characters of prose and zero findings. So JSCR passes the reviewer
prompt with `--system-prompt`, which replaces the CLI's, and passes the
reply shape with `--json-schema`, which the CLI validates before returning.
The shape stops being a request and becomes a constraint.

### Example

```json
{
  "version": 1,
  "egress": { "enabled": true, "allow_hosts": ["api.anthropic.com"] },
  "provider": {
    "name": "claude_cli",
    "model": "claude-opus-5",
    "allow_cli": true
  }
}
```

`allow_hosts` is named here for the operator's own record. It is not
enforced for this provider; see the limits above.

## Example: review with a model, tightly scoped

```json
{
  "version": 1,
  "egress": { "enabled": true, "allow_hosts": ["api.anthropic.com"] },
  "provider": {
    "name": "anthropic",
    "model": "claude-sonnet-5",
    "api_key_env": "ANTHROPIC_API_KEY"
  }
}
```

One host, one port, redaction on, execution off, tools empty. See
`examples/jscr.json`.

"""The jscr command line.

Exit codes are part of the interface, because this runs in CI:

  0  the review ran and found nothing at or above --fail-on
  1  the review ran and found something at or above --fail-on
  2  the review could not run (bad configuration, no repository, denied)
  3  the review ran but a required step failed (provider error, scanner error)

An error is never reported as a clean review. Exit code 3 exists so that a
pipeline cannot read "the model was unreachable" as "no issues found".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from . import gate as gate_mod
from .config import CONFIG_FILENAME, Config, default_config_json
from .errors import JscrError, PolicyDenied
from .policy import Policy
from .report import render_html, render_json, render_sarif, render_text
from .review.engine import ReviewEngine
from .review.findings import Severity
from .scanners.runner import available_scanners
from .vcs.git import Git, GitRange

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_UNUSABLE = 2
EXIT_INCOMPLETE = 3


def main(argv: Optional[List[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_UNUSABLE
    try:
        return args.handler(args)
    except PolicyDenied as exc:
        _err("denied: {0}".format(exc))
        return EXIT_UNUSABLE
    except JscrError as exc:
        _err("error: {0}".format(exc))
        return EXIT_UNUSABLE
    except KeyboardInterrupt:
        _err("interrupted")
        return EXIT_UNUSABLE


# -- commands -----------------------------------------------------------
def cmd_review(args: argparse.Namespace) -> int:
    root = _root(args)
    config = _config(args, root)
    if args.all and (args.commit or args.base or args.staged or args.worktree):
        _err(
            "--all reviews the whole tree; it cannot be combined with "
            "--commit, --base, --staged or --worktree"
        )
        return EXIT_UNUSABLE
    engine = ReviewEngine(config, root)
    target = GitRange.from_args(
        commit=args.commit,
        base=args.base,
        head=args.head,
        staged=args.staged,
        worktree=args.worktree,
        every_file=args.all,
    )
    result = engine.review(target)

    text = _render(result, args)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write("\n")
        _err("written to {0}".format(args.output))
        _log_provenance(args.output, result)
    else:
        sys.stdout.write(text + "\n")

    if result.errors and not args.ignore_errors:
        return EXIT_INCOMPLETE
    floor = Severity.rank(Severity.normalise(args.fail_on))
    for finding in result.findings:
        if Severity.rank(finding.severity) <= floor:
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_gate(args: argparse.Namespace) -> int:
    """The pre-commit gate: scan the staged change, report, stop for a person."""
    root = _root(args)
    config = _config(args, root)
    if not args.deep:
        for key, value in gate_mod.DETERMINISTIC:
            config.override(key, value)
    engine = ReviewEngine(config, root)
    git = engine.git
    if not git.is_repository():
        raise JscrError("not a git repository: {0}".format(root))

    if args.approve:
        mark = args.mark or gate_mod.stamp()
        tag, target, stashed = gate_mod.save_marker(git, mark)
        branch = gate_mod.start_branch(git, mark)
        for line in gate_mod.approval_note(tag, target, branch, stashed):
            sys.stdout.write(line + "\n")
        return EXIT_OK

    result = engine.review(GitRange.from_args(staged=True))

    mark = gate_mod.stamp()
    path = args.output or gate_mod.report_path(root, mark)
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html(result))
        handle.write("\n")
    _log_provenance(path, result)

    out = sys.stdout.write
    out("JSCR gate: {0} pass over the staged change.\n".format("deep" if args.deep else "fast"))
    out(gate_mod.counts_line(result) + "\n")
    if result.errors:
        out("The review did not complete. Read What Ran in the report.\n")
    if not result.findings and not result.errors:
        out("Report: {0}\n".format(path))
        out("Nothing found. This is not proof the change is safe: read what the\n")
        out("report says it did not cover.\n")
        return EXIT_OK
    out("\n")
    for line in gate_mod.next_steps(path, mark, deep_offered=not args.deep):
        out(line + "\n")
    if result.errors and not args.ignore_errors:
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS


def cmd_init(args: argparse.Namespace) -> int:
    root = _root(args)
    path = os.path.join(root, CONFIG_FILENAME)
    if os.path.exists(path) and not args.force:
        _err("{0} already exists; pass --force to overwrite".format(path))
        return EXIT_UNUSABLE
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(default_config_json())
        handle.write("\n")
    sys.stdout.write("wrote {0}\n".format(path))
    sys.stdout.write(
        "Egress is closed and the provider is 'null'. JSCR will run its "
        "deterministic checks and nothing will leave this machine until you "
        "set provider.name, provider.endpoint, egress.enabled and "
        "egress.allow_hosts yourself.\n"
    )
    return EXIT_OK


def cmd_config(args: argparse.Namespace) -> int:
    root = _root(args)
    config = _config(args, root)
    if args.key:
        value = config.get(args.key, _MISSING)
        if value is _MISSING:
            _err("no such setting: {0}".format(args.key))
            return EXIT_UNUSABLE
        sys.stdout.write(json.dumps(value, indent=2) + "\n")
        return EXIT_OK
    sys.stdout.write(json.dumps(config.as_dict(), indent=2) + "\n")
    return EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    """Print what this configuration permits, before anything runs."""
    root = _root(args)
    config = _config(args, root)
    policy = Policy(config)
    rows = policy.explain()
    if args.json:
        sys.stdout.write(json.dumps(rows, indent=2) + "\n")
        return EXIT_OK
    sys.stdout.write("Policy for {0}\n".format(root))
    sys.stdout.write("-" * 72 + "\n")
    for row in rows:
        mark = "allow" if row["allowed"] else "deny "
        sys.stdout.write("  {0}  {1:<18} {2}\n".format(mark, row["action"], row["reason"]))
    return EXIT_OK


def cmd_sbom(args: argparse.Namespace) -> int:
    """Write a CycloneDX document for what this repository declares."""
    from .boundary.fs import boundary_from_config
    from .supply.sbom import build_sbom, render

    root = _root(args)
    config = _config(args, root)
    boundary = boundary_from_config(config, root)
    paths = list(boundary.walk())  # already repository-relative
    document = build_sbom(
        boundary.read_text,
        paths,
        project=args.project or os.path.basename(os.path.abspath(root)),
        version=args.project_version or "",
    )
    text = render(document)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        _err("wrote {0} component(s) to {1}".format(len(document["components"]), args.output))
    else:
        sys.stdout.write(text)
    # An empty document is not a failure: a repository can genuinely declare
    # nothing. It is reported on stderr so a pipeline can see the difference.
    if not document["components"]:
        _err("no dependency manifest found inside the boundary")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    """What is installed, what is configured, what can leave this machine."""
    from . import telemetry

    root = _root(args)
    config = _config(args, root)
    out = sys.stdout.write

    out("jscr {0} on Python {1}\n".format(__version__, sys.version.split()[0]))
    out("repository      {0}\n".format(root))
    out("configuration   {0}\n".format(_config_path(args, root) or "defaults only"))
    out("\n")

    out("Git\n")
    try:
        from .boundary.fs import boundary_from_config

        git = Git(boundary_from_config(config, root))
        out("  {0}\n".format(git.version()))
        out("  repository root confirmed: {0}\n".format(git.is_repository()))
    except JscrError as exc:
        out("  unavailable: {0}\n".format(exc))
    out("\n")

    out("Deterministic scanners\n")
    out("  builtin        available (no install needed)\n")
    for name, installed, enabled in available_scanners(config):
        state = "installed" if installed else "not installed"
        switch = "enabled" if enabled else "disabled in configuration"
        out("  {0:<14} {1}, {2}\n".format(name, state, switch))
    out("\n")

    out("Model provider\n")
    out("  provider.name  {0}\n".format(config.get("provider.name")))
    out("  endpoint       {0}\n".format(config.get("provider.endpoint") or "unset"))
    env = config.get("provider.api_key_env")
    if env:
        out("  key variable   {0} ({1})\n".format(env, "set" if os.environ.get(env) else "NOT set"))
    else:
        out("  key variable   unset\n")
    out("\n")

    out("Network\n")
    out("  egress.enabled {0}\n".format(config.get("egress.enabled")))
    hosts = config.get("egress.allow_hosts") or []
    out("  allowed hosts  {0}\n".format(", ".join(hosts) if hosts else "none"))
    out("  allowed ports  {0}\n".format(config.get("egress.allow_ports")))
    out("  private addrs  {0}\n".format(config.get("egress.allow_private_addresses")))
    out("  redirects      {0}\n".format(config.get("egress.allow_redirects")))
    out("\n")

    out("Telemetry\n")
    out("  {0}\n".format(telemetry.status()["note"]))
    out("\n")

    out("Execution\n")
    out("  repository code {0}\n".format(config.get("execution.allow_repository_code")))
    out("  git hooks       {0}\n".format(config.get("execution.allow_repository_hooks")))
    out("  tools allowed   {0}\n".format(config.get("tools.allow") or "none"))
    return EXIT_OK


# -- plumbing -----------------------------------------------------------
class _Missing(object):
    pass


_MISSING = _Missing()


def _render(result, args: argparse.Namespace) -> str:
    if args.format == "json":
        return render_json(result)
    if args.format == "sarif":
        return render_sarif(result)
    if args.format == "html":
        return render_html(result)
    return render_text(result, verbose=args.verbose)


def _root(args: argparse.Namespace) -> str:
    return os.path.realpath(os.path.abspath(getattr(args, "repo", None) or os.getcwd()))


def _config_path(args: argparse.Namespace, root: str) -> Optional[str]:
    if getattr(args, "config", None):
        return os.path.abspath(args.config)
    candidate = os.path.join(root, CONFIG_FILENAME)
    return candidate if os.path.exists(candidate) else None


def _config(args: argparse.Namespace, root: str) -> Config:
    path = _config_path(args, root)
    config = Config.load(path, root)
    for assignment in getattr(args, "set", None) or []:
        if "=" not in assignment:
            raise JscrError("--set expects key=value, got {0!r}".format(assignment))
        key, _, raw = assignment.partition("=")
        config.override(key.strip(), _value(raw.strip()))
    return config


def _value(raw: str):
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jscr",
        description="JMac Secure Code Review: a security-first AI code review engine.",
        epilog="Nothing leaves your machine unless you configure it to. "
        "Run 'jscr policy' to see what the current configuration permits.",
    )
    parser.add_argument("--version", action="version", version="jscr {0}".format(__version__))
    subparsers = parser.add_subparsers(dest="command")

    def common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--repo", metavar="PATH", help="repository root (default: cwd)")
        sub.add_argument(
            "--config",
            metavar="PATH",
            help="configuration file (default: ./" + CONFIG_FILENAME + ")",
        )
        sub.add_argument(
            "--set",
            action="append",
            metavar="KEY=VALUE",
            help="override one setting for this run; value is parsed as JSON",
        )

    review = subparsers.add_parser("review", help="review a change")
    common(review)
    review.add_argument("--commit", metavar="REV", help="review one commit against its parent")
    review.add_argument("--base", metavar="REV", help="base revision")
    review.add_argument("--head", metavar="REV", help="head revision (default: working tree)")
    review.add_argument("--staged", action="store_true", help="review staged changes")
    review.add_argument("--worktree", action="store_true", help="review unstaged changes")
    review.add_argument(
        "--all",
        action="store_true",
        help="review every tracked file at --head (default HEAD), not a change; "
        "uncommitted edits are not included",
    )
    review.add_argument("--format", choices=("text", "json", "sarif", "html"), default="text")
    review.add_argument("--output", metavar="PATH", help="write the report to a file")
    review.add_argument(
        "--fail-on",
        default="High",
        metavar="SEVERITY",
        help="exit 1 at or above this severity (Critical, High, Medium, Low, Info; default High)",
    )
    review.add_argument(
        "--ignore-errors",
        action="store_true",
        help="exit on findings alone, even if part of the review failed to run",
    )
    review.add_argument("-v", "--verbose", action="store_true", help="show rejected findings too")
    review.set_defaults(handler=cmd_review)

    gate = subparsers.add_parser("gate", help="review the staged change before it is committed")
    common(gate)
    gate.add_argument(
        "--deep",
        action="store_true",
        help="ask the model as well as the rules; slower, and needs egress allowed",
    )
    gate.add_argument(
        "--approve",
        action="store_true",
        help="save the version as a tag and branch for the fix; makes no commit",
    )
    gate.add_argument("--mark", metavar="STAMP", help="name the marker and branch yourself")
    gate.add_argument("--output", metavar="PATH", help="write the report here instead")
    gate.add_argument(
        "--ignore-errors",
        action="store_true",
        help="report findings even if part of the review failed to run",
    )
    gate.set_defaults(handler=cmd_gate)

    init = subparsers.add_parser("init", help="write a default " + CONFIG_FILENAME)
    common(init)
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.set_defaults(handler=cmd_init)

    config_cmd = subparsers.add_parser("config", help="print the effective configuration")
    common(config_cmd)
    config_cmd.add_argument("key", nargs="?", help="a dotted key, e.g. egress.allow_hosts")
    config_cmd.set_defaults(handler=cmd_config)

    policy_cmd = subparsers.add_parser("policy", help="print what this configuration permits")
    common(policy_cmd)
    policy_cmd.add_argument("--json", action="store_true")
    policy_cmd.set_defaults(handler=cmd_policy)

    sbom = subparsers.add_parser("sbom", help="write a CycloneDX bill of materials")
    common(sbom)
    sbom.add_argument("--output", metavar="PATH", help="write to a file instead of stdout")
    sbom.add_argument("--project", metavar="NAME", help="name for the root component")
    sbom.add_argument("--project-version", metavar="VERSION", help="version of the root component")
    sbom.set_defaults(handler=cmd_sbom)

    doctor = subparsers.add_parser("doctor", help="check the environment")
    common(doctor)
    doctor.set_defaults(handler=cmd_doctor)

    return parser


def _log_provenance(output_path: str, result) -> None:
    """Append one line per run to provenance.jsonl beside the report.

    Append-only and one line per run, so the log survives a report being
    overwritten: the report says what the latest run found, the log says
    every run that ever produced one, and which file each wrote. A failure
    to write the log never fails the review — the review already happened.
    """
    record = dict(result.run or {})
    if not record:
        return
    record["report"] = os.path.abspath(output_path)
    record["report_bytes"] = os.path.getsize(output_path) if os.path.exists(output_path) else 0
    path = os.path.join(os.path.dirname(os.path.abspath(output_path)) or ".", "provenance.jsonl")
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:
        _err("provenance log not written to {0}: {1}".format(path, exc))
        return
    _err("provenance appended to {0}".format(path))

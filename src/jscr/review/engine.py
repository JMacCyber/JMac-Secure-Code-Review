"""The review engine.

The order of operations is the security design, so it is written out here
rather than spread across call sites:

1. resolve the repository boundary;
2. read the diff through the constrained git client;
3. build a deterministic, budgeted bundle from inside the boundary;
4. run deterministic scanners;
5. scan the bundle for text addressed at the reviewer, and report it;
6. build the prompt, framing all repository content as data;
7. inspect the assembled prompt for secrets, and redact or refuse;
8. ask the configured provider, through the egress guard;
9. anchor every finding to real lines deterministically;
10. verify adversarially, if a model is configured;
11. merge, sort, filter and report, with the policy audit trail attached.

Steps 1, 3, 4, 5, 7 and 9 happen whether or not a model is involved. With the
null provider, steps 8 and 10 do nothing and the rest still runs.
"""

from __future__ import annotations

import datetime
import os
import platform
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence

from ..boundary.fs import RepositoryBoundary, boundary_from_config
from ..config import Config
from ..context.bundle import Bundle, build_bundle
from ..egress.guard import EgressGuard
from ..errors import JscrError, PolicyDenied, ProviderError, SecretDetected
from ..policy import Policy
from ..providers.base import Completion, Provider
from ..providers.gateway import Gateway
from ..redaction.secrets import Redactor
from ..scanners.runner import run_scanners, scanner_notes, split_results
from ..vcs.diff import FileDiff, parse_unified_diff, summarise
from ..vcs.git import Git, GitRange
from .findings import SOURCE_SCANNER, Finding, Severity, dedupe, sort_findings
from .prompt import (
    REVIEW_SCHEMA,
    SYSTEM_PROMPT,
    VERIFY_SCHEMA,
    VERIFY_SYSTEM_PROMPT,
    PromptBuilder,
    detect_injection,
    hidden_characters,
)
from .verify import apply_anchoring, apply_verdicts, parse_json_object


class ReviewResult(object):
    """Everything one review produced, including what it refused to do."""

    def __init__(self, target: str, root: str) -> None:
        self.target = target
        self.root = root
        self.findings: List[Finding] = []
        self.rejected: List[Finding] = []
        self.scanners: List[Dict[str, Any]] = []
        self.bundle: Optional[Bundle] = None
        self.diffs: List[FileDiff] = []
        self.provider: Dict[str, Any] = {}
        self.usage: Dict[str, Any] = {}
        self.policy: Dict[str, Any] = {}
        self.egress: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.duration_seconds = 0.0
        self.run: Dict[str, Any] = {}
        self.redaction: Dict[str, Any] = {"applied": False, "hits": 0}

    def counts(self) -> Dict[str, int]:
        counts = dict.fromkeys(Severity.ALL, 0)
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def worst_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return sorted(self.findings, key=lambda f: Severity.rank(f.severity))[0].severity

    def as_dict(self) -> Dict[str, Any]:
        return {
            "jscr": {"version": _version(), "target": self.target},
            "run": self.run,
            "summary": {
                "findings": len(self.findings),
                "rejected": len(self.rejected),
                "by_severity": self.counts(),
                "worst": self.worst_severity(),
                "duration_seconds": round(self.duration_seconds, 3),
                "diff": summarise(self.diffs),
            },
            "findings": [f.as_dict() for f in self.findings],
            "rejected": [f.as_dict() for f in self.rejected],
            "scanners": self.scanners,
            "provider": self.provider,
            "usage": self.usage,
            "redaction": self.redaction,
            "policy": self.policy,
            "egress": self.egress,
            "context": self.bundle.as_dict() if self.bundle else {},
            "errors": self.errors,
            "warnings": self.warnings,
        }


class ReviewEngine(object):
    """Runs one review."""

    def __init__(self, config: Config, root: str) -> None:
        self.config = config
        self.policy = Policy(config)
        self.boundary: RepositoryBoundary = boundary_from_config(config, root)
        self.guard = EgressGuard(self.policy)
        self.git = Git(self.boundary)
        self.redactor = Redactor(
            enabled=config.get("redaction.enabled", True),
            block_on_secret=config.get("redaction.block_on_secret", True),
            extra_patterns=config.get("redaction.extra_patterns", ()),
        )

    def review(self, target: GitRange, provider: Optional[Provider] = None) -> ReviewResult:
        started = time.time()
        target = self.git.settle(target)
        result = ReviewResult(target.describe(), self.boundary.root)
        # Provenance is written before any work, so a run that dies half
        # way still says when it started, on what, and with which engine.
        result.run = {
            "run_id": uuid.uuid4().hex,
            "started_at": _utc_now(),
            "finished_at": "",
            "duration_seconds": 0.0,
            "engine": {
                "name": "JMac Secure Code Review",
                "version": _version(),
                "commit": _engine_commit(),
                "python": platform.python_version(),
            },
            "host": {
                "hostname": platform.node(),
                "platform": "{0} {1} {2}".format(
                    platform.system(), platform.release(), platform.machine()
                ),
                "user": os.environ.get("USER", ""),
            },
            "repository": _repository_state(self.git, target, self.boundary.root),
            "context_budget": {
                "max_files": self.config.get("context.max_files", 40),
                "max_total_bytes": self.config.get("context.max_total_bytes", 400000),
                "max_diff_bytes": self.config.get("context.max_diff_bytes", 400000),
            },
        }

        # 2. the diff
        diff_text = self.git.diff(target)
        diffs = parse_unified_diff(diff_text)
        # A configured exclusion has to hold on every route a path takes into a
        # review. The walk applies it; the diff did not, so an excluded
        # directory was still scanned whenever a base revision was given.
        inside = [d for d in diffs if not self.boundary.excluded(d.path)]
        if len(inside) != len(diffs):
            result.warnings.append(
                "excluded {0} changed files by repository.exclude".format(len(diffs) - len(inside))
            )
        diffs = inside
        result.diffs = diffs
        if not diffs:
            result.warnings.append("no changes to review for {0}".format(target.describe()))
            result.duration_seconds = time.time() - started
            result.policy = self.policy.summary()
            _close_run(result)
            return result

        # 3. the bundle
        bundle = build_bundle(
            self.boundary,
            diffs,
            target=target.describe(),
            max_files=self.config.get("context.max_files", 40),
            max_total_bytes=self.config.get("context.max_total_bytes", 400000),
            expand_imports=self.config.get("context.expand_imports", True),
            expand_tests=self.config.get("context.expand_tests", True),
            expand_schemas=self.config.get("context.expand_schemas", True),
            expand_callers=self.config.get("context.expand_callers", False),
        )
        result.bundle = bundle
        for refusal in bundle.refusals:
            result.warnings.append("refused {0}: {1}".format(refusal["path"], refusal["reason"]))

        # 4. deterministic scanners
        scanner_results = run_scanners(
            self.policy, self.boundary, [d.path for d in diffs if not d.is_binary]
        )
        scanner_findings, scanner_rows = split_results(scanner_results)
        result.scanners = scanner_rows
        candidates: List[Finding] = list(scanner_findings)

        # 5. text addressed at the reviewer
        for path, line, excerpt in detect_injection(bundle):
            candidates.append(
                Finding(
                    path=path,
                    line=line,
                    title="Text in this change addresses an automated reviewer",
                    detail=(
                        "This line reads as an instruction to a code review tool "
                        "rather than as code or documentation. It may be an attempt "
                        "to influence automated review. JSCR treated it as data and "
                        "reviewed the change normally."
                    ),
                    severity=Severity.HIGH,
                    evidence=excerpt,
                    recommendation="Remove the text, or confirm with the author why it is there.",
                    rule_id="jscr/prompt-injection-attempt",
                    cwe="CWE-1427",
                    confidence=0.8,
                    source=SOURCE_SCANNER,
                )
            )

        for path, line, names, text in hidden_characters(bundle):
            candidates.append(
                Finding(
                    path=path,
                    line=line,
                    title="Invisible characters in this change",
                    detail=(
                        "This line contains characters that are not visible when the "
                        "file is read by a person but are read normally by a model or "
                        "a compiler. That gap can be used to hide instructions or to "
                        "make code read differently than it runs. JSCR made them "
                        "visible before review; it did not remove them from the file. "
                        "Code points present on this line: {0}.".format(names)
                    ),
                    severity=Severity.HIGH,
                    evidence=text,
                    recommendation=(
                        "Remove the characters, or confirm with the author why the file needs them."
                    ),
                    rule_id="jscr/hidden-characters",
                    cwe="CWE-1007",
                    confidence=0.9,
                    source=SOURCE_SCANNER,
                )
            )

        # 6-8. the model pass
        #
        # A caller-supplied provider is always asked. Otherwise the null
        # provider is not asked at all: it answers nothing, so building and
        # inspecting a prompt for it would spend the work and, worse, could
        # report a pre-egress secret block on a run where nothing was ever
        # going to be sent. "AI review not run" is already in the report.
        asked = provider is not None
        if not asked:
            if str(self.config.get("provider.name") or "null") == "null":
                result.provider = {"configured": "null", "used": "null"}
                result.warnings.append(
                    "the null provider is configured: this run is deterministic scanning only"
                )
            else:
                provider = self._provider(result)
                asked = provider is not None
        builder = PromptBuilder(
            max_diff_bytes=int(self.config.get("context.max_diff_bytes", 400000))
        )
        if asked and provider is not None:
            model_findings = self._ask_model(
                provider, builder, bundle, scanner_notes(scanner_results), result
            )
            candidates.extend(model_findings)

        # 9. deterministic anchoring
        kept, rejected = apply_anchoring(candidates, bundle, self.boundary)
        result.rejected.extend(rejected)

        # 10. adversarial verification
        if kept and provider is not None and self.config.get("review.verify_findings", True):
            kept, verification_rejected = self._verify(provider, builder, bundle, kept, result)
            result.rejected.extend(verification_rejected)

        # 11. merge, filter, sort
        merged = dedupe(kept)
        floor = float(self.config.get("review.min_confidence", 0.6))
        surviving = []
        for finding in merged:
            if finding.confidence < floor:
                finding.verification_note = (
                    "below review.min_confidence ({0:.2f} < {1:.2f})".format(
                        finding.confidence, floor
                    )
                )
                result.rejected.append(finding)
            else:
                surviving.append(finding)
        limit = int(self.config.get("review.max_findings", 200))
        ordered = sort_findings(surviving)
        if len(ordered) > limit:
            result.warnings.append(
                "{0} findings truncated to review.max_findings={1}".format(len(ordered), limit)
            )
            ordered = ordered[:limit]
        result.findings = ordered

        result.policy = self.policy.summary()
        result.egress = list(self.guard.connections)
        result.duration_seconds = time.time() - started
        _close_run(result)
        return result

    # -- internals ------------------------------------------------------
    def _provider(self, result: ReviewResult) -> Optional[Provider]:
        try:
            provider = Gateway(self.policy, self.guard).build()
        except (ProviderError, PolicyDenied) as exc:
            # No fallback. The review continues deterministically and the
            # report says the AI pass did not happen.
            result.errors.append("provider unavailable: {0}".format(exc))
            result.provider = {"configured": self.config.get("provider.name"), "used": None}
            return None
        result.provider = provider.describe()
        result.provider["used"] = provider.name
        if provider.name == "null":
            result.warnings.append(
                "the null provider is configured: this run is deterministic scanning only"
            )
        return provider

    def _ask_model(
        self,
        provider: Provider,
        builder: PromptBuilder,
        bundle: Bundle,
        notes: str,
        result: ReviewResult,
    ) -> List[Finding]:
        prompt = builder.review_prompt(bundle, notes)
        try:
            prompt = self._clean(prompt, result)
        except SecretDetected as exc:
            result.errors.append(str(exc))
            return []
        try:
            completion = provider.complete(
                SYSTEM_PROMPT,
                prompt,
                max_output_tokens=int(self.config.get("provider.max_output_tokens", 4096)),
                temperature=float(self.config.get("provider.temperature", 0.0)),
                json_schema=REVIEW_SCHEMA,
            )
        except JscrError as exc:
            result.errors.append("review pass failed: {0}".format(exc))
            return []
        _record_usage(result, completion, "review")
        return _findings_from(completion.text, result)

    def _verify(
        self,
        provider: Provider,
        builder: PromptBuilder,
        bundle: Bundle,
        findings: Sequence[Finding],
        result: ReviewResult,
    ):
        # The verification prompt carries the findings as well as the code,
        # and the findings are the bigger half: measured on a real
        # repository, 499 findings listed 249,497 bytes against a
        # 64,313-byte bundle, and the whole prompt was refused as too long.
        # One pass per batch of findings keeps each prompt inside the
        # provider's window. The batch cap bounds what a review costs when
        # a repository raises hundreds of findings.
        batch_bytes = int(self.config.get("review.verify_batch_bytes", 80000))
        max_batches = int(self.config.get("review.max_verify_batches", 4))
        batches = _batch_findings(findings, batch_bytes)
        kept: List[Finding] = []
        rejected: List[Finding] = []
        for number, batch in enumerate(batches, 1):
            if number > max_batches:
                # Said plainly, because an unverified finding is a weaker
                # claim than a verified one and the reader must know which.
                unchecked = sum(len(b) for b in batches[number - 1 :])
                result.warnings.append(
                    "{0} findings not verified: review.max_verify_batches={1} "
                    "reached. They are kept, unverified.".format(unchecked, max_batches)
                )
                kept.extend(f for b in batches[number - 1 :] for f in b)
                break
            prompt = builder.verify_prompt(bundle, batch)
            try:
                prompt = self._clean(prompt, result)
            except SecretDetected as exc:
                result.warnings.append("verification skipped: {0}".format(exc))
                kept.extend(batch)
                continue
            try:
                completion = provider.complete(
                    VERIFY_SYSTEM_PROMPT,
                    prompt,
                    max_output_tokens=int(self.config.get("provider.max_output_tokens", 4096)),
                    temperature=0.0,
                    json_schema=VERIFY_SCHEMA,
                )
            except JscrError as exc:
                result.warnings.append(
                    "verification pass {0} of {1} failed, its {2} findings kept "
                    "unverified: {3}".format(number, len(batches), len(batch), exc)
                )
                kept.extend(batch)
                continue
            _record_usage(
                result, completion, "verify" if len(batches) == 1 else "verify-{0}".format(number)
            )
            batch_kept, batch_rejected = apply_verdicts(batch, completion.text)
            kept.extend(batch_kept)
            rejected.extend(batch_rejected)
        return kept, rejected

    def _clean(self, text: str, result: ReviewResult) -> str:
        """Run the pre-egress inspection over everything about to be sent."""
        cleaned, hits = self.redactor.redact(text)
        if hits:
            result.redaction = {
                "applied": True,
                "hits": len(hits),
                "rules": sorted({h.rule for h in hits}),
            }
            result.warnings.append(
                "{0} probable secret(s) redacted before egress".format(len(hits))
            )
        return cleaned


def _findings_from(payload: str, result: ReviewResult) -> List[Finding]:
    data = parse_json_object(payload)
    if not isinstance(data, dict):
        # Discarding the reply with no trace left the failure undiagnosable:
        # a run reported "no AI findings" and nothing said why. The excerpt
        # is model output, which has been through no repository content, so
        # it carries nothing the report does not already hold.
        result.warnings.append(
            "the model did not return readable JSON; no AI findings recorded. "
            "It answered {0} characters, beginning: {1}".format(
                len(payload or ""), (payload or "").strip()[:300].replace("\n", " ")
            )
        )
        return []
    raw = data.get("findings")
    if not isinstance(raw, list):
        result.warnings.append(
            "the model returned JSON with no findings list; keys were: {0}".format(
                ", ".join(sorted(str(k) for k in data)) or "none"
            )
        )
        return []
    findings: List[Finding] = []
    for entry in raw:
        if isinstance(entry, dict):
            findings.append(Finding.from_dict(entry))
    return findings


def _record_usage(result: ReviewResult, completion: Completion, phase: str) -> None:
    usage = result.usage.setdefault("phases", {})
    usage[phase] = completion.as_dict()
    totals = result.usage.setdefault("totals", {"input_tokens": 0, "output_tokens": 0})
    totals["input_tokens"] += completion.input_tokens
    totals["output_tokens"] += completion.output_tokens


def _version() -> str:
    from .. import __version__

    return __version__


def _utc_now() -> str:
    """One timestamp format everywhere: UTC, to the second, with the Z.

    A local timestamp cannot be compared across machines, and a run record
    that cannot be placed on a timeline is not traceability.
    """
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _engine_commit() -> str:
    """The commit of JSCR itself, so a finding can be traced to the code
    that raised it. Empty when JSCR is not being run from a checkout."""
    import subprocess  # nosec B404 - argument list only, never a shell

    here = os.path.dirname(os.path.abspath(__file__))
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", here, "rev-parse", "HEAD"],  # noqa: S607 - git from PATH,
            # the same resolution every other git call in this package uses
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.decode("utf-8", "replace").strip() if out.returncode == 0 else ""


def _repository_state(git: Git, target: GitRange, root: str) -> Dict[str, Any]:
    """What was reviewed, named by commit rather than by branch.

    A branch name moves. The head commit and the base commit are what make
    a run repeatable, and the dirty flag says whether the tree on disk was
    the tree in that commit.
    """
    state: Dict[str, Any] = {"root": root, "target": target.describe()}
    for key, call in (
        ("head_commit", git.head_commit),
        ("branch", git.current_branch),
    ):
        try:
            state[key] = call()
        except JscrError:
            state[key] = ""
    try:
        state["base_commit"] = git.resolve(target.base) if target.base else ""
    except (JscrError, AttributeError):
        state["base_commit"] = ""
    try:
        state["dirty"] = bool(git.run(["status", "--porcelain"]).strip())
    except JscrError:
        state["dirty"] = None
    return state


def _close_run(result: ReviewResult) -> None:
    """Stamp the end of the run, and copy in what only became known during
    it: the model that answered, and whether anything failed."""
    if not result.run:
        return
    result.run["finished_at"] = _utc_now()
    result.run["duration_seconds"] = round(result.duration_seconds, 3)
    result.run["provider"] = {
        "used": result.provider.get("used"),
        "model": result.provider.get("model", ""),
    }
    result.run["outcome"] = {
        "findings": len(result.findings),
        "errors": len(result.errors),
        "warnings": len(result.warnings),
        "worst": result.worst_severity(),
    }


def _batch_findings(findings: Sequence[Finding], budget: int) -> List[List[Finding]]:
    """Split findings into batches whose listing fits the byte budget.

    The measure is the finding's own text, because that is what the prompt
    carries. A single finding larger than the budget still gets its own
    batch: dropping it would verify nothing and say nothing.
    """
    batches: List[List[Finding]] = []
    current: List[Finding] = []
    used = 0
    for finding in findings:
        size = (
            len(finding.title or "") + len(finding.detail or "") + len(finding.evidence or "") + 200
        )
        if current and used + size > budget:
            batches.append(current)
            current = []
            used = 0
        current.append(finding)
        used += size
    if current:
        batches.append(current)
    return batches

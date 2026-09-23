"""Record what the coverage number is, and what produced it.

A percentage on its own is a claim. This writes the claim next to the
things that make it checkable: the commit measured, the interpreter and
tool that measured it, when, and the workflow run that can be opened and
read. The same file is written locally, where the CI fields are simply
absent rather than invented.
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import subprocess  # noqa: S404 - fixed argv, no shell
import sys


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _commit() -> str:
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - git from PATH
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.decode("utf-8", "replace").strip() if out.returncode == 0 else ""


def main() -> int:
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "coverage", "json", "-o", "coverage.json"],
        check=True,
    )
    with open("coverage.json", encoding="utf-8") as handle:
        data = json.load(handle)
    totals = data.get("totals", {})
    covered = int(totals.get("covered_lines", 0))
    missing = int(totals.get("missing_lines", 0))

    files = data.get("files", {})
    worst = sorted(
        ((name, body.get("summary", {})) for name, body in files.items()),
        key=lambda pair: int(pair[1].get("missing_lines", 0)),
        reverse=True,
    )[:5]

    record = {
        "measured_at": _utc_now(),
        "commit": _commit(),
        "percent_covered": round(float(totals.get("percent_covered", 0.0)), 2),
        "covered_lines": covered,
        "missing_lines": missing,
        "statements": covered + missing,
        "python": platform.python_version(),
        "coverage_version": data.get("meta", {}).get("version", ""),
        "workflow_run": os.environ.get("GITHUB_RUN_ID", ""),
        "workflow_run_url": (
            "{0}/{1}/actions/runs/{2}".format(
                os.environ.get("GITHUB_SERVER_URL", ""),
                os.environ.get("GITHUB_REPOSITORY", ""),
                os.environ.get("GITHUB_RUN_ID", ""),
            )
            if os.environ.get("GITHUB_RUN_ID")
            else ""
        ),
        "least_covered": [
            {
                "file": name,
                "missing_lines": int(summary.get("missing_lines", 0)),
                "percent_covered": round(float(summary.get("percent_covered", 0.0)), 2),
            }
            for name, summary in worst
        ],
    }
    with open("coverage-provenance.json", "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = [
        "## Coverage",
        "",
        "**{0}%** of {1} statements, {2} missed.".format(
            record["percent_covered"], record["statements"], missing
        ),
        "",
        "Commit `{0}` · Python {1} · coverage {2} · measured {3}".format(
            record["commit"][:12] or "unknown",
            record["python"],
            record["coverage_version"] or "unknown",
            record["measured_at"],
        ),
        "",
        "| Least covered | Missing | Covered |",
        "| --- | ---: | ---: |",
    ]
    for entry in record["least_covered"]:
        lines.append(
            "| `{0}` | {1} | {2}% |".format(
                entry["file"], entry["missing_lines"], entry["percent_covered"]
            )
        )
    text = "\n".join(lines) + "\n"
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

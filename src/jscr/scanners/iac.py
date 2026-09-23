"""Infrastructure written as files.

Terraform, Kubernetes, Compose and CloudFormation all describe a machine that
does not exist yet, so a mistake here is not a bug in one request — it is the
shape of everything that runs afterwards. The rules are line-based on purpose:
they quote the line that sets the value, which is the line a reader has to
change.

Only settings whose meaning does not depend on the surrounding stack are
flagged. "Open to the whole internet" is one of those. "Too much memory" is
not, so it is absent.
"""

from __future__ import annotations

import re
import time
from typing import List, Pattern, Sequence, Tuple

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation
from ..review.findings import CRITICAL, HIGH, MEDIUM, SOURCE_SCANNER, Finding
from .base import Scanner, ScannerResult

#: rule id, compiled pattern, severity, cwe, title, detail, fix
Rule = Tuple[str, Pattern[str], str, str, str, str, str]

_TF: Sequence[Rule] = (
    (
        "jscr/iac-open-ingress",
        re.compile(r'cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"'),
        HIGH,
        "CWE-284",
        "network open to every address",
        "0.0.0.0/0 means every host on the internet may reach this port. Whether that is "
        "acceptable depends on the port, and this rule cannot see the port reliably, so it "
        "reports the opening rather than judging it.",
        "Name the source range, a security group, or a prefix list. If the service really "
        "is public, put it behind a load balancer and open the balancer, not the instance.",
    ),
    (
        "jscr/iac-public-bucket",
        re.compile(r'acl\s*=\s*"public-read(-write)?"'),
        CRITICAL,
        "CWE-732",
        "storage bucket readable by anyone",
        "A public-read ACL makes every object in the bucket downloadable without "
        "credentials, including objects written later by something that assumed privacy.",
        "Remove the ACL, block public access at the account level, and serve what must be "
        "public through a CDN with signed URLs.",
    ),
    (
        "jscr/iac-unencrypted",
        re.compile(r"encrypted\s*=\s*false|storage_encrypted\s*=\s*false"),
        MEDIUM,
        "CWE-311",
        "storage encryption switched off",
        "Encryption at rest is switched off explicitly. The default for this resource is "
        "on, so this is a decision someone made, not an omission.",
        "Delete the line and let the default apply, or set it to true with a named key.",
    ),
    (
        "jscr/iac-plaintext-secret",
        re.compile(r'(password|secret|token)\s*=\s*"[^"$][^"]{5,}"', re.I),
        HIGH,
        "CWE-798",
        "credential written into the plan",
        "A literal credential in a Terraform file is also in the state file, the plan "
        "output, and every CI log that printed the plan.",
        "Read it from a secret manager data source or a variable marked sensitive, and "
        "rotate the value that is already committed.",
    ),
    (
        "jscr/iac-wildcard-policy",
        re.compile(r'"(Action|Resource)"\s*:\s*"\*"|Action\s*=\s*\[?\s*"\*"'),
        HIGH,
        "CWE-732",
        "policy grants every action or every resource",
        "A wildcard in a policy grants everything the service can do, so the blast radius "
        "of a stolen key is the whole account rather than one bucket.",
        "List the actions the workload calls, and scope the resource to the exact ARNs.",
    ),
)

_K8S: Sequence[Rule] = (
    (
        "jscr/k8s-privileged",
        re.compile(r"privileged\s*:\s*true"),
        CRITICAL,
        "CWE-250",
        "container runs privileged",
        "A privileged container has the host's devices and capabilities. Escaping it to "
        "the node is a documented, routine step, not an exploit.",
        "Drop privileged and add only the capabilities the process names. If it needs the "
        "host, run it as a separate node-level unit that is reviewed on its own.",
    ),
    (
        "jscr/k8s-host-network",
        re.compile(r"hostNetwork\s*:\s*true|hostPID\s*:\s*true|hostIPC\s*:\s*true"),
        HIGH,
        "CWE-250",
        "container shares the host namespace",
        "Sharing the host network, PID or IPC namespace removes the boundary between the "
        "container and everything else on the node.",
        "Use a Service for traffic. If a node agent genuinely needs the namespace, isolate "
        "it with a taint and a dedicated service account.",
    ),
    (
        "jscr/k8s-root-user",
        re.compile(r"runAsUser\s*:\s*0|runAsNonRoot\s*:\s*false"),
        HIGH,
        "CWE-250",
        "container runs as root",
        "Running as UID 0 means a file-write weakness in the process writes as root, and "
        "any capability the runtime grants is held by the attacker too.",
        "Set runAsNonRoot: true and a numeric runAsUser above 10000, and make the image's "
        "files readable by that user at build time.",
    ),
    (
        "jscr/k8s-host-path",
        re.compile(r"hostPath\s*:"),
        MEDIUM,
        "CWE-732",
        "host directory mounted into the container",
        "A hostPath mount gives the container a real directory on the node. Which one "
        "decides whether this is harmless or a full escape.",
        "Use a PersistentVolumeClaim or an emptyDir. If a host directory is required, "
        "mount it read-only and name the exact path.",
    ),
    (
        "jscr/k8s-docker-socket",
        re.compile(r"/var/run/docker\.sock|/var/run/containerd"),
        CRITICAL,
        "CWE-250",
        "container runtime socket mounted",
        "Access to the runtime socket is control of every container on the node, including "
        "the ability to start a new one with the host filesystem attached.",
        "Remove the mount. If the workload builds images, use a builder that does not need "
        "the socket, or move the build to a separate, isolated runner.",
    ),
)

_TF_SUFFIX = (".tf", ".tfvars", ".hcl")
_CF_HINT = ("AWSTemplateFormatVersion", "Resources:")
_K8S_HINT = ("apiVersion:", "kind:")
_COMPOSE = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


class IacScanner(Scanner):
    """Terraform, Kubernetes, Compose and CloudFormation settings."""

    name = "iac"
    external = False

    def scan(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        timeout: int = 300,
    ) -> ScannerResult:
        del timeout
        started = time.time()
        findings: List[Finding] = []
        read = 0
        for path in paths:
            normalised = path.replace("\\", "/")
            base = normalised.split("/")[-1]
            terraform = normalised.endswith(_TF_SUFFIX)
            yaml_like = normalised.endswith((".yml", ".yaml", ".json"))
            if not terraform and not yaml_like:
                continue
            try:
                text = boundary.read_text(path)
            except (OSError, UnicodeDecodeError, BoundaryViolation):
                continue

            rules: List[Rule] = []
            if terraform:
                rules = list(_TF)
            elif base in _COMPOSE:
                rules = list(_K8S)
            elif any(hint in text for hint in _K8S_HINT) and "kind:" in text:
                rules = list(_K8S)
            elif any(hint in text for hint in _CF_HINT):
                rules = list(_TF)
            if not rules:
                continue
            read += 1
            findings.extend(_apply(path, text, rules))
        return ScannerResult(
            name=self.name,
            ran=True,
            findings=findings,
            duration_seconds=time.time() - started,
            version="files={0}".format(read),
        )


def _apply(path: str, text: str, rules: Sequence[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule_id, pattern, severity, cwe, title, detail, fix in rules:
            if not pattern.search(line):
                continue
            findings.append(
                Finding(
                    path=path,
                    line=index,
                    title=title,
                    detail=detail,
                    severity=severity,
                    evidence=stripped[:200],
                    recommendation=fix,
                    rule_id=rule_id,
                    cwe=cwe,
                    confidence=0.75,
                    source=SOURCE_SCANNER,
                )
            )
    return findings

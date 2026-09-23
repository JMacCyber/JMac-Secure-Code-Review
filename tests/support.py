"""Shared test helpers.

One convention is load bearing: **no credential-shaped literal is written
anywhere in this repository**, including in tests. Fixtures that need to
look like a key are assembled at runtime from fragments. A repository of
security tooling that contains strings matching every secret scanner in
existence trains people to ignore those scanners, and gets the repository
flagged by the tools it is meant to sit alongside.
"""

from __future__ import annotations

import copy
import os
import shutil
import subprocess
import tempfile
import unittest

from jscr.config import DEFAULTS, Config


def fake_aws_key_id() -> str:
    """A string shaped like an AWS access key id. Assembled, never written."""
    return "A" + "KIA" + "IOSFODNN7" + "EXAMPLE"


def fake_vcs_token() -> str:
    return "g" + "hp_" + ("a1b2c3d4e5" * 4)


def fake_model_key() -> str:
    return "s" + "k-" + "ant-" + "api03-" + ("x" * 32)


def fake_private_key_block() -> str:
    head = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
    tail = "-----END " + "RSA PRIVATE" + " KEY-----"
    return head + "\nMIIEow" + "IBAAKCAQEA" + "x" * 40 + "\n" + tail


def fake_connection_string() -> str:
    return "postgres://app:" + "hunter2" + "corrrect" + "@db.internal/app"


def fake_assigned_secret() -> str:
    return "api_secret = " + '"' + "8f3a9c2b7d1e" + "4056a1b2c3d4e5f60718" + '"'


def config(**overrides) -> Config:
    """A Config built from the shipped defaults plus dotted overrides."""
    data = copy.deepcopy(DEFAULTS)
    cfg = Config(data, None)
    for key, value in overrides.items():
        cfg.override(key.replace("__", "."), value)
    return cfg


class TempRepo(object):
    """A throwaway git repository, created and removed inside the test run."""

    def __init__(self) -> None:
        self.root = tempfile.mkdtemp(prefix="jscr-test-")

    def write(self, relative: str, content: str) -> str:
        path = os.path.join(self.root, relative)
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def git(self, *args: str) -> str:
        env = dict(os.environ)
        env.update(
            {
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.invalid",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.invalid",
                "GIT_CONFIG_NOSYSTEM": "1",
            }
        )
        completed = subprocess.run(
            ["git"] + list(args),
            cwd=self.root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        if completed.returncode != 0:
            raise AssertionError("git {0} failed: {1}".format(" ".join(args), output))
        return output

    def init(self) -> "TempRepo":
        self.git("init", "-q", ".")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.git("config", "commit.gpgsign", "false")
        return self

    def commit(self, message: str = "change") -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def close(self) -> None:
        # Test scaffolding created by this process in the system temp
        # directory, removed by the same process. Nothing here belongs to
        # the user.
        shutil.rmtree(self.root, ignore_errors=True)


class RepoTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = TempRepo().init()
        self.addCleanup(self.repo.close)

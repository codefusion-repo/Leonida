"""Synthetic policy tests, never invoke project executables."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_policy", ROOT / "make_game.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.game = self.root / "private-canary"
        self.game.mkdir()
        (self.game / "sentinel.txt").write_bytes(b"synthetic")
        self.out = self.root / "out"
        self.work = self.root / "work"

    def args(self, game=None, out=None, work=None, stages="runtime", jobs="1"):
        return ["plan", "--game", str(game or self.game), "--out", str(out or self.out),
                "--work", str(work or self.work), "--stages", stages, "--jobs", jobs]

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with patch("subprocess.Popen", side_effect=AssertionError("process forbidden")), \
                    patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                    patch("os.scandir", side_effect=AssertionError("scan forbidden")), \
                    patch("os.mkdir", side_effect=AssertionError("write forbidden")):
                rc = policy.main(args)
        self.assertNotIn("private-canary", stdout.getvalue() + stderr.getvalue())
        self.assertFalse(self.out.exists())
        self.assertFalse(self.work.exists())
        self.assertEqual((self.game / "sentinel.txt").read_bytes(), b"synthetic")
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_plan(self):
        rc, output, err = self.invoke(self.args(stages="runtime,assets", jobs="4"))
        self.assertEqual((rc, err), (0, ""))
        data = json.loads(output)
        self.assertFalse(data["execution_authorized"])
        self.assertEqual(data["status"], "HOLD")
        self.assertEqual(data["stages"], ["assets", "runtime"])
        self.assertEqual(data["tool_identity"], "UNVERIFIED")
        self.assertEqual(data["requested_jobs"], 4)

    def test_default_legacy_and_private_argument(self):
        for args in ([], ["--find"], ["--game", str(self.game)], ["plan"], ["--check"], ["private-canary"]):
            self.assertEqual(self.invoke(args)[0], 2)

    def test_execution_disabled(self):
        for command in ("prepare", "build"):
            self.assertEqual(self.invoke([command])[0], 3)

    def test_invalid_stages_jobs(self):
        for stages, jobs in (("", "1"), ("runtime,runtime", "1"), ("bad", "1"),
                             ("runtime", "0"), ("runtime", "5"), ("runtime", "bad")):
            self.assertEqual(self.invoke(self.args(stages=stages, jobs=jobs))[0], 2)

    def test_missing_relative_file_input(self):
        for game in ("relative", self.root / "missing", self.game / "sentinel.txt"):
            self.assertEqual(self.invoke(self.args(game=game))[0], 2)

    def test_overlap_missing_parent(self):
        for out, work in ((self.game / "child", self.work), (self.out, self.out),
                          (self.out, self.out / "work"), (ROOT / "new-output", self.work)):
            self.assertEqual(self.invoke(self.args(out=out, work=work))[0], 2)

    def test_existing_destination(self):
        stale = self.root / "stale"
        stale.mkdir()
        self.assertEqual(self.invoke(self.args(out=stale))[0], 2)

    def test_traversal(self):
        self.assertEqual(self.invoke(self.args(game=str(self.game) + os.sep + ".." + os.sep + self.game.name))[0], 2)

    @unittest.skipIf(os.name == "nt", "Windows junction test below")
    def test_real_symlink(self):
        link = self.root / "link"
        link.symlink_to(self.game, target_is_directory=True)
        self.assertEqual(self.invoke(self.args(game=link))[0], 2)
        self.assertEqual(self.invoke(self.args(out=link / "child"))[0], 2)

    @unittest.skipUnless(os.name == "nt", "Windows filesystem only")
    def test_real_junction(self):
        link = self.root / "junction"
        cmd = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
        result = subprocess.run([str(cmd), "/d", "/c", "mklink", "/J", str(link), str(self.game)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, "synthetic junction creation failed")
        try:
            self.assertEqual(self.invoke(self.args(game=link))[0], 2)
            self.assertEqual(self.invoke(self.args(out=link / "child"))[0], 2)
        finally:
            link.rmdir()

    @unittest.skipUnless(os.name == "nt", "Windows filesystem only")
    def test_windows_special_paths(self):
        for raw in (r"\\invalid.invalid\share\folder", r"\\?\C:\folder", str(self.game) + ":ads"):
            self.assertEqual(self.invoke(self.args(game=raw))[0], 2)


if __name__ == "__main__":
    unittest.main()

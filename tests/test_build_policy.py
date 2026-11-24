"""Synthetic regressions; no project binaries, user data, or sandbox claims."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_policy", ROOT / "make_game.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def snapshot(root):
    """Observe synthetic tree only, without following symlinks/reparse points."""
    result = {}
    def visit(p):
        info = p.lstat()
        key = str(p.relative_to(root))
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            result[key] = ("link", os.readlink(p))
        elif stat.S_ISDIR(info.st_mode):
            result[key] = ("dir",)
            for child in sorted(p.iterdir()):
                visit(child)
        else:
            result[key] = ("file", p.read_bytes())
    visit(root)
    return result


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.game = self.root / "private-input-canary"
        self.game.mkdir()
        (self.game / "sentinel.txt").write_bytes(b"synthetic")
        self.out = self.root / "private-output-canary"
        self.work = self.root / "private-work-canary"

    def args(self, operation="plan", **overrides):
        values = dict(game=str(self.game), out=str(self.out), work=str(self.work), stages="runtime", jobs="1")
        values.update(overrides)
        return [operation] + [item for k, v in values.items() for item in ("--" + k, str(v))]

    def cli(self, args, expected):
        before = snapshot(self.root)
        p = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "make_game.py"), *args],
                           cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, expected)
        self.assertEqual(snapshot(self.root), before)
        for secret in (str(self.root), self.game.name, self.out.name, self.work.name, "private-flag-canary"):
            self.assertNotIn(secret, p.stdout + p.stderr)
        if expected:
            self.assertEqual(p.stdout, "")
            self.assertTrue(p.stderr.startswith("REJECTED:" if expected == 2 else "HOLD:"))
        else:
            self.assertEqual(p.stderr, "")
        return p.stdout

    def assert_plan_hold(self, **paths):
        data = json.loads(self.cli(self.args(**paths), 0))
        self.assertEqual(data["status"], "HOLD")
        self.assertEqual(data["path_validation"], "LEXICAL_ONLY")
        self.assertEqual(data["metadata"], "NOT_INSPECTED")
        self.assertEqual(data["locality"], "UNVERIFIED")
        self.assertEqual(data["path_identity"], "UNVERIFIED")
        self.assertFalse(data["execution_authorized"])
        self.cli(self.args("inspect", **paths), 3)
        return data

    def test_plan_and_metadata_denial(self):
        data = self.assert_plan_hold(stages="runtime,assets", jobs="4")
        self.assertEqual(data["stages"], ["assets", "runtime"])
        self.assertEqual(data["requested_jobs"], 4)
        self.assertEqual(data["resource_enforcement"], "NOT_AVAILABLE")

    def test_default_and_help(self):
        for args in ([], ["--find"], ["--game", str(self.game)], ["plan"], ["--check"], ["private-flag-canary"]):
            self.cli(args, 2)
        for args in (["--help"], ["plan", "--help"], ["inspect", "--help"]):
            self.assertIn("usage:", self.cli(args, 0))

    def test_execution_disabled(self):
        for command in ("prepare", "build"):
            self.cli([command], 3)

    def test_invalid_and_duplicate_arguments(self):
        for stages, jobs in (("", "1"), ("runtime,runtime", "1"), ("bad", "1"),
                             ("runtime", "0"), ("runtime", "5"), ("runtime", "private-flag-canary")):
            self.cli(self.args(stages=stages, jobs=jobs), 2)
        for flag in ("game", "out", "work", "stages", "jobs"):
            self.cli(self.args() + ["--" + flag + "=private-flag-canary"], 2)
        self.cli(self.args() + ["--private-flag-canary"], 2)

    def test_all_roles_lexical_rejection(self):
        for role in ("game", "out", "work"):
            for raw in ("relative", str(self.root.anchor), str(self.root / "x") + "/../y",
                        str(self.root / "x") + "/", str(self.root / "x") + "\x7f",
                        str(self.root / ("x" * 256))):
                self.cli(self.args(**{role: raw}), 2)

    def test_overlaps(self):
        for values in (dict(out=self.game / "child"), dict(work=self.out),
                       dict(work=self.out / "child"), dict(out=ROOT / "new-output"),
                       dict(out=str(self.game).upper())):
            self.cli(self.args(**values), 2)

    def test_metadata_never_claimed(self):
        for role in ("game", "out", "work"):
            self.assert_plan_hold(**{role: self.root / "missing"})
            self.assert_plan_hold(**{role: self.game / "sentinel.txt"} if role == "game" else
                                  {role: self.root / "existing"})
        self.out.mkdir()
        self.assert_plan_hold()

    def test_pure_planner_no_io_calls(self):
        with contextlib.ExitStack() as stack:
            for name in ("os.stat", "os.lstat", "os.scandir", "os.mkdir", "os.open", "builtins.open",
                         "os.path.realpath", "pathlib.Path.resolve", "subprocess.Popen", "socket.socket"):
                stack.enter_context(patch(name, side_effect=AssertionError("planner IO forbidden")))
            result = policy.make_plan(str(self.game), str(self.out), str(self.work), "runtime", 1)
        self.assertFalse(result["execution_authorized"])

    def test_exception_redaction(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(policy, "make_plan", side_effect=OSError("private-flag-canary")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(policy.main(self.args()), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "REJECTED: PATH_POLICY_FAILED\n")

    def test_windows_lexical_cases_portable(self):
        for raw in (r"\\server\share\x", r"\\?\C:\x", r"\\.\C:\x", r"C:relative",
                    r"C:\x:ads", r"C:\CON.txt", r"C:\COM¹.txt", r"C:\CONIN$", r"C:\x.",
                    r"C:\x ", r"C:\PROGRA~1\x", r"C:\x\\y"):
            with self.assertRaises(policy.PolicyError):
                policy.lexical_path(raw, windows=True)
        self.assertEqual(policy.lexical_path(r"C:\Alpha\Beta", True), policy.lexical_path("c:/alpha/beta", True))

    @unittest.skipIf(os.name == "nt", "Windows junction test below")
    def test_real_symlink(self):
        link = self.root / "link"
        link.symlink_to(self.game, target_is_directory=True)
        for role in ("game", "out", "work"):
            self.assert_plan_hold(**{role: link / "child"})

    @unittest.skipUnless(os.name == "nt", "Windows filesystem only")
    def test_real_junction(self):
        link = self.root / "junction"
        cmd = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
        p = subprocess.run([str(cmd), "/d", "/c", "mklink", "/J", str(link), str(self.game)],
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 0)
        try:
            for role in ("game", "out", "work"):
                self.assert_plan_hold(**{role: link / "child"})
        finally:
            link.rmdir()

    @unittest.skipUnless(os.name == "nt", "Windows filesystem only")
    def test_windows_special_paths_all_roles(self):
        for role in ("game", "out", "work"):
            for raw in (r"\\invalid.invalid\share\folder", r"\\?\C:\folder", r"\\.\C:\folder",
                        str(self.game) + ":ads", str(self.game / "CON.txt"), str(self.game / "ALIAS~1")):
                self.cli(self.args(**{role: raw}), 2)

    @unittest.skipUnless(os.name == "nt", "Windows batch only")
    def test_batch_no_python(self):
        cmd = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
        for name in ("python.bat", "python.cmd", "py.bat", "py.cmd"):
            (self.root / name).write_text("@echo off\necho launched>launched.txt\nexit /b 99\n")
        env = dict(os.environ, PATH=str(self.root), PATHEXT=".COM;.EXE;.BAT;.CMD")
        before = snapshot(self.root)
        p = subprocess.run([str(cmd), "/d", "/c", "call", str(ROOT / "Build.bat")],
                           cwd=self.root, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 3)
        self.assertTrue(p.stdout.startswith("HOLD:"))
        self.assertEqual(snapshot(self.root), before)

    def test_git_ignore(self):
        paths = ["game_path.txt", "nested/game_path.txt"]
        p = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "--no-index", "--", *paths],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout.splitlines(), paths)
        p = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--", "game_path.txt", "*/game_path.txt"],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual((p.returncode, p.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()

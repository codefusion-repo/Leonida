import json
from pathlib import Path
import runpy
import tempfile
import unittest

p = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/artifact_integrity.py"))
SHA = "a" * 40
ENV = {"GITHUB_REPOSITORY": p["REPO"], "GITHUB_EVENT_NAME": "push",
       "GITHUB_REF": "refs/heads/main", "GITHUB_WORKFLOW_REF": p["WORKFLOW"] + "refs/heads/main",
       "GITHUB_WORKFLOW_SHA": SHA, "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "123",
       "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REF_PROTECTED": "true"}


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.identity = p["context"](SHA, ENV, True)
        for name in p["FILES"]:
            self.write(name, {})
        self.write("audit.json", {"candidate": SHA, "submodule": p["SUB"], "reviewedLocks": True,
                                  "lockedRestore": "passed", "advisoryReports": "passed",
                                  "source": "https://api.nuget.org/v3/index.json"})
        self.write("rpf9dump.cdx.json", {"bomFormat": "CycloneDX", "specVersion": "1.5",
                                         "metadata": {"component": {"version": SHA}}})

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")

    def seal(self):
        p["create"](self.root, self.identity)

    def reject(self, identity=None):
        with self.assertRaises((ValueError, OSError)):
            p["verify"](self.root, identity or self.identity)

    def test_valid(self):
        self.seal()
        self.assertRegex(p["verify"](self.root, self.identity), "^[a-f0-9]{64}$")
        with self.assertRaises(ValueError):
            self.seal()

    def test_tampered_file(self):
        self.seal()
        self.write("rpf9dump.lock.json", {"changed": True})
        self.reject()

    def test_missing_extra(self):
        self.seal()
        (self.root / "unexpected.json").write_text("{}")
        self.reject()
        (self.root / "unexpected.json").unlink()
        (self.root / "rpf9-core.lock.json").unlink()
        self.reject()

    def test_identity(self):
        self.seal()
        for key, value in (("candidate", "b" * 40), ("runId", "124"), ("runAttempt", "2"),
                           ("workflowSha", "b" * 40), ("repository", "other/repo")):
            changed = dict(self.identity, **{key: value})
            self.reject(changed)

    def test_manifest_tamper(self):
        self.seal()
        manifest = json.loads((self.root / "manifest.json").read_text())
        manifest["files"]["audit.json"]["sha256"] = "0" * 64
        self.write("manifest.json", manifest)
        self.reject()

    def test_failed_gate(self):
        audit = json.loads((self.root / "audit.json").read_text())
        audit["reviewedLocks"] = False
        self.write("audit.json", audit)
        with self.assertRaises(ValueError):
            self.seal()

    def test_duplicate_and_size(self):
        self.seal()
        path = self.root / "rpf9dump.lock.json"
        path.write_text('{"x":1,"x":2}', encoding="utf-8")
        self.reject()
        path.write_bytes(b"x" * 65537)
        self.reject()

    def test_symlink(self):
        self.seal()
        path = self.root / "rpf9dump.lock.json"
        path.unlink()
        try:
            path.symlink_to(self.root / "rpf9-core.lock.json")
        except OSError:
            self.skipTest("symlink creation unavailable on runner")
        self.reject()

    def test_signing_context(self):
        for changed in (dict(ENV, GITHUB_REF_PROTECTED="false"),
                        dict(ENV, GITHUB_REPOSITORY="other/repo"),
                        dict(ENV, GITHUB_REF="refs/heads/feature",
                             GITHUB_WORKFLOW_REF=p["WORKFLOW"] + "refs/heads/feature")):
            with self.assertRaises(ValueError):
                p["context"](SHA, changed, True)
        pr = dict(ENV, GITHUB_EVENT_NAME="pull_request", GITHUB_REF="refs/pull/12/merge",
                  GITHUB_WORKFLOW_REF=p["WORKFLOW"] + "refs/pull/12/merge",
                  GITHUB_SHA="b" * 40, GITHUB_WORKFLOW_SHA="b" * 40)
        p["context"](SHA, pr)
        with self.assertRaises(ValueError):
            p["context"](SHA, pr, True)


if __name__ == "__main__":
    unittest.main()

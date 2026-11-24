import base64
import copy
from pathlib import Path
import runpy
import unittest

p = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/supply_chain.py"))
sha, sub, source = p["SUB_SHA"], p["SUB"], p["SOURCE"]


class PolicyTests(unittest.TestCase):
    def test_gitlink(self):
        tree = f"160000 commit {sha}\t{sub}\0"
        index = f"160000 {sha} 0\t{sub}\0"
        p["validate_submodule"](p["MANIFEST"], tree, index)
        for manifest, t, i in [(p["MANIFEST"] + "\tbranch = main\n", tree, index),
                               (p["MANIFEST"].replace("https:", "file:"), tree, index),
                               (p["MANIFEST"], tree.replace(sha, "0" * 40), index),
                               (p["MANIFEST"], tree + tree, index),
                               (p["MANIFEST"], tree, index.replace(" 0\t", " 1\t"))]:
            with self.assertRaises(ValueError):
                p["validate_submodule"](manifest, t, i)

    def test_workflows(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / ".github/workflows").glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            p["validate_workflow"](text)
            for changed in (text.replace("contents: read", "contents: write"),
                            text.replace("persist-credentials: false", "persist-credentials: true"),
                            text.replace("submodules: false", "submodules: recursive"),
                            text.replace(p["ACTIONS"]["actions/checkout"], "v4"),
                            text.replace("    env:\n", "    env:\n      BAD: ${{ runner.temp }}\n"),
                            text.replace("          submodules: false", "          submodules: false\n          token: unsafe"),
                            text + "\n    permissions: write-all\n",
                            text + "\n    - uses: other/action@" + "0" * 40 + "\n"):
                with self.assertRaises(ValueError):
                    p["validate_workflow"](changed)

    def test_signing_policy(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        p["validate_workflow"](source)
        for changed in (source.replace(" && github.ref_protected", ""),
                        source.replace("github.event_name == 'push' && github.repository", "github.event_name == 'pull_request' && github.repository"),
                        source.replace("needs: [check, verify_evidence]", "needs: [check]"),
                        source.replace("attestations: write", "attestations: read"),
                        source.replace("subject-path:", "subject-digest:"),
                        source.replace("merge-multiple: true", "merge-multiple: false"),
                        source.replace("--expected-digest", "--unexpected-digest"),
                        source.replace("      manifest_sha256:", "      wrong_digest:"),
                        source.replace("    needs: check\n", "    needs: []\n"),
                        source.replace("    outputs:\n", "    permissions:\n      id-token: write\n    outputs:\n")):
            with self.assertRaises(ValueError):
                p["validate_workflow"](changed)

    def test_reports(self):
        clean = {"version": 1, "parameters": "--vulnerable --include-transitive", "sources": [source], "projects": [
            {"path": "rpf9dump.csproj", "frameworks": []}]}
        p["validate_report"](clean, "rpf9dump.csproj")
        omitted = copy.deepcopy(clean)
        del omitted["projects"][0]["frameworks"]
        p["validate_report"](omitted, "rpf9dump.csproj")
        for value in (None, {}, "invalid"):
            malformed = copy.deepcopy(clean)
            malformed["projects"][0]["frameworks"] = value
            with self.assertRaises(ValueError):
                p["validate_report"](malformed, "rpf9dump.csproj")
        for key in ("version", "sources", "projects", "parameters"):
            bad = copy.deepcopy(clean)
            del bad[key]
            with self.assertRaises(ValueError):
                p["validate_report"](bad, "rpf9dump.csproj")
        for field in ("topLevelPackages", "transitivePackages", "problems", "vulnerabilities"):
            bad = copy.deepcopy(clean)
            bad["projects"][0]["frameworks"] = [{field: [{"id": "Synthetic"}]}]
            with self.assertRaises(ValueError):
                p["validate_report"](bad, "rpf9dump.csproj")

    def test_sbom(self):
        digest = base64.b64encode(bytes(64)).decode()
        target = {"RpfPreview.Core/1.0.0": {"type": "project", "dependencies": {"BCnEncoder.Net": "2.3.0"}},
                  "BCnEncoder.Net/2.3.0": {"type": "package", "dependencies": {"Synthetic": "1.0.0"}},
                  "Synthetic/1.0.0": {"type": "package"}}
        assets = {"version": 3, "targets": {"net8.0": target},
                  "libraries": {k: {"type": v["type"], "sha512": digest} for k, v in target.items()},
                  "project": {"restore": {"sources": {source: {}}}, "frameworks": {"net8.0": {}}}}
        p["verify_restore_sources"](assets)
        for key, value in (("sources", {source: {}, "https://example.invalid": {}}),
                           ("fallbackFolders", ["C:/untrusted"])):
            altered = copy.deepcopy(assets)
            altered["project"]["restore"][key] = value
            with self.assertRaises(ValueError):
                p["verify_restore_sources"](altered)
        inventory = {"version": 1, "parameters": "--include-transitive", "projects": [
            {"path": "rpf9dump.csproj", "frameworks": [{"framework": "net8.0", "transitivePackages": [
                {"id": "BCnEncoder.Net", "resolvedVersion": "2.3.0"},
                {"id": "Synthetic", "resolvedVersion": "1.0.0"}]}]}]}
        p["validate_inventory"](inventory, assets, "rpf9dump.csproj")
        inventory["projects"][0]["frameworks"][0]["transitivePackages"].pop()
        with self.assertRaises(ValueError):
            p["validate_inventory"](inventory, assets, "rpf9dump.csproj")
        bom = p["sbom"](assets, "1" * 40)
        lock = {"version": 1, "dependencies": {"net8.0": {
            "RpfPreview.Core": {"type": "Project", "dependencies": {"BCnEncoder.Net": "2.3.0"}},
            "BCnEncoder.Net": {"type": "Transitive", "resolved": "2.3.0", "contentHash": digest,
                              "dependencies": {"Synthetic": "1.0.0"}},
            "Synthetic": {"type": "Transitive", "resolved": "1.0.0", "contentHash": digest}}}}
        p["validate_lock"](lock, assets)
        equivalent = copy.deepcopy(lock)
        equivalent["dependencies"]["net8.0"]["RpfPreview.Core"]["dependencies"]["BCnEncoder.Net"] = "[2.3.0, )"
        equivalent["dependencies"]["net8.0"]["BCnEncoder.Net"]["dependencies"]["Synthetic"] = "[1.0, )"
        p["validate_lock"](equivalent, assets)
        for value in ("[1.0.0]", "(1.0.0, )", "[1.0.0, 2.0.0)", "*"):
            altered = copy.deepcopy(lock)
            altered["dependencies"]["net8.0"]["BCnEncoder.Net"]["dependencies"]["Synthetic"] = value
            with self.assertRaises(ValueError):
                p["validate_lock"](altered, assets)
        for field, value in (("contentHash", "bad"), ("resolved", "2.4.0"), ("dependencies", {})):
            altered = copy.deepcopy(lock)
            altered["dependencies"]["net8.0"]["BCnEncoder.Net"][field] = value
            with self.assertRaises(ValueError):
                p["validate_lock"](altered, assets)
        altered = copy.deepcopy(lock)
        del altered["dependencies"]["net8.0"]["Synthetic"]
        with self.assertRaises(ValueError):
            p["validate_lock"](altered, assets)
        self.assertEqual(len(bom["components"]), 3)
        self.assertEqual(len(bom["dependencies"]), 4)
        self.assertIn("pkg:nuget/synthetic@1.0.0", [c.get("purl") for c in bom["components"]])
        bad = copy.deepcopy(assets)
        bad["libraries"]["Synthetic/1.0.0"]["sha512"] = "bad"
        with self.assertRaises(ValueError):
            p["sbom"](bad, "1" * 40)
        bad = copy.deepcopy(assets)
        del bad["targets"]["net8.0"]["Synthetic/1.0.0"]
        with self.assertRaises(ValueError):
            p["sbom"](bad, "1" * 40)


if __name__ == "__main__":
    unittest.main()

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
                            text + "\n    permissions: write-all\n",
                            text + "\n    - uses: other/action@" + "0" * 40 + "\n"):
                with self.assertRaises(ValueError):
                    p["validate_workflow"](changed)

    def test_reports(self):
        clean = {"version": 1, "sources": [source], "projects": [
            {"path": "rpf9dump.csproj", "frameworks": []}]}
        p["validate_report"](clean, "rpf9dump.csproj")
        for key in ("version", "sources", "projects"):
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
        assets = {"targets": {"net8.0": target},
                  "libraries": {k: {"type": v["type"], "sha512": digest} for k, v in target.items()},
                  "project": {"restore": {"sources": {source: {}}}, "frameworks": {"net8.0": {}}}}
        bom = p["sbom"](assets, "1" * 40)
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

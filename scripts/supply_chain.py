"""Scoped supply-chain checks; stdlib only. Run in disposable CI."""
import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SUB = "third_party/rpf9-explorer"
SUB_URL = "https://github.com/breadbbbb/rpf9-explorer"
SUB_SHA = "48557ead00601d3757ba12b894f2595c4faad2a5"
SOURCE = "https://api.nuget.org/v3/index.json"
PROJECT = "tools/rpf9dump/rpf9dump.csproj"
CORE = SUB + "/Core/RpfPreview.Core.csproj"
MANIFEST = '[submodule "' + SUB + '"]\n\tpath = ' + SUB + '\n\turl = ' + SUB_URL + '\n'
ACTIONS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/setup-dotnet": "67a3573c9a986a3f9c594539f4ab511d57bb3ce9",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def run(*args, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                            encoding="utf-8", errors="strict", timeout=300)
    return result.stdout


def candidate(sha):
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "invalid candidate SHA")
    require(run("git", "rev-parse", "HEAD").strip() == sha, "candidate mismatch")


def validate_submodule(manifest, tree, index):
    require(manifest == MANIFEST, "unreviewed submodule manifest")
    links = [line for line in tree.split("\0") if line.startswith("160000 ")]
    require(links == [f"160000 commit {SUB_SHA}\t{SUB}"], "unreviewed gitlink")
    links = [line for line in index.split("\0") if line.startswith("160000 ")]
    require(links == [f"160000 {SUB_SHA} 0\t{SUB}"], "unreviewed index gitlink")


def verify_submodule_input():
    manifest = (ROOT / ".gitmodules").read_text(encoding="utf-8")
    require(run("git", "show", "HEAD:.gitmodules").replace("\r\n", "\n") == manifest,
            "working manifest differs from commit")
    validate_submodule(manifest, run("git", "ls-tree", "-rz", "HEAD"),
                       run("git", "ls-files", "--stage", "-z"))


def verify_submodule_checkout():
    require(run("git", "rev-parse", "HEAD", cwd=ROOT / SUB).strip() == SUB_SHA,
            "submodule checkout mismatch")
    require(run("git", "config", "--local", "--get", "remote.origin.url",
                cwd=ROOT / SUB).strip() == SUB_URL, "submodule remote mismatch")
    require(not run("git", "status", "--porcelain", "--untracked-files=no", cwd=ROOT / SUB),
            "modified submodule source")


def validate_workflow(source):
    # Narrow guard for reviewed block-style YAML, not a general YAML parser.
    require(re.search(r"(?m)^permissions:\n  contents: read\n(?=\S)", source) is not None,
            "workflow must declare read-only contents")
    require(len(re.findall(r"(?m)^\s*permissions\s*:", source)) == 1, "permission override")
    require(not re.search(r"\bpull_request_target\b|\bworkflow_run\b", source),
            "unreviewed privileged trigger")
    for runner in re.findall(r"(?m)^\s*runs-on:\s*(.+)$", source):
        require(runner.strip() in ("ubuntu-24.04", "windows-2022", "windows-latest"), "unreviewed runner")
    uses = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+)", source)
    for action, sha in uses:
        require(ACTIONS.get(action) == sha, "unreviewed action: " + action)
    require(len(re.findall(r"(?m)^\s*(?:-\s*)?uses\s*:", source)) == len(uses),
            "unrecognized action syntax")
    count = source.count("uses: actions/checkout@")
    require(count and count == source.count("persist-credentials: false")
            == source.count("submodules: false"), "unsafe checkout settings")


def validate_config(path):
    root = ET.parse(path).getroot()
    require(root.tag == "configuration" and len(root) == 1, "unexpected NuGet config")
    sources = root[0]
    require(sources.tag == "packageSources" and len(sources) == 2
            and sources[0].tag == "clear" and sources[1].tag == "add"
            and sources[1].attrib == {"key": "nuget.org", "value": SOURCE},
            "unreviewed NuGet source")


def prepare(sha):
    candidate(sha)
    for path in sorted((ROOT / ".github/workflows").iterdir()):
        require(path.is_file() and path.suffix in (".yml", ".yaml"), "unexpected workflow file")
        validate_workflow(path.read_text(encoding="utf-8"))
    validate_config(ROOT / "NuGet.Config")
    verify_submodule_input()
    subprocess.run(["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                    "-c", f"submodule.{SUB}.url={SUB_URL}", "submodule", "update",
                    "--init", "--checkout", "--depth", "1", "--", SUB],
                   cwd=ROOT, check=True, timeout=180)
    verify_submodule_checkout()
    print("Supply-chain policy PASS: exact candidate, reviewed actions and submodule")


def validate_report(report, project_name):
    require(type(report.get("version")) is int and report["version"] == 1,
            "unexpected NuGet report format")
    require(report.get("sources") == [SOURCE], "unexpected audit sources")
    projects = report.get("projects")
    require(isinstance(projects, list) and len(projects) == 1, "missing audit project")
    require(str(projects[0].get("path", "")).replace("\\", "/").split("/")[-1] == project_name,
            "wrong audit project")
    require(isinstance(projects[0].get("frameworks"), list), "missing framework report")

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("problems", "vulnerabilities", "topLevelPackages", "transitivePackages"):
                    require(isinstance(value, list) and not value,
                            "NuGet audit returned findings or incomplete results")
                walk(value)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(report)


def sbom(assets, sha):
    require(set(assets["targets"]) == {"net8.0"}, "unexpected restore target")
    target = assets["targets"]["net8.0"]
    libraries = assets["libraries"]
    require(set(target) == set(libraries) and target, "incomplete restore graph")
    require(set(assets["project"]["restore"]["sources"]) == {SOURCE}, "unexpected restore sources")
    refs, components, edges = {}, [], {}
    root_ref = "leonida:rpf9dump:" + sha
    root_deps = []
    for key, node in sorted(target.items()):
        name, version = key.split("/")
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) and
                re.fullmatch(r"[A-Za-z0-9.+-]+", version), "invalid package identity")
        require(name.lower() not in refs, "ambiguous dependency")
        kind = node["type"]
        require(kind == libraries[key]["type"], "library type mismatch")
        if kind == "package":
            ref = "pkg:nuget/" + urllib.parse.quote(name.lower(), safe="") + "@" + urllib.parse.quote(version, safe="")
            digest = base64.b64decode(libraries[key]["sha512"], validate=True)
            require(len(digest) == 64, "invalid package content hash")
            component = {"type": "library", "name": name, "version": version, "bom-ref": ref,
                         "purl": ref, "hashes": [{"alg": "SHA-512", "content": digest.hex()}]}
        elif kind == "project":
            require(name == "RpfPreview.Core", "unexpected project dependency")
            ref = "leonida:rpf9-core:" + SUB_SHA
            component = {"type": "library", "name": name, "version": version, "bom-ref": ref,
                         "properties": [{"name": "leonida:git:commit", "value": SUB_SHA}]}
            root_deps.append(ref)
        else:
            raise ValueError("unknown library type")
        refs[name.lower()] = ref
        components.append(component)
        edges[ref] = node.get("dependencies", {})
    require(len(root_deps) == 1 and "bcnencoder.net" in refs, "expected dependencies missing")
    framework = assets["project"]["frameworks"]["net8.0"]
    root_deps += [refs[name.lower()] for name in framework.get("dependencies", {})]
    deps = {ref: sorted({refs[name.lower()] for name in names}) for ref, names in edges.items()}
    deps[root_ref] = sorted(set(root_deps))
    visited, pending = set(), [root_ref]
    while pending:
        ref = pending.pop()
        if ref not in visited:
            visited.add(ref)
            pending.extend(deps[ref])
    require(visited == set(deps), "unreachable dependency in restore graph")
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         "component": {"type": "application", "name": "Leonida rpf9dump",
                                       "version": sha, "bom-ref": root_ref}},
            "components": components,
            "dependencies": [{"ref": ref, "dependsOn": children} for ref, children in sorted(deps.items())]}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def audit(sha, output):
    candidate(sha)
    verify_submodule_input()
    verify_submodule_checkout()
    validate_config(ROOT / "NuGet.Config")
    for name in ("NUGET_PACKAGES", "NUGET_HTTP_CACHE_PATH"):
        require(os.environ.get(name), "isolated NuGet cache required")
        require(not Path(os.environ[name]).exists(), "NuGet cache must start empty")
    version = run("dotnet", "--version").strip()
    require(re.fullmatch(r"8\.0\.\d+", version), "unexpected SDK")
    print("Audit SDK:", version, flush=True)
    command = ["dotnet", "restore", PROJECT, "--configfile", "NuGet.Config",
               "--force", "--no-cache", "-p:NuGetAudit=true", "-p:NuGetAuditMode=all",
               "-p:NuGetAuditLevel=low", "-p:TreatWarningsAsErrors=true", "-p:NoWarn=",
               "-p:WarningsNotAsErrors=", "-p:RestoreIgnoreFailedSources=false"]
    restored = subprocess.run(command, cwd=ROOT, capture_output=True,
                              encoding="utf-8", timeout=300)
    print(restored.stdout, restored.stderr, flush=True)
    require(restored.returncode == 0 and not re.search(r"\bNU190[0-5]\b", restored.stdout + restored.stderr),
            "NuGet restore/audit failed")
    for project in (PROJECT, CORE):
        result = subprocess.run(["dotnet", "list", project, "package", "--vulnerable",
                                 "--include-transitive", "--format", "json", "--output-version", "1"],
                                cwd=ROOT, capture_output=True, encoding="utf-8", timeout=180)
        require(result.returncode == 0 and not result.stderr.strip(), "NuGet advisory query failed")
        report = json.loads(result.stdout)
        validate_report(report, Path(project).name)
    data = json.loads((ROOT / "tools/rpf9dump/obj/project.assets.json").read_text(encoding="utf-8"))
    bom = sbom(data, sha)
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "rpf9dump.cdx.json", bom)
    packages = [{"name": c["name"], "version": c["version"]} for c in bom["components"] if "purl" in c]
    write_json(output / "audit.json", {"candidate": sha, "submodule": SUB_SHA, "sdk": version,
                                     "source": SOURCE, "mode": "all", "level": "low",
                                     "restoreExitCode": restored.returncode, "advisoryReports": "passed",
                                     "packages": packages, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    print("NuGet audit PASS: direct and transitive reports; resolved CycloneDX components:")
    for package in packages:
        print(package["name"], package["version"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "audit"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.sha)
    else:
        require(args.output is not None, "audit output required")
        audit(args.sha, args.output)


if __name__ == "__main__":
    main()

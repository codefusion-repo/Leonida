"""Scoped supply-chain checks; stdlib only. Run in disposable CI."""
import argparse
import base64
import datetime
import json
import hashlib
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
LOCKS = {"rpf9dump.lock.json": "tools/rpf9dump/packages.lock.json",
         "rpf9-core.lock.json": SUB + "/Core/packages.lock.json"}
LOCK_DIR = ROOT / "dependency-locks"
MANIFEST = '[submodule "' + SUB + '"]\n\tpath = ' + SUB + '\n\turl = ' + SUB_URL + '\n'
ACTIONS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/setup-dotnet": "67a3573c9a986a3f9c594539f4ab511d57bb3ce9",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
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
    require(not run("git", "diff", "--name-only", "HEAD", cwd=ROOT / SUB),
            "modified submodule source")
    require(not any(line.startswith("160000 ") for line in
                    run("git", "ls-tree", "-rz", "HEAD", cwd=ROOT / SUB).split("\0")),
            "nested submodule not authorized")


# The sole privileged exception is an exact, reviewed, main-only job.
# This is a regression guard, not a security boundary for workflow authors.
SIGNER_JOB = "  attest:\n    if: github.event_name == 'push' && github.repository == 'codefusion-repo/Leonida' && github.ref == 'refs/heads/main' && github.ref_protected\n    needs: [check, verify_evidence]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    permissions:\n      contents: read\n      id-token: write\n      attestations: write\n    env:\n      CANDIDATE_SHA: ${{ github.sha }}\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          ref: ${{ env.CANDIDATE_SHA }}\n          persist-credentials: false\n          submodules: false\n      - name: Validate producer outputs\n        env:\n          ARTIFACT_ID: ${{ needs.check.outputs.artifact_id }}\n          MANIFEST_SHA256: ${{ needs.check.outputs.manifest_sha256 }}\n        run: python3 -I -B scripts/artifact_integrity.py validate-outputs\n      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n        with:\n          artifact-ids: ${{ needs.check.outputs.artifact_id }}\n          path: ${{ runner.temp }}/reviewed-evidence\n          merge-multiple: true\n      - name: Verify exact evidence before signing\n        env:\n          MANIFEST_SHA256: ${{ needs.check.outputs.manifest_sha256 }}\n        run: python3 -I -B scripts/artifact_integrity.py verify --directory \"$RUNNER_TEMP/reviewed-evidence\" --sha \"$CANDIDATE_SHA\" --expected-digest \"$MANIFEST_SHA256\" --signing\n      - name: Attest evidence manifest\n        uses: actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be\n        with:\n          subject-path: ${{ runner.temp }}/reviewed-evidence/manifest.json\n"
VERIFIER_JOB = "  verify_evidence:\n    needs: check\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    env:\n      CANDIDATE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          ref: ${{ env.CANDIDATE_SHA }}\n          persist-credentials: false\n          submodules: false\n      - name: Validate producer outputs\n        env:\n          ARTIFACT_ID: ${{ needs.check.outputs.artifact_id }}\n          MANIFEST_SHA256: ${{ needs.check.outputs.manifest_sha256 }}\n        run: python3 -I -B scripts/artifact_integrity.py validate-outputs\n      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n        with:\n          artifact-ids: ${{ needs.check.outputs.artifact_id }}\n          path: ${{ runner.temp }}/reviewed-evidence\n          merge-multiple: true\n      - name: Verify downloaded evidence\n        env:\n          MANIFEST_SHA256: ${{ needs.check.outputs.manifest_sha256 }}\n        run: python3 -I -B scripts/artifact_integrity.py verify --directory \"$RUNNER_TEMP/reviewed-evidence\" --sha \"$CANDIDATE_SHA\" --expected-digest \"$MANIFEST_SHA256\"\n"

def validate_workflow(source):
    if source.startswith("name: CI\n"):
        require(source.endswith(VERIFIER_JOB + SIGNER_JOB) and
                source.count("\n  attest:\n") == source.count("\n  verify_evidence:\n") == 1,
                "unreviewed signing or verification job")
        source = source[:-len(VERIFIER_JOB + SIGNER_JOB)]
        require("      artifact_id: ${{ steps.evidence.outputs.artifact-id }}\n" in source and
                "      manifest_sha256: ${{ steps.manifest.outputs.sha256 }}\n" in source,
                "missing producer identity outputs")
    require(not re.search(r"\bid-token\s*:|\battestations\s*:|actions/attest", source),
            "signing privileges outside approved job")
    # Required checks must not silently succeed by skipping a whole job.
    require(source.splitlines()[1] == "on: [push, pull_request]", "required workflows must run on every PR and push")
    require(not re.search(r"(?m)^    if\s*:", source), "required job must not be conditionally skipped")
    gate = "      - name: Reject external fork PR before checkout\n        if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository\n        shell: bash\n        run: exit 1\n"
    require(source.count(gate) == source.count("uses: actions/checkout@"),
            "missing pre-checkout external fork rejection")
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
    checkout = re.escape(ACTIONS["actions/checkout"])
    exact = r"(?m)^      - uses: actions/checkout@" + checkout + r"\n        with:\n          ref: \$\{\{ env\.CANDIDATE_SHA \}\}\n          persist-credentials: false\n          submodules: false\n(?=      -|$)"
    require(count and count == len(re.findall(exact, source)), "unsafe checkout settings")
    require(count == source.count("persist-credentials: false") == source.count("submodules: false"),
            "ambiguous checkout settings")
    require(not re.search(r"(?m)^    env:\n(?:(?:      [^\n]+)\n)*?      [^\n]*\$\{\{\s*runner\.", source),
            "runner context unavailable in job env")
    require(not re.search(r"(?m)^\s*(?:continue-on-error|secrets|container|services)\s*:", source),
            "unreviewed job execution policy")


def validate_config(path):
    root = ET.parse(path).getroot()
    require(root.tag == "configuration" and not root.attrib and len(root) == 1,
            "unexpected NuGet config")
    sources = root[0]
    require(sources.tag == "packageSources" and len(sources) == 2
            and not sources.attrib and sources[0].tag == "clear" and not sources[0].attrib
            and not len(sources[0]) and sources[1].tag == "add" and not len(sources[1])
            and sources[1].attrib == {"key": "nuget.org", "value": SOURCE},
            "unreviewed NuGet source")


def prepare(sha):
    candidate(sha)
    for path in sorted((ROOT / ".github/workflows").iterdir()):
        require(path.is_file() and path.suffix in (".yml", ".yaml"), "unexpected workflow file")
        validate_workflow(path.read_text(encoding="utf-8"))
    validate_config(ROOT / "NuGet.Config")
    verify_submodule_input()
    config = subprocess.run(["git", "config", "--get-regexp", r"^url\..*\.insteadof$"],
                            cwd=ROOT, capture_output=True, timeout=30)
    require(config.returncode == 1, "Git URL rewrite configured or config query failed")
    require(not (ROOT / SUB / ".git").exists(), "submodule must start uninitialized")
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
    # NuGet's vulnerability-only JSON omits frameworks when none contain findings.
    # The unfiltered inventory is separately checked against the actual assets.
    require(isinstance(projects[0].get("frameworks", []), list), "invalid framework report")
    parameters = report.get("parameters", "")
    require(isinstance(parameters, str) and "vulnerable" in parameters and
            "include-transitive" in parameters, "wrong advisory query mode")

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


def validate_inventory(report, assets, project_name):
    require(report.get("version") == 1 and "include-transitive" in report.get("parameters", ""),
            "unexpected inventory report")
    require(not report.get("problems"), "inventory query reported problems")
    projects = report["projects"]
    require(len(projects) == 1 and
            projects[0]["path"].replace("\\", "/").split("/")[-1] == project_name,
            "wrong inventory project")
    require(not projects[0].get("problems"), "project inventory problems")
    frameworks = projects[0]["frameworks"]
    require(len(frameworks) == 1 and frameworks[0]["framework"] == "net8.0",
            "unexpected inventory framework")
    require(not frameworks[0].get("problems"), "framework inventory problems")
    listed = {}
    for category in ("topLevelPackages", "transitivePackages"):
        for item in frameworks[0].get(category, []):
            name = item["id"].lower()
            require(name not in listed, "duplicate inventory package")
            listed[name] = item["resolvedVersion"]
    expected = {key.split("/")[0].lower(): key.split("/")[1]
                for key, value in assets["targets"]["net8.0"].items() if value["type"] == "package"}
    require(listed == expected, "inventory does not cover resolved package graph")


def verify_restore_sources(assets):
    restore = assets["project"]["restore"]
    sources = restore["sources"]
    require(isinstance(sources, dict) and set(sources) == {SOURCE},
            "unexpected restore sources: " + repr(list(sources)))
    require(not restore.get("fallbackFolders"), "unexpected fallback package folders")
    require(not assets.get("logs"), "restore graph contains diagnostic findings")


def sbom(assets, sha):
    require(assets.get("version") == 3, "unexpected assets format")
    require(not assets.get("logs"), "restore graph contains diagnostic findings")
    require(set(assets["targets"]) == {"net8.0"}, "unexpected restore target")
    target = assets["targets"]["net8.0"]
    libraries = assets["libraries"]
    require(set(target) == set(libraries) and target, "incomplete restore graph")
    verify_restore_sources(assets)
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
    require("BCnEncoder.Net/2.3.0" in target and target["BCnEncoder.Net/2.3.0"]["type"] == "package",
            "unexpected direct package resolution")
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


def canonical_range(value):
    # NuGet serializes minimum-inclusive unbounded ranges both as "1.2.3"
    # and "[1.2.3, )". Preserve all other bounds; reject unknown syntax.
    require(isinstance(value, str) and len(value) <= 128, "invalid version constraint")
    version = r"\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?"
    def norm(v):
        if not v:
            return ""
        core, sep, pre = v.partition("-")
        parts = [str(int(x)) for x in core.split(".")]
        while len(parts) < 3:
            parts.append("0")
        if len(parts) == 4 and parts[-1] == "0":
            parts.pop()
        return ".".join(parts) + (sep + pre.lower() if sep else "")
    value = value.strip()
    if re.fullmatch(version, value):
        return ("[", norm(value), "", ")")
    exact = re.fullmatch(r"\[\s*(" + version + r")\s*\]", value)
    if exact:
        v = norm(exact[1])
        return ("[", v, v, "]")
    ranged = re.fullmatch(r"([\[(])\s*(" + version + r")?\s*,\s*(" + version + r")?\s*([\])])", value)
    require(ranged is not None, "unsupported version constraint: " + value)
    lo, hi = norm(ranged[2]), norm(ranged[3])
    return (ranged[1] if lo else "(", lo, hi, ranged[4] if hi else ")")


def canonical_edges(mapping):
    result = {}
    for key, value in mapping.items():
        require(key.lower() not in result, "duplicate dependency edge")
        result[key.lower()] = canonical_range(value)
    return result


def validate_lock(lock, assets):
    require(lock.get("version") in (1, 2), "unsupported lock format")
    require(set(lock["dependencies"]) == {"net8.0"}, "unexpected lock framework")
    entries = lock["dependencies"]["net8.0"]
    graph = assets["targets"]["net8.0"]
    by_name = {key.split("/")[0].lower(): (key, node) for key, node in graph.items()}
    require(len(by_name) == len(graph), "ambiguous assets identities")
    require(len({name.lower() for name in entries}) == len(entries), "ambiguous lock identities")
    seen = set()
    for name, item in entries.items():
        key, node = by_name[name.lower()]
        if node["type"] == "project":
            require(item["type"] == "Project", "project lock mismatch")
        else:
            require(item["type"] in ("Direct", "Transitive") and
                    item["resolved"] == key.split("/")[1] and
                    item["contentHash"] == assets["libraries"][key]["sha512"],
                    "package lock mismatch")
        seen.add(name.lower())
        lock_edges = canonical_edges(item.get("dependencies", {}))
        asset_edges = canonical_edges(node.get("dependencies", {}))
        require(lock_edges == asset_edges,
                f"lock dependency edges differ for {name}: lock={lock_edges!r} assets={asset_edges!r}")
    require(seen == set(by_name), "lock omits resolved libraries")


def read_assets(project):
    return json.loads((ROOT / Path(project).parent / "obj/project.assets.json").read_text(encoding="utf-8"))


def read_locks():
    return {name: json.loads((ROOT / path).read_text(encoding="utf-8-sig")) for name, path in LOCKS.items()}


def committed_locks():
    present = [(LOCK_DIR / name).is_file() for name in LOCKS]
    require(all(present) or not any(present), "partial reviewed lock set")
    if not any(present):
        return None
    values = {}
    for name in LOCKS:
        path = "dependency-locks/" + name
        text = run("git", "show", "HEAD:" + path)
        value = json.loads(text)
        require(value == json.loads((ROOT / path).read_text(encoding="utf-8")),
                "reviewed lock differs from candidate")
        values[name] = value
    return values


def restore(locked):
    command = ["dotnet", "restore", PROJECT, "--configfile", "NuGet.Config",
               "--source", SOURCE, "-p:RestoreAdditionalProjectSources=",
               "-p:RestoreFallbackFolders=", "-p:RestoreAdditionalProjectFallbackFolders=",
               "-p:DisableImplicitNuGetFallbackFolder=true",
               "--force", "--no-cache", "--use-lock-file", "-p:NuGetAudit=true",
               "-p:NuGetAuditMode=all", "-p:NuGetAuditLevel=low", "-p:TreatWarningsAsErrors=true",
               "-p:NoWarn=", "-p:WarningsNotAsErrors=", "-p:NuGetAuditSuppress=",
               "-p:RestoreIgnoreFailedSources=false"]
    if locked:
        command.append("--locked-mode")
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                            encoding="utf-8", timeout=300)
    print(result.stdout, result.stderr, flush=True)
    require(result.returncode == 0 and not re.search(r"\bNU190[0-5]\b", result.stdout + result.stderr),
            "NuGet restore/audit failed")


def emit_evidence(path, label, value):
    write_json(path, value)
    data = path.read_bytes()
    require(len(data) <= 65536, "dependency evidence exceeds log budget")
    print(label, path.name, hashlib.sha256(data).hexdigest(),
          base64.b64encode(data).decode("ascii"), flush=True)


def audit(sha, output):
    candidate(sha)
    verify_submodule_input()
    verify_submodule_checkout()
    validate_config(ROOT / "NuGet.Config")
    caches = ("NUGET_PACKAGES", "NUGET_HTTP_CACHE_PATH")
    for name in caches:
        require(os.environ.get(name), "isolated NuGet cache required")
        require(not Path(os.environ[name]).exists(), "NuGet cache must start empty")
    version = run("dotnet", "--version").strip()
    require(re.fullmatch(r"8\.0\.4\d\d", version), "unexpected SDK")
    print("Audit SDK:", version, flush=True)
    reviewed = committed_locks()
    if reviewed:
        for name, path in LOCKS.items():
            write_json(ROOT / path, reviewed[name])
    restore(locked=reviewed is not None)
    generated = read_locks()
    # Preserve diagnostic evidence even if validation fails. Never treat this
    # first-stage material as approved or as a successful locked restore.
    raw = output.parent / "supply-chain-unreviewed"
    raw.mkdir(parents=True, exist_ok=False)
    for name, project in (("rpf9dump.lock.json", PROJECT), ("rpf9-core.lock.json", CORE)):
        assets = read_assets(project)
        emit_evidence(raw / name, "UNREVIEWED_LOCKFILE", generated[name])
        graph = {"version": assets["version"], "targets": assets["targets"],
                 "restoreSources": assets["project"]["restore"]["sources"],
                 "fallbackFolders": assets["project"]["restore"].get("fallbackFolders", []),
                 "libraries": {k: {field: v[field] for field in ("type", "sha512") if field in v}
                               for k, v in assets["libraries"].items()}}
        emit_evidence(raw / (name + ".graph.json"), "UNREVIEWED_GRAPH", graph)
    for name, project in (("rpf9dump.lock.json", PROJECT), ("rpf9-core.lock.json", CORE)):
        assets = read_assets(project)
        verify_restore_sources(assets)
        validate_lock(generated[name], assets)
    if reviewed:
        require(reviewed == generated, "reviewed lock changed")
    first = sbom(read_assets(PROJECT), sha)
    # Re-resolve against the lock with fresh caches. Do not let first restore
    # contents mask a missing or substituted package.
    for name in caches:
        os.environ[name] += "-locked"
        require(not Path(os.environ[name]).exists(), "locked cache must start empty")
    restore(locked=True)
    require(generated == read_locks(), "locked restore modified lockfiles")
    print("Locked NuGet restore PASS: fresh package and HTTP caches", flush=True)
    for name, project in (("rpf9dump.lock.json", PROJECT), ("rpf9-core.lock.json", CORE)):
        assets = read_assets(project)
        verify_restore_sources(assets)
        validate_lock(generated[name], assets)
    bom = sbom(read_assets(PROJECT), sha)
    require(first["components"] == bom["components"] and first["dependencies"] == bom["dependencies"],
            "locked restore changed resolved graph")
    reports = {}
    for project in (PROJECT, CORE):
        inventory = run("dotnet", "list", project, "package", "--include-transitive",
                        "--format", "json", "--output-version", "1")
        validate_inventory(json.loads(inventory), read_assets(project), Path(project).name)
        result = subprocess.run(["dotnet", "list", project, "package", "--vulnerable",
                                 "--include-transitive", "--config", "NuGet.Config",
                                 "--format", "json", "--output-version", "1"],
                                cwd=ROOT, capture_output=True, encoding="utf-8", timeout=180)
        require(result.returncode == 0 and not result.stderr.strip(), "NuGet advisory query failed")
        report = json.loads(result.stdout)
        # Retain actual JSON even if schema or advisory findings block approval.
        emit_evidence(raw / (Path(project).stem + ".advisories.json"), "UNREVIEWED_ADVISORY", report)
        validate_report(report, Path(project).name)
        reports[Path(project).stem] = report
    output.mkdir(parents=True, exist_ok=False)
    for name, report in reports.items():
        emit_evidence(output / (name + ".advisories.json"), "ADVISORY", report)
    emit_evidence(output / "rpf9dump.cdx.json", "SBOM", bom)
    for name, value in generated.items():
        emit_evidence(output / name, "LOCKFILE", value)
    packages = [{"name": c["name"], "version": c["version"]} for c in bom["components"] if "purl" in c]
    write_json(output / "audit.json", {"candidate": sha, "submodule": SUB_SHA, "sdk": version,
                                     "source": SOURCE, "mode": "all", "level": "low",
                                     "lockedRestore": "passed", "reviewedLocks": reviewed is not None,
                                     "advisoryReports": "passed", "packages": packages,
                                     "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    # Carry the second restore's cache path into the subsequent --no-restore build.
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as env:
            for name in caches:
                env.write(name + "=" + os.environ[name] + "\n")
    print("NuGet audit PASS: direct/transitive reports, locked restore, resolved CycloneDX components:")
    for package in packages:
        print(package["name"], package["version"])


def require_locks(sha):
    candidate(sha)
    reviewed = committed_locks()
    require(reviewed is not None, "BLOCKED: generated lockfiles require review and versioned publication")
    require(reviewed == read_locks(), "working locks differ from reviewed locks")
    print("Reviewed lockfiles PASS")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "audit", "require-locks"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.sha)
    elif args.mode == "require-locks":
        require_locks(args.sha)
    else:
        require(args.output is not None, "audit output required")
        audit(args.sha, args.output)


if __name__ == "__main__":
    main()

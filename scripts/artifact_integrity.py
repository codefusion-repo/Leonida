"""Integrity of CI dependency evidence; does not authenticate unsigned manifests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPO = "codefusion-repo/Leonida"
WORKFLOW = REPO + "/.github/workflows/ci.yml@"
SUB = "48557ead00601d3757ba12b894f2595c4faad2a5"
FILES = frozenset(("audit.json", "rpf9dump.cdx.json", "rpf9dump.lock.json",
                   "rpf9-core.lock.json", "rpf9dump.advisories.json",
                   "RpfPreview.Core.advisories.json"))
MANIFEST = "manifest.json"
MAX_BYTES = 65536


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON field")
        result[name] = value
    return result


def parse(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_read(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and
            not getattr(info, "st_file_attributes", 0) & 0x400,
            "non-regular or reparse-point evidence")
    require(0 < info.st_size <= MAX_BYTES, "evidence file size outside policy")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) == info.st_size, "evidence size changed")
    return data


def context(sha, env, signing=False):
    require(re.fullmatch(r"[a-f0-9]{40}", sha), "invalid candidate SHA")
    require(env.get("GITHUB_REPOSITORY") == REPO, "repository mismatch")
    event = env.get("GITHUB_EVENT_NAME")
    ref = env.get("GITHUB_REF", "")
    workflow = env.get("GITHUB_WORKFLOW_REF", "")
    workflow_sha = env.get("GITHUB_WORKFLOW_SHA", "")
    event_sha = env.get("GITHUB_SHA", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    require(event in ("push", "pull_request") and workflow == WORKFLOW + ref,
            "unexpected workflow identity")
    require(re.fullmatch(r"[a-f0-9]{40}", workflow_sha) and
            re.fullmatch(r"[a-f0-9]{40}", event_sha), "invalid workflow SHA")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id) and
            re.fullmatch(r"[1-9][0-9]{0,8}", attempt), "invalid run identity")
    if event == "push":
        require(ref.startswith("refs/heads/") or ref.startswith("refs/tags/"), "invalid push ref")
        require(sha == event_sha == workflow_sha, "push SHA mismatch")
    else:
        require(re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref), "invalid PR ref")
        require(workflow_sha == event_sha, "PR workflow SHA mismatch")
    if signing:
        require(event == "push" and ref == "refs/heads/main" and
                env.get("GITHUB_REF_PROTECTED") == "true", "signing requires protected main push")
    return {"repository": REPO, "candidate": sha, "event": event, "ref": ref,
            "eventSha": event_sha, "workflowRef": workflow, "workflowSha": workflow_sha,
            "runId": run_id, "runAttempt": attempt}


def validate_outputs(artifact_id, digest):
    require(isinstance(artifact_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", artifact_id),
            "expected exactly one numeric artifact ID")
    require(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest),
            "invalid producer manifest digest")


def validate_event(identity, event):
    if identity["event"] == "pull_request":
        pr = event["pull_request"]
        require(pr["head"]["sha"] == identity["candidate"] and
                pr["head"]["repo"]["full_name"] == REPO and
                pr["base"]["repo"]["full_name"] == REPO and
                str(pr["number"]) == identity["ref"].split("/")[2],
                "PR payload identity mismatch")
    else:
        require(event["after"] == identity["candidate"] and event["ref"] == identity["ref"] and
                event["repository"]["full_name"] == REPO and event.get("deleted") is False,
                "push payload identity mismatch")


def snapshot(directory, identity, with_manifest):
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and not directory.is_symlink() and
            not getattr(info, "st_file_attributes", 0) & 0x400, "invalid evidence directory")
    expected = FILES | ({MANIFEST} if with_manifest else set())
    require({p.name for p in directory.iterdir()} == expected, "missing or unexpected evidence")
    raw = {name: safe_read(directory / name) for name in FILES}
    data = {name: parse(value) for name, value in raw.items()}
    require(all(isinstance(value, dict) for value in data.values()), "expected JSON objects")
    audit = data["audit.json"]
    require(audit.get("candidate") == identity["candidate"] and audit.get("submodule") == SUB and
            audit.get("reviewedLocks") is True and audit.get("lockedRestore") == "passed" and
            audit.get("advisoryReports") == "passed" and
            audit.get("source") == "https://api.nuget.org/v3/index.json" and
            audit.get("mode") == "all" and audit.get("level") == "low",
            "audit identity or gates mismatch")
    bom = data["rpf9dump.cdx.json"]
    require(bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5" and
            bom["metadata"]["component"]["version"] == identity["candidate"],
            "SBOM identity mismatch")
    return {"schemaVersion": 1, "identity": identity,
            "files": {name: {"sha256": sha256(value), "size": len(value)}
                      for name, value in sorted(raw.items())}}


def create(directory, identity):
    manifest = snapshot(directory, identity, False)
    with (directory / MANIFEST).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")


def verify(directory, identity, expected_digest=None):
    expected = snapshot(directory, identity, True)
    raw = safe_read(directory / MANIFEST)
    actual = parse(raw)
    # Canonical serialization also rejects JSON numeric/bool type aliases
    # (Python considers True == 1) in security-critical metadata.
    require(json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True),
            "manifest identity, file size or digest mismatch")
    digest = sha256(raw)
    if expected_digest is not None:
        require(re.fullmatch(r"[a-f0-9]{64}", expected_digest) and digest == expected_digest,
                "producer manifest digest mismatch")
    return digest


def verify_semantics(directory, root):
    # Use the already reviewed S4.1 parser for the actual advisory reports.
    import runpy
    policy = runpy.run_path(str(root / "scripts/supply_chain.py"))
    for name, project in (("rpf9dump.advisories.json", "rpf9dump.csproj"),
                          ("RpfPreview.Core.advisories.json", "RpfPreview.Core.csproj")):
        policy["validate_report"](parse(safe_read(directory / name)), project)
    for name in ("rpf9dump.lock.json", "rpf9-core.lock.json"):
        require(parse(safe_read(directory / name)) ==
                parse(safe_read(root / "dependency-locks" / name)),
                "artifact lock differs from reviewed checkout")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "verify", "validate-outputs"))
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--sha")
    parser.add_argument("--expected-digest")
    parser.add_argument("--signing", action="store_true")
    args = parser.parse_args()
    if args.mode == "validate-outputs":
        validate_outputs(os.environ.get("ARTIFACT_ID"), os.environ.get("MANIFEST_SHA256"))
        print("Producer outputs PASS: single artifact ID and SHA-256")
        return
    require(args.directory is not None and args.sha is not None, "directory and SHA required")
    require(not args.signing or (args.mode == "verify" and args.expected_digest),
            "signing requires verification against producer digest")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                     text=True, timeout=30).strip()
    require(actual == args.sha, "checkout mismatch")
    identity = context(args.sha, os.environ, args.signing)
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as stream:
        validate_event(identity, json.load(stream))
    verify_semantics(args.directory, ROOT)
    if args.mode == "create":
        create(args.directory, identity)
    digest = verify(args.directory, identity, args.expected_digest)
    print("Artifact integrity PASS: six JSON files, candidate/workflow/run identity, manifest SHA-256", digest)


if __name__ == "__main__":
    main()

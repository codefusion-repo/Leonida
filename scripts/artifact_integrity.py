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
    if signing:
        require(event == "push" and ref == "refs/heads/main" and
                env.get("GITHUB_REF_PROTECTED") == "true", "signing requires protected main push")
    return {"repository": REPO, "candidate": sha, "event": event, "ref": ref,
            "eventSha": event_sha, "workflowRef": workflow, "workflowSha": workflow_sha,
            "runId": run_id, "runAttempt": attempt}


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
            audit.get("source") == "https://api.nuget.org/v3/index.json",
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


def verify(directory, identity):
    expected = snapshot(directory, identity, True)
    raw = safe_read(directory / MANIFEST)
    actual = parse(raw)
    require(actual == expected, "manifest identity, file size or digest mismatch")
    return sha256(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--signing", action="store_true")
    args = parser.parse_args()
    require(not args.signing or args.mode == "verify", "signing requires verify")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                     text=True, timeout=30).strip()
    require(actual == args.sha, "checkout mismatch")
    identity = context(args.sha, os.environ, args.signing)
    if args.mode == "create":
        create(args.directory, identity)
    digest = verify(args.directory, identity)
    print("Artifact integrity PASS: six JSON files, candidate/workflow/run identity, manifest SHA-256", digest)


if __name__ == "__main__":
    main()

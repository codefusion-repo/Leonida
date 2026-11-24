"""Collect bounded MSVC /VERBOSE:LIB provenance for additional direct imports.

Link-time evidence does not establish runtime reachability or trust.
Never execute the inspected binary. No extra dependencies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy

policy = runpy.run_path(str(Path(__file__).with_name("binary_security.py")))
read_bounded = policy["read_bounded"]
require = policy["require"]


def parse_trace(text):
    records = {}
    current = None
    for line in text.splitlines():
        value = line.strip()
        if value.startswith("Found "):
            symbol = value[6:].strip()
            require(symbol and len(symbol) <= 1024, "malformed linker symbol")
            current = {"references": [], "loaded": []}
            records.setdefault(symbol, []).append(current)
        elif value.startswith("Referenced in ") and current is not None:
            current["references"].append(value[len("Referenced in "):])
        elif value.startswith("Loaded ") and current is not None:
            current["loaded"].append(value[len("Loaded "):])
        elif value.startswith(("Searching ", "Finished searching libraries")) or not value:
            current = None
    return records


def additional_imports(cmake, direct):
    return sorted((dll, symbol) for dll, symbols in direct.items()
                  for symbol in set(symbols) - set(cmake.get(dll, [])))


def attribute(extra, records):
    results = []
    for dll, symbol in extra:
        # Named x64 imports can resolve via an __imp_ symbol or a library thunk.
        matches = []
        for spelling in ("__imp_" + symbol, symbol):
            for record in records.get(spelling, []):
                if record["references"] and record["loaded"]:
                    matches.append({"symbol": spelling, **record})
        results.append({"dll": dll, "import": symbol, "matches": matches})
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "stdout", "stderr", "evidence"):
        ap.add_argument("--" + name, type=Path, required=True)
    args = ap.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true", "runner-only collection")
    reports = {}
    report_hashes = {}
    for build in ("cmake", "direct"):
        data = read_bounded(args.evidence / (build + ".report.json"), 1048576)
        report = json.loads(data)
        identity = report["identity"]
        require(report["status"] == "PASS" and identity["candidate"] == os.environ["CANDIDATE_SHA"]
                and identity["GITHUB_RUN_ID"] == os.environ["GITHUB_RUN_ID"]
                and identity["GITHUB_RUN_ATTEMPT"] == os.environ["GITHUB_RUN_ATTEMPT"]
                and identity["build"] == build, "unexpected report identity")
        report_hashes[build] = hashlib.sha256(data).hexdigest()
        reports[build] = report
    binary_hash = hashlib.sha256(read_bounded(args.binary, policy["MAX_FILE"])).hexdigest()
    require(binary_hash == reports["direct"]["binary"]["sha256"], "link trace binary mismatch")
    streams = {key: read_bounded(getattr(args, key), 4194304) for key in ("stdout", "stderr")}
    trace = {key: data.decode("utf-8", errors="backslashreplace") for key, data in streams.items()}
    # MSVC output can use either stream; never join partial records across streams.
    records = parse_trace(trace["stdout"])
    for key, values in parse_trace(trace["stderr"]).items():
        records.setdefault(key, []).extend(values)
    extra = additional_imports(reports["cmake"]["binary"]["direct_imports"],
                               reports["direct"]["binary"]["direct_imports"])
    results = attribute(extra, records)
    missing = [f'{r["dll"]}!{r["import"]}' for r in results if not r["matches"]]
    evidence = {"status": "INCOMPLETE" if missing or not records else "PASS",
                "identity": reports["direct"]["identity"], "sha256": binary_hash,
                "report_sha256": report_hashes,
                "scope": "link-time symbol/object/library references only; runtime reachability unknown",
                "additional_imports": results, "unattributed": missing,
                "trace_sha256": {k: hashlib.sha256(v).hexdigest() for k, v in streams.items()},
                "trace": trace}
    with (args.evidence / "direct.link.json").open("x", encoding="utf-8") as out:
        json.dump(evidence, out, indent=2, sort_keys=True)
        out.write("\n")
    require(records, "no recognized linker records")
    require(not missing, "unattributed additional direct imports: " + ", ".join(missing))
    print("Native linker attribution PASS:", len(results), "additional imports")


if __name__ == "__main__":
    main()

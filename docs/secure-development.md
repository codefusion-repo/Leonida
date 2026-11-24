# Secure development and readiness gates

Status: **HOLD — not approved for execution on a personal workstation.**

Baseline inspected: `56f023a10a726da20702d4e121656ceda2391d93`. Static review only; no antivirus or behavioral analysis has been performed as part of this adoption. Matching upstream is not a trust assertion. These are proposed engineering gates, not evidence of completed work.

## Threat model and operating boundaries

Protect the developer host, credentials, repositories, game data and cloud accounts against untrusted input, malicious dependencies, arbitrary code execution, memory corruption, and unintended network or filesystem access. The Windows PE runtime, graphics drivers, external tools, dependency restore and build scripts are trust boundaries. Treat even dry-run as processing untrusted data, not as a sandbox.

Work remotely through source inspection and review first. Use only disposable, non-privileged GitHub-hosted test runners after inspecting workflow and dependencies, with minimal token permissions, no secrets and no proprietary assets. For dynamic Windows testing, use a disposable VM with no shared folders, host credentials or sensitive drives, and restricted network access. Do not disable security tools. Never execute unknown game binaries. No protection bypasses or distribution of game-derived materials.

## Ordered work units

| Unit | Outcome | Acceptance evidence |
| --- | --- | --- |
| A0 | Adopt Project OS and document controls | Pinned canonical version, ignore rules, reviewed diff |
| S1 | Harden Python input parsers | Restricted parsing, valid and invalid synthetic regression tests |
| S2 | Harden PE validation | Bounds and overflow checks, malformed fixture rejection, sanitizer/fuzz evidence where supported |
| S3 | Harden runtime and tool invocation | Safe library resolution, least privilege, documented executable-memory policy and failure paths |
| S4 | Review supply chain and CI | Pinned actions and dependencies, transitive inventory, vulnerability and secret scans, reviewed submodule |
| S5 | Harden default build and privacy | Explicit input paths, no silent downloads, output containment, reviewed external libraries |
| Q1 | Establish native test infrastructure | Reproducible CMake/CTest and Python checks, Windows runner evidence, synthetic fixtures only |
| B1 | Validate runtime compatibility with owned fixtures | Documented ABI assumptions, module/import diagnostics, lifecycle tests; fail closed on unsupported features |
| B2 | Evaluate authorized game compatibility | Only legitimately accessible inputs in isolation; documented blockers, no keys or protection circumvention |

Each unit has its own draft PR; split further when risk warrants. Do not publish exploit reproductions or sensitive vulnerability details in public PRs; coordinate private disclosure where available.

## Readiness gates

- [ ] G0 — Inspect exact candidate commit, tree, changes, submodules and relevant history; verify provenance and review all execution entry points.
- [ ] G1 — Remediate or explicitly assess all material security findings; verify regressions with real tests. Unresolved high-impact findings block execution approval.
- [ ] G2 — Audit direct and transitive dependencies, external binary provenance, CI permissions and immutable action references. Record scan scope and unresolved items.
- [ ] G3 — Run reviewed builds and synthetic tests in isolation; record exact SHA, commands, exit codes, logs sanitized of private data, and CI URLs. Include negative and malformed input tests.
- [ ] G4 — Scan candidate source and generated binaries with updated malware detection; conduct isolated behavioral testing of file, registry, process and network activity. Review unexpected behavior.
- [ ] G5 — Review candidate diff, artifacts and evidence; publish a narrowly scoped readiness decision for the exact SHA. Distinguish source inspection, isolated synthetic execution and personal-host execution. Reassess after dependency or upstream changes.

No gate is passed by this document. No release, merge, settings change or host execution is authorized by a checklist. A passing gate reduces risk but cannot guarantee absence of malware. If testing capabilities or evidence are missing, report BLOCKED for that scope rather than treating missing checks as passed.

## Evidence and continuity

Use GitHub as source of truth: link the outcome PR, candidate SHA, actual diff, checks, review findings and remaining blockers. Preserve upstream contribution rules and avoid unrelated changes. Use the Project OS browser adapter for remote work; local setup, effective ignore tests and VM execution must be verified separately when available.

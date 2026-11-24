# Supply-chain baseline (S4.1)

Scope: CI restore/build of tools/rpf9dump targeting net8.0 and repository dependency inventory. No host approval.

| Component | Reference | Trust status |
| --- | --- | --- |
| actions/checkout | 11d5960a326750d5838078e36cf38b85af677262 | official commit verified; not a full code audit |
| actions/setup-python | a26af69be951a213d495a4c3e4e4022e16d87065 | official v5 tag resolved |
| actions/setup-dotnet | 67a3573c9a986a3f9c594539f4ab511d57bb3ce9 | official v4 tag resolved |
| actions/upload-artifact | ea165f8d65b6e75b540449e92b4886f43607fa02 | official v4 tag resolved |
| rpf9-explorer | https://github.com/breadbbbb/rpf9-explorer @ 48557ead00601d3757ba12b894f2595c4faad2a5 | reviewed gitlink and manifests, no nested gitlinks observed |
| RpfPreview.Core | net8.0 | project reference, BCnEncoder.Net 2.3.0 declared |
| BCnEncoder.Net | 2.3.0 declared | resolved graph and known advisories checked by CI; no result asserted here |
| Python | 3.12 CI; numpy, Pillow, pefile in optional tools | packages not version-locked/audited |
| .NET SDK | 8.0.400 feature band, latestPatch | mutable patch version; record actual version |
| GitHub-hosted runners | windows-2022 (general), windows-latest and ubuntu-24.04 (security) | mutable images, compiler and OS dependencies |
| MSVC, CMake, Ninja, LLVM 21+, Vulkan SDK/SPIRV-Tools | external toolchain | not verified by NuGet audit |
| FFmpeg | optional PATH executable | unpinned |
| CodeWalker.Core, SharpDX, SharpDX.Mathematics | optional external assemblies | unpinned, do not run legacy tool on host |
| Three.js | 0.160.0 from jsDelivr | versioned URL, no verified integrity |
| Mesa reference header | 4fa244fddfebb21378042556862e197284ef65ac in chaotic-cx/mesa-mirror | pinned source used for swizzle CI; not package SBOM |

CI uses read-only contents permissions, disables credential persistence and recursive submodule checkout, verifies candidate SHA, checks exact manifest and gitlinks before explicitly fetching the reviewed submodule, then checks its HEAD and origin. The source policy is a narrow block-style regression guard, not a general YAML/security parser. Same-repository PR jobs only; external fork contributions require a separate trusted review route. No repository settings modified.

NuGet.Config clears other package sources. CI uses empty job-local caches and explicit restore audit settings (all dependencies, all severities, warnings as errors), then queries vulnerable package reports for both projects, including transitives. A missing/malformed report, warning, finding, unexpected source or restore failure blocks the job. CycloneDX 1.5 JSON is generated from the actual net8.0 project.assets.json graph with package identities, NuGet-reported content hashes and resolved edges; it is scoped to rpf9dump, not the entire repository or toolchain. An audit summary binds candidate and submodule SHAs and SDK version. The pinned artifact action retains outputs for 30 days. Artifact generation is not a signed attestation. No game files uploaded.

References: https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages ; https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-restore ; https://cyclonedx.org/specification/overview/

Remaining: exact resolved lockfiles and locked restore, artifact provenance, independent SBOM schema validation, advisory freshness/coverage limits, optional Python and external binaries, full third-party source review, action dependency review, branch protection and malware/behavioral analysis. Advisory absence does not establish malware absence. Host execution HOLD.

Review correction: runner-local cache paths are initialized inside a step via GITHUB_ENV, not job-level runner context. CI rejects URL rewrites, requires an initially uninitialized submodule, verifies no nested gitlinks, and checks exact checkout blocks. NuGet produces lockfiles for both projects; the audit repeats restore in locked mode using new caches and validates lock identity/version/content hash/dependency edges against resolved assets. The generated locks are published as evidence artifacts and bounded public package metadata in logs. Bootstrap deliberately fails the final reviewed-lock gate until both generated locks have been independently reviewed and committed under dependency-locks/. The submodule itself is not modified in Git. Subsequent CI installs the reviewed copies before locked restore. This is a staged trust-on-first-use process, not independent verification of publisher trust. Actual execution is required before claiming lockfile validity.

Review 03: initial restore succeeds but strict string equality of dependency constraints rejected NuGet output. The comparison now normalizes only supported version range spellings (bare minimum-inclusive versus bracketed unbounded, whitespace, numeric normalization); different bounds are still rejected. Native locked restore remains the authority for full NuGet constraint semantics. The exact original differing values were not retained by the failed runner. Initial lock and graph evidence is retained separately as UNREVIEWED, even on subsequent failure, and may not be used as approval. Final lock/SBOM evidence is emitted only after a fresh locked restore and advisory validation. The Node.js 20 deprecation warning in CI remains a follow-up for action upgrades.

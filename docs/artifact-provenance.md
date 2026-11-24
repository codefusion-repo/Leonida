# CI dependency evidence integrity and provenance (S4.2)

Scope: six existing NuGet evidence JSON files, not game assets, package binaries, runtime binaries or a release. The producer remains contents: read, performs audited locked restore, reviewed-lock gate and no-restore build before creating manifest.json. The manifest records exact file names, SHA-256 of raw bytes, sizes, candidate SHA, event SHA, repository, ref, workflow ref/SHA, run ID and attempt. JSON duplicate keys, unexpected files, non-regular files/reparse points and sizes over 64 KiB are rejected. A separate read-only job retrieves the exact immutable artifact ID from the producer in the same run and verifies the manifest against its own checkout and environment. PR head SHA and workflow/event SHA are deliberately distinct.

Only a push to protected refs/heads/main in codefusion-repo/Leonida can run the separate signing job, after both producer and verifier pass. It receives contents: read, id-token: write and attestations: write; no packages/release permissions, no personal secrets, no submodule or package restore. It downloads the same artifact ID, verifies the manifest again and attests only manifest.json with GitHub build provenance. The manifest cryptographically binds the six JSON files to the attested subject. The workflow-policy guard permits only the exact reviewed signing job; it is not an external enforcement boundary against workflow writers. Main was unprotected at baseline: signing deliberately skips until repository protection is enabled by the owner in a separate authorized operation. No settings changed. PR/push feature CI must never sign. Actual attestation can only be verified on an eligible main run after integration.

Action references verified in official repos: actions/download-artifact d3f86a106a0bac45b974a628896c90dbdf5c8093 (v4), actions/attest-build-provenance e8998f949152b193b063cb0ec769d69d929409be (v2, annotated tag peeled to commit). The latter composite pins predicate 1176ef556905f349f669722abf30bce1a6e16e01 and actions/attest ce27ba3b4a9a139d9a20a4a07d69fabb52f1e5bc. This is reference verification, not a full action implementation audit.

## Consumer verification

Obtain the expected main source SHA independently from a reviewed commit. Download the artifact from that exact successful main push run, inspect the archive before extraction, and use current GitHub CLI on an isolated verifier. The following verifies the manifest signature and provenance, not the six files by itself:

```sh
gh attestation verify manifest.json --repo codefusion-repo/Leonida \
  --signer-workflow codefusion-repo/Leonida/.github/workflows/ci.yml \
  --source-ref refs/heads/main --source-digest "$EXPECTED_SHA" \
  --deny-self-hosted-runners
```

Then check each file against the authenticated manifest: exact six names, raw byte size and SHA-256, expected candidate and workflow identity, run ID/attempt and audit gates. The CI verifier is intentionally bound to live CI environment and checkout; it is not a standalone offline verifier. Unsigned SHA-256 manifests detect accidental corruption but are not authentic against an adversary who can replace both file and manifest. Signed provenance establishes a workflow claim, not independent malware safety, reproducible binaries or publisher trust. This PR does not publish any binaries or releases. Host execution HOLD.

References: https://cli.github.com/manual/gh_attestation_verify ; https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

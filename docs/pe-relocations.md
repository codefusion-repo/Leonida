# PE base relocation policy (S2.2)

Validate the base relocation directory from immutable file bytes after PE preflight, before creating a module or mapping memory, even at the preferred base. The plan records only checked DIR64 target RVAs; ABSOLUTE entries are padding. Unsupported types, malformed block lengths, out-of-range targets, overlapping writes and writes into headers or the relocation directory are rejected. The supported subset requires page-aligned block RVAs and 4-byte block sizes. Resource limits: 16 MiB relocation directory and 1,048,576 write targets per image.

The mapper applies the plan to an exact-size image span using explicit little-endian byte access, without unaligned typed pointer writes or signed delta arithmetic. A different base requires a present relocation directory. Validation and application do not execute image code. This policy does not establish that relocated values are trustworthy pointers or that imports, exports, TLS, other directory metadata or module lifecycle are safe. Real-game compatibility remains unverified; host execution HOLD.

Tests use independently authored in-memory metadata/data, positive and negative cases and deterministic mutations. Linux CI uses ASan/UBSan; Windows compiles the runtime and runs both data-only CTest targets. No game assets or runtime execution.

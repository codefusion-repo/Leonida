# Diagnostic loader ownership (S3.2)

Each Loader owns at most one Module via unique_ptr. A local candidate owns its native allocation via a noexcept VirtualFree deleter; publication happens only after validation, diagnostics, mapping and relocation succeed. Failed calls leave the loader empty; subsequent calls after success are rejected without reading a second file. No basename cache, executable memory, IAT writes or native DLL resolution. Exports are RVA values, not callable pointers. Module views are borrowed and expire with the Loader; not thread-safe.

Default policy: 256 MiB input, 512 MiB mapped image, 768 MiB combined. Checked before file allocation and before mapping; existing PE and parser-specific limits remain applicable. These are conservative diagnostic policy limits, not a total process RSS guarantee: metadata, allocator overhead, file system and concurrent Loader instances remain outside the combined accounting. No real-game compatibility established.

Portable budget tests under ASan/UBSan and Windows data-only lifecycle tests cover rollback/retry, duplicate rejection, resource limits, non-executable page protection and release on destruction. Post-allocation exception injection and broader OS tracing remain review work. Host execution HOLD.

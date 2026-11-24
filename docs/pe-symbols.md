# PE symbol metadata (S2.3)

Parse import, delay import and export metadata from the original validated file before mapping or resolving symbols. Snapshot names, ordinal keys, export RVAs and IAT write offsets. Limit descriptors to 4096, records to 65536 per category and cumulative string bytes to 16 MiB. Strings must terminate within copied section data and use printable non-space ASCII. DLL names are restricted to simple .dll basenames. Reject forwarded exports and legacy VA-based delay import descriptors. Data exports remain supported. No game compatibility established.

The mapper binds the validated snapshot without re-reading writable PE metadata. This is not a complete DLL trust policy: native dependency loading, module lifecycle, unresolved shims, W^X and aggregate resource usage remain follow-up work. Tests are data-only and never execute images. Host execution HOLD.

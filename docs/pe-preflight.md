# PE preflight (S2.1)

The portable validator in runtime/src/pe_validation.h rejects unsupported headers and section ranges before the native mapper reserves image memory. It accepts a deliberate AMD64 PE32+ subset: 240-byte optional header, 16 directories, 1–96 sections, page-aligned sections, 512–65536-byte power-of-two file alignment, image base aligned to 64 KiB, file limit 1 GiB and image limit 2 GiB. These limits are policy, not universal PE format rules. No compatibility with proprietary images has been established. The certificate directory is range-checked as a file offset; other nonempty directories are range-checked as RVAs. Range validation does not validate their internal structures or authenticate a signature.

The mapper consumes the validated header/section layout for allocation and copying, preserving the previous copy-size rule for supported images. The validator is header-only so the existing direct MSVC build does not need another translation unit.

## Validation

Synthetic fixtures are generated in memory with metadata and zero-filled data only. Run the portable tests with a C++20 compiler and ASan/UBSan, or enable LEONIDA_PE_VALIDATION_TESTS in the Windows CMake build and use CTest. The dedicated CI workflow checks the exact candidate SHA and compiles the Windows runtime without launching it.

## Boundaries

This change does not validate nested relocation, import, delay-import, export, TLS or other directory structures. It does not harden module lifecycle, DLL resolution, memory permissions, aggregate resource usage, or the runtime's execution behavior. These remain explicit follow-up units. No host execution approval.

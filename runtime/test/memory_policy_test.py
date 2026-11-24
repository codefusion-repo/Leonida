"""Narrow source regression guard, not proof of process-wide memory safety."""
import pathlib
import re

EXECUTABLE = re.compile(r"\b(?:PAGE_EXECUTE(?:_READ|_READWRITE|_WRITECOPY)?|make_unimplemented_thunk|FlushInstructionCache)\b")
ALLOCATOR = re.compile(r"\b(?:VirtualAlloc\w*|VirtualProtect\w*|MapViewOfFile\w*|CreateFileMapping\w*|NtAllocateVirtualMemory|NtProtectVirtualMemory|WriteProcessMemory|CreateRemoteThread\w*)\s*\(")
DYNAMIC_LOAD = re.compile(r"\b(?:LoadLibrary\w*|GetProcAddress|LdrLoadDll)\s*\(")
# All explicit native memory calls are restricted to the reviewed mapper and lifecycle test.
EXPECTED = {
    "src/pe_loader.cpp": {"VirtualAlloc": 2, "VirtualProtect": 1},
    "test/loader_lifecycle_test.cpp": {"VirtualAlloc": 1},
}
# Dormant shims and GPU tools are separate targets, not diagnostic dependencies.
EXCLUDED_LOADERS = {"shims/d3d12_xs.cpp", "test/vk_harness.cpp", "test/vk_texture_test.cpp",
                    "test/vk_compute_test.cpp", "test/vk_store_test.cpp", "test/vk_pipeline_check.cpp"}

def check_source(name, source):
    if EXECUTABLE.search(source):
        raise ValueError(f"executable-memory token: {name}")
    counts = {}
    for match in ALLOCATOR.finditer(source):
        api = match.group().split("(")[0].strip()
        counts[api] = counts.get(api, 0) + 1
    if counts != EXPECTED.get(name, {}):
        raise ValueError(f"unexpected native memory call sites: {name}: {counts}")
    if DYNAMIC_LOAD.search(source) and name not in EXCLUDED_LOADERS:
        raise ValueError(f"unexpected dynamic loader: {name}")

def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    for source in ("VirtualAlloc(0, 1, 0, 0x40)", "LoadLibraryA(\"x\")", "PAGE_EXECUTE_READWRITE"):
        try:
            check_source("src/unreviewed.cpp", source)
        except ValueError:
            pass
        else:
            raise SystemExit("policy self-test failed")
    seen = set()
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in (".cpp", ".h", ".c", ".cc", ".hpp", ".inl", ".cxx", ".hxx"):
            continue
        name = path.relative_to(root).as_posix()
        check_source(name, path.read_text(encoding="utf-8"))
        seen.add(name)
    if not EXPECTED.keys() <= seen:
        raise SystemExit("reviewed memory source missing")
    print("Native source memory policy PASS: allocation call sites, loader exclusions, negative self-tests")

if __name__ == "__main__":
    main()

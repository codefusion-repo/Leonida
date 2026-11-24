// xmem.dll: the GDK's tracked allocator. Mapped onto the CRT's aligned heap and VirtualQuery.
//
// TODO: decode the XALLOC_ATTRIBUTES alignment and memory-type fields. Until that's checked against real call
// sites, every block is 64-byte aligned, which covers cache-line and SIMD alignment.
#include <windows.h>
#include <malloc.h>
#include <psapi.h>

#include <cstdint>
#include <cstring>

#include "shims.h"
#include "shim_symbols.h"

namespace {

constexpr size_t kAlign = 64;

void* __stdcall XMemAlloc(size_t size, uint64_t /*attributes*/) { return _aligned_malloc(size ? size : 1, kAlign); }

void __stdcall XMemFree(void* p, uint64_t /*attributes*/) { _aligned_free(p); }

// Same shape as VirtualQuery on the console (MEMORY_BASIC_INFORMATION out, returns bytes written).
SIZE_T __stdcall XMemVirtualQuery(const void* address, MEMORY_BASIC_INFORMATION* info, SIZE_T length) {
    return VirtualQuery(address, info, length);
}

// GDK: HRESULT XMemGetWorkingSetStatistics(XMEM_WORKING_SET_STATISTICS*). The struct's exact layout isn't known
// yet, so it's zeroed up to a conservative size and filled with the process's working set in the first field.
// Revisit once the exe's call sites show which fields are read.
long __stdcall XMemGetWorkingSetStatistics(void* stats) {
    if (!stats) return static_cast<long>(0x80070057);  // E_INVALIDARG
    std::memset(stats, 0, 32);
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        uint64_t ws = pmc.WorkingSetSize;
        std::memcpy(stats, &ws, sizeof(ws));
    }
    return 0;  // S_OK
}

}  // namespace

#define LEONIDA_CALLABLE_ENTRY(dll, name) {dll, #name, reinterpret_cast<void*>(&name)},
SHIM_TABLE(xmem, LEONIDA_XMEM_SYMBOLS(LEONIDA_CALLABLE_ENTRY));
#undef LEONIDA_CALLABLE_ENTRY

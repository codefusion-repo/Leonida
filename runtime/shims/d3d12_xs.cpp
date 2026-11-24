// d3d12_xs.dll: the Xbox Series build of D3D12. Only the free functions the bundled DLLs import are here.
//
// ASSUMPTION (verify against the exe's call sites): root-signature descriptions and blobs have the same layout as
// desktop D3D12, so these forward to the PC d3d12.dll. Device/command-list interfaces are a separate, much larger
// job (Xbox-only methods, placement and ESRAM-era extensions) and aren't shimmed here.
#include <windows.h>

#include <cstdio>

#include "shims.h"
#include "shim_symbols.h"

namespace {

FARPROC host(const char* name) {
    static HMODULE d3d12 = LoadLibraryExA("d3d12.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    FARPROC p = d3d12 ? GetProcAddress(d3d12, name) : nullptr;
    if (!p) std::fprintf(stderr, "[rt] d3d12_xs: host d3d12.dll has no %s\n", name);
    return p;
}

using SerializeFn = HRESULT(WINAPI*)(const void*, void**, void**);
using DeserializerFn = HRESULT(WINAPI*)(const void*, SIZE_T, const GUID*, void**);

HRESULT WINAPI D3D12SerializeVersionedRootSignature(const void* desc, void** blob, void** error) {
    static auto fn = reinterpret_cast<SerializeFn>(host("D3D12SerializeVersionedRootSignature"));
    return fn ? fn(desc, blob, error) : E_NOTIMPL;
}

HRESULT WINAPI D3D12CreateRootSignatureDeserializer(const void* data, SIZE_T size, const GUID* iid, void** out) {
    static auto fn = reinterpret_cast<DeserializerFn>(host("D3D12CreateRootSignatureDeserializer"));
    return fn ? fn(data, size, iid, out) : E_NOTIMPL;
}

}  // namespace

#define LEONIDA_CALLABLE_ENTRY(dll, name) {dll, #name, reinterpret_cast<void*>(&name)},
SHIM_TABLE(d3d12_xs, LEONIDA_D3D12_XS_SYMBOLS(LEONIDA_CALLABLE_ENTRY));
#undef LEONIDA_CALLABLE_ENTRY

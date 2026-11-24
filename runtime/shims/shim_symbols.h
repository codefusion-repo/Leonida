#pragma once

// Single source of symbol names for diagnostic coverage and future callable shims.
// X receives (DLL basename, C++ function identifier).
#define LEONIDA_XMEM_SYMBOLS(X) \
    X("xmem.dll", XMemAlloc) \
    X("xmem.dll", XMemFree) \
    X("xmem.dll", XMemVirtualQuery) \
    X("xmem.dll", XMemGetWorkingSetStatistics)

#define LEONIDA_D3D12_XS_SYMBOLS(X) \
    X("d3d12_xs.dll", D3D12SerializeVersionedRootSignature) \
    X("d3d12_xs.dll", D3D12CreateRootSignatureDeserializer)

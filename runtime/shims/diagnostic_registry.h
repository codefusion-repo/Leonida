#pragma once
#include "shim_symbols.h"
#include <string_view>

namespace rt::shims {
struct DiagnosticSymbol { std::string_view dll, name; };
#define LEONIDA_DIAGNOSTIC_ENTRY(dll, name) {dll, #name},
inline constexpr DiagnosticSymbol diagnostic_symbols[] = {
    LEONIDA_XMEM_SYMBOLS(LEONIDA_DIAGNOSTIC_ENTRY)
    LEONIDA_D3D12_XS_SYMBOLS(LEONIDA_DIAGNOSTIC_ENTRY)
};
#undef LEONIDA_DIAGNOSTIC_ENTRY

inline bool registered(std::string_view dll, std::string_view name) {
    for (const auto& entry : diagnostic_symbols)
        if (entry.dll == dll && entry.name == name) return true;
    return false;
}
} // namespace rt::shims

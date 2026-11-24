#pragma once
#include <windows.h>
#include <stdexcept>

namespace rt {
// Process-wide policy for the standalone diagnostic executable only.
// Apply before reading any image, and never permit opt-out or downgrade.
inline void prohibit_dynamic_code() {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY requested{};
    requested.ProhibitDynamicCode = 1;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &requested, sizeof(requested)))
        throw std::runtime_error("cannot enable diagnostic dynamic-code mitigation");
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY actual{};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &actual, sizeof(actual)) ||
        !actual.ProhibitDynamicCode || actual.AllowThreadOptOut || actual.AllowRemoteDowngrade)
        throw std::runtime_error("diagnostic dynamic-code mitigation not enforced");
}
}

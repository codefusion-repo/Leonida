#include "../src/dll_policy.h"
#include "../shims/diagnostic_registry.h"
#include <iostream>
#include <vector>
int main() {
    try {
        int queries = 0;
        auto registry = [&](std::string_view dll, std::string_view symbol) {
            ++queries;
            return dll == "known.dll" && symbol == "Example";
        };
        auto known = rt::dll::classify("KNOWN.DLL", "Example", registry);
        if (!known.registered || known.key != "known.dll" || known.symbol != "Example") return 1;
        for (const auto* name : {"kernel32.dll", "unknown.dll", "api-ms-win-core-file-l1-1-0.dll"})
            if (rt::dll::classify(name, "#7", registry).registered) return 2;
        if (queries != 4) return 3;
        const std::vector<std::string> invalid = {
            "../a.dll", "C:a.dll", "a/b.dll", "a\\b.dll", "a.dll ", "a..dll",
            "CON.dll", "NUL.extra.dll", "LPT1.dll", "COM0.dll", "PRN.dll", ".a.dll",
            "a.exe", "a.dll:stream", std::string("a\0.dll", 6), std::string(256, 'x') + ".dll"
        };
        for (const auto& name : invalid) {
            bool rejected = false;
            try { (void)rt::dll::classify(name, "Example", registry); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected) return 4;
        }
        for (const auto* symbol : {"", "#0", "#01", "#65536", "#-1", "#x", "a b", "a\n"}) {
            bool rejected = false;
            try { (void)rt::dll::classify("known.dll", symbol, registry); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected) return 5;
        }
        if (queries != 4) return 5;
        for (const auto& entry : rt::shims::diagnostic_symbols)
            if (!rt::dll::classify(entry.dll, entry.name, rt::shims::registered).registered) return 7;
        if (rt::dll::classify("kernel32.dll", "GetCurrentProcess", rt::shims::registered).registered ||
            rt::dll::classify("xmem.dll", "xmemalloc", rt::shims::registered).registered ||
            rt::dll::classify("xmem.dll", "#65535", rt::shims::registered).registered) return 8;
        std::cout << "DLL diagnostic policy PASS: static registry only, invalid basenames rejected\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 6; }
}

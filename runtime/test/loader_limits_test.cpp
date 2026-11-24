#include "../src/loader_limits.h"
#include <iostream>
#include <limits>
#include <utility>
int main() {
    rt::Limits l{10, 20, 25};
    l.check(10, 15);
    l.check(5, 20);
    for (auto [f,i] : {std::pair<uint64_t,uint64_t>{11,0}, {0,21}, {10,16}, {UINT64_MAX,1}}) {
        bool rejected = false;
        try { l.check(f,i); } catch (const std::runtime_error&) { rejected = true; }
        if (!rejected) return 1;
    }
    rt::Limits overflow{UINT64_MAX, UINT64_MAX, UINT64_MAX};
    try { overflow.check(UINT64_MAX, 1); return 2; } catch (const std::runtime_error&) {}
    std::cout << "Loader budget PASS\n";
}

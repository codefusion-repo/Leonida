#include "../src/loader_limits.h"
#include <iostream>
#include <limits>
#include <utility>
int main() {
    rt::Limits{}.validate_policy();
    rt::Limits l{10, 20, 25};
    l.validate_policy();
    for (const auto invalid : {rt::Limits{0, 20, 25}, rt::Limits{10, 0, 25},
                               rt::Limits{10, 20, 0}, rt::Limits{rt::Limits::max_file + 1, 20, 25},
                               rt::Limits{10, rt::Limits::max_image + 1, 25},
                               rt::Limits{10, 20, rt::Limits::max_combined + 1}}) {
        bool rejected = false;
        try { invalid.validate_policy(); } catch (const std::runtime_error&) { rejected = true; }
        if (!rejected) return 3;
    }
    l.check(10, 15);
    l.check(5, 20);
    l.check(0, 0);
    rt::Limits{}.check(rt::Limits::max_file, rt::Limits::max_image);
    for (auto [f,i] : {std::pair<uint64_t,uint64_t>{11,0}, {0,21}, {10,16}, {UINT64_MAX,1}}) {
        bool rejected = false;
        try { l.check(f,i); } catch (const std::runtime_error&) { rejected = true; }
        if (!rejected) return 1;
    }
    rt::Limits overflow{UINT64_MAX, UINT64_MAX, UINT64_MAX};
    try { overflow.check(UINT64_MAX, 1); return 2; } catch (const std::runtime_error&) {}
    std::cout << "Loader budget PASS\n";
}

#include "../src/pe_relocations.h"
#include <iostream>
#include <random>
#include <string>

namespace {
using Bytes = std::vector<uint8_t>;
constexpr uint64_t preferred = 0x140000000ull;

void put(Bytes& b, size_t pos, uint64_t value, unsigned width = 4) {
    for (unsigned i = 0; i < width; ++i) b.at(pos + i) = static_cast<uint8_t>(value >> (8 * i));
}
void check(bool ok, const char* message) { if (!ok) throw std::logic_error(message); }
template<class F> void reject(F f) {
    try { f(); } catch (const std::runtime_error&) { return; }
    throw std::logic_error("unexpected acceptance");
}
rt::pe::Layout layout() {
    rt::pe::Layout l{};
    l.image_base = preferred; l.image_size = 0x3000; l.headers_size = 0x200;
    l.sections = {{0x1000, 0x200, 0x200, 0x200, 0x40000040},
                  {0x2000, 0x200, 0x400, 0x200, 0x40000040}};
    l.directories[5] = {0x2000, 12};
    return l;
}
Bytes fixture() {
    Bytes b(0x600);
    put(b, 0x400, 0x1000); put(b, 0x404, 12);
    put(b, 0x408, 0xa010, 2); put(b, 0x40a, 0, 2);
    return b;
}
}

int main() {
    try {
        auto l = layout(); const auto good = fixture();
        const auto plan = rt::pe::plan_relocations(good, l);
        check(plan.present() && plan.size() == 1, "plan mismatch");
        Bytes image(l.image_size); put(image, 0x1010, preferred + 0x123, 8);
        const auto original = image;
        for (const uint64_t actual : {preferred, preferred + 0x10000, preferred - 0x10000}) {
            image = original; plan.apply(image, preferred, actual);
            auto expected = original; put(expected, 0x1010, actual + 0x123, 8);
            check(image == expected, "incorrect rebase or unrelated write");
        }
        Bytes wrong(8); const auto before = wrong;
        reject([&] { plan.apply(wrong, preferred, preferred + 0x10000); });
        check(wrong == before, "modified invalid buffer");
        auto absent = l; absent.directories[5] = {};
        auto none = rt::pe::plan_relocations(good, absent);
        image = original; none.apply(image, preferred, preferred);
        reject([&] { none.apply(image, preferred, preferred + 0x10000); });
        check(image == original, "missing directory modified image");
        auto bad = [&](size_t offset, uint64_t value, unsigned width = 4) {
            auto b = good; put(b, offset, value, width);
            reject([&] { (void)rt::pe::plan_relocations(b, l); });
        };
        bad(0x404, 0); bad(0x404, 4); bad(0x404, 10); bad(0x404, 16);
        bad(0x400, 0x1001); bad(0x400, 0x3000);
        bad(0x408, 0x3010, 2); bad(0x408, 0xa1fc, 2);
        bad(0x40a, 0xa010, 2); bad(0x40a, 0xa014, 2);
        auto b = good; put(b, 0x400, 0x2000); put(b, 0x408, 0xa000, 2);
        reject([&] { (void)rt::pe::plan_relocations(b, l); });
        auto truncated = good; truncated.resize(0x40b);
        reject([&] { (void)rt::pe::plan_relocations(truncated, l); });
        auto invalid = l; invalid.directories[5].size = 16u * 1024u * 1024u + 1;
        reject([&] { (void)rt::pe::plan_relocations(good, invalid); });
        // Explicitly test unaligned DIR64 data access and unsigned wrap.
        b = good; put(b, 0x408, 0xa011, 2);
        auto unaligned = rt::pe::plan_relocations(b, l);
        image.assign(l.image_size, 0); put(image, 0x1011, UINT64_MAX, 8);
        unaligned.apply(image, preferred, preferred + 1);
        check(rt::pe::read_le(image, 0x1011, 8) == 0, "unsigned relocation wrap mismatch");
        // Multiple blocks and padding-only blocks.
        b = good; put(b, 0x40c, 0x1000); put(b, 0x410, 12);
        put(b, 0x414, 0xa020, 2); auto multiple = l; multiple.directories[5].size = 24;
        check(rt::pe::plan_relocations(b, multiple).size() == 2, "multiple blocks");
        b = good; put(b, 0x408, 0, 2);
        check(rt::pe::plan_relocations(b, l).size() == 0, "padding block");
        std::mt19937 rng(0x5232u);
        for (unsigned i = 0; i < 10000; ++i) {
            b = good;
            for (unsigned j = 0; j < 3; ++j) b[0x400 + rng() % 12] = static_cast<uint8_t>(rng());
            try {
                const auto candidate = rt::pe::plan_relocations(b, l);
                image = original; candidate.apply(image, preferred, preferred + 0x10000);
            } catch (const std::runtime_error&) {}
        }
        std::cout << "PE relocations PASS: synthetic fixtures, 10000 mutations\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}

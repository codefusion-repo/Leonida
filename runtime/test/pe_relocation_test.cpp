#include "../src/pe_relocations.h"
#include <iostream>
#include <random>
#include <string>
#include <type_traits>

namespace {
using Bytes = std::vector<uint8_t>;
constexpr uint64_t preferred = 0x140000000ull;
constexpr size_t nt = 0x80, opt = nt + 24, sec = opt + 240, dir = opt + 112 + 5 * 8;
static_assert(!std::is_copy_constructible_v<rt::pe::RelocationPlan>);
static_assert(!std::is_move_constructible_v<rt::pe::RelocationPlan>);

void put(Bytes& b, size_t pos, uint64_t value, unsigned width = 4) {
    for (unsigned i = 0; i < width; ++i) b.at(pos + i) = static_cast<uint8_t>(value >> (8 * i));
}
void check(bool ok, const char* message) { if (!ok) throw std::logic_error(message); }
template<class F> void reject(F f) {
    try { f(); } catch (const std::runtime_error&) { return; }
    throw std::logic_error("unexpected acceptance");
}
Bytes fixture() {
    Bytes b(0x600);
    put(b, 0, 0x5a4d, 2); put(b, 0x3c, nt);
    put(b, nt, 0x4550); put(b, nt + 4, 0x8664, 2); put(b, nt + 6, 2, 2);
    put(b, nt + 20, 240, 2); put(b, nt + 22, 2, 2); put(b, opt, 0x20b, 2);
    put(b, opt + 24, preferred, 8); put(b, opt + 32, 0x1000); put(b, opt + 36, 0x200);
    put(b, opt + 56, 0x3000); put(b, opt + 60, 0x200); put(b, opt + 108, 16);
    put(b, dir, 0x2000); put(b, dir + 4, 12);
    for (unsigned i = 0; i < 2; ++i) {
        const auto p = sec + i * 40;
        put(b, p + 8, 0x200); put(b, p + 12, 0x1000 * (i + 1));
        put(b, p + 16, 0x200); put(b, p + 20, 0x200 * (i + 1)); put(b, p + 36, 0x40000040);
    }
    put(b, 0x210, preferred + 0x123, 8);
    put(b, 0x400, 0x1000); put(b, 0x404, 12); put(b, 0x408, 0xa010, 2);
    return b;
}
// Data-only copy of the mapper's validated layout; no native allocation or execution.
Bytes copy_image(const Bytes& file) {
    const auto l = rt::pe::validate(file);
    Bytes image(l.image_size);
    std::copy_n(file.begin(), l.headers_size, image.begin());
    for (const auto& s : l.sections)
        if (s.copy_size()) std::copy_n(file.begin() + s.raw_offset, s.copy_size(), image.begin() + s.rva);
    return image;
}
}

int main() {
    try {
        const auto good = fixture();
        const auto plan = rt::pe::plan_relocations(good);
        check(plan.present() && plan.size() == 1, "plan mismatch");
        const auto original = copy_image(good);
        auto image = original;
        for (const uint64_t actual : {preferred, preferred + 0x10000, preferred - 0x10000}) {
            image = original; plan.apply(image, actual);
            auto expected = original; put(expected, 0x1010, actual + 0x123, 8);
            check(image == expected, "incorrect rebase or unrelated write");
        }
        Bytes wrong(8); const auto before = wrong;
        reject([&] { plan.apply(wrong, preferred + 0x10000); });
        check(wrong == before, "modified invalid buffer");
        image = original;
        for (const uint64_t actual : {uint64_t(0), preferred + 1, uint64_t(0x800000000000ull)}) {
            reject([&] { plan.apply(image, actual); });
            check(image == original, "invalid base modified image");
        }
        auto absent = good; put(absent, dir, 0); put(absent, dir + 4, 0); put(absent, nt + 22, 3, 2);
        const auto none = rt::pe::plan_relocations(absent);
        image = copy_image(absent); const auto absent_image = image;
        none.apply(image, preferred); reject([&] { none.apply(image, preferred + 0x10000); });
        check(image == absent_image, "missing directory modified image");
        auto bad = [&](size_t offset, uint64_t value, unsigned width = 4) {
            auto b = good; put(b, offset, value, width);
            reject([&] { (void)rt::pe::plan_relocations(b); });
        };
        bad(0, 0, 2); bad(nt + 22, 3, 2); bad(dir + 4, 0);
        bad(0x404, 0); bad(0x404, 4); bad(0x404, 10); bad(0x404, 16);
        bad(0x400, 0x1001); bad(0x400, 0x3000);
        bad(0x400, 0); bad(0x408, 0x3010, 2); bad(0x408, 0xa1fc, 2);
        bad(0x40a, 0xa010, 2); bad(0x40a, 0xa014, 2);
        auto b = good; put(b, 0x400, 0x2000); put(b, 0x408, 0xa000, 2);
        reject([&] { (void)rt::pe::plan_relocations(b); });
        b = good; b.resize(0x5ff); reject([&] { (void)rt::pe::plan_relocations(b); });
        b = good; put(b, dir + 4, 16); reject([&] { (void)rt::pe::plan_relocations(b); });
        // Unaligned DIR64 data and modulo-2^64 addition with an aligned base delta.
        b = good; put(b, 0x408, 0xa011, 2); put(b, 0x211, UINT64_MAX - 0xffff, 8);
        const auto unaligned = rt::pe::plan_relocations(b);
        image = copy_image(b); unaligned.apply(image, preferred + 0x10000);
        check(rt::pe::read_le(image, 0x1011, 8) == 0, "unsigned relocation wrap mismatch");
        b = good; put(b, 0x40c, 0x1000); put(b, 0x410, 12);
        put(b, 0x414, 0xa020, 2); put(b, dir + 4, 24);
        const auto multiple = rt::pe::plan_relocations(b);
        check(multiple.size() == 2, "multiple blocks");
        put(b, 0x414, 0xa010, 2); reject([&] { (void)rt::pe::plan_relocations(b); });
        b = good; put(b, 0x408, 0, 2);
        check(rt::pe::plan_relocations(b).size() == 0, "padding block");
        // The plan owns its checked offsets; altering input after planning cannot change them.
        b = good; const auto saved = rt::pe::plan_relocations(b);
        std::fill(b.begin() + 0x400, b.end(), 0xff);
        image = original; saved.apply(image, preferred + 0x10000);
        auto expected = original; put(expected, 0x1010, preferred + 0x10123, 8);
        check(image == expected, "plan depends on mutable input");
        std::mt19937 rng(0x5232u);
        for (unsigned i = 0; i < 10000; ++i) {
            b = good;
            for (unsigned j = 0; j < 3; ++j) b[0x400 + rng() % 12] = static_cast<uint8_t>(rng());
            try {
                const auto candidate = rt::pe::plan_relocations(b);
                image = copy_image(b); const auto initial = image;
                candidate.apply(image, preferred);
                check(image == initial, "preferred base changed image");
                candidate.apply(image, preferred + 0x10000);
                check(std::equal(image.begin(), image.begin() + 0x200, initial.begin()), "headers changed");
                check(std::equal(image.begin() + 0x2000, image.begin() + 0x200c, initial.begin() + 0x2000), "relocation metadata changed");
            } catch (const std::runtime_error&) {}
        }
        std::cout << "PE relocations PASS: full PE fixtures, 10000 mutations\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}

#include "../src/pe_validation.h"

#include <iostream>
#include <random>
#include <string_view>

namespace {
using Bytes = std::vector<uint8_t>;
constexpr size_t nt = 0x80, opt = nt + 24, sec = opt + 240;

void put(Bytes& data, size_t offset, uint64_t value, unsigned width = 4) {
    for (unsigned i = 0; i < width; ++i)
        data.at(offset + i) = static_cast<uint8_t>(value >> (8 * i));
}

// Independently authored metadata and zero-filled data only; never executed.
Bytes fixture() {
    Bytes b(0x400);
    put(b, 0, 0x5a4d, 2); put(b, 0x3c, nt);
    put(b, nt, 0x4550); put(b, nt + 4, 0x8664, 2); put(b, nt + 6, 1, 2);
    put(b, nt + 20, 240, 2); put(b, opt, 0x20b, 2);
    put(b, opt + 24, 0x140000000ull, 8);
    put(b, opt + 32, 0x1000); put(b, opt + 36, 0x200);
    put(b, opt + 56, 0x2000); put(b, opt + 60, 0x200); put(b, opt + 108, 16);
    put(b, sec + 8, 0x180); put(b, sec + 12, 0x1000);
    put(b, sec + 16, 0x200); put(b, sec + 20, 0x200); put(b, sec + 36, 0x40000040);
    return b;
}

void check(bool condition, std::string_view label) {
    if (!condition) throw std::logic_error(std::string(label));
}

void reject(const Bytes& b, std::string_view label) {
    try { (void)rt::pe::validate(b); }
    catch (const std::runtime_error&) { return; }
    throw std::logic_error("accepted invalid PE: " + std::string(label));
}

void field(size_t offset, uint64_t value, std::string_view label, unsigned width = 4) {
    auto b = fixture(); put(b, offset, value, width); reject(b, label);
}

Bytes two_sections() {
    auto b = fixture();
    put(b, nt + 6, 2, 2); put(b, opt + 56, 0x3000);
    put(b, sec + 40 + 8, 0x300); put(b, sec + 40 + 12, 0x2000);
    put(b, sec + 40 + 36, 0xc0000080);
    return b;
}
}  // namespace

int main() {
    try {
        const auto good = fixture();
        auto layout = rt::pe::validate(good);
        check(layout.image_base == 0x140000000ull && layout.image_size == 0x2000 &&
              layout.headers_size == 0x200 && layout.sections.size() == 1 &&
              layout.sections[0].copy_size() == 0x180, "valid layout mismatch");
        auto b = two_sections();
        check(rt::pe::validate(b).sections[1].copy_size() == 0, "valid zero-fill section rejected");
        b = fixture(); put(b, opt + 16, 0x1000); put(b, sec + 36, 0x60000020);
        check(rt::pe::validate(b).entry_rva == 0x1000, "valid entry metadata rejected");
        b = fixture(); put(b, opt + 112 + 4 * 8, 0x300); put(b, opt + 116 + 4 * 8, 0x10);
        check(rt::pe::validate(b).directories[4].rva == 0x300, "certificate offset rejected");
        for (size_t size = 0; size < good.size(); ++size)
            reject(Bytes(good.begin(), good.begin() + static_cast<Bytes::difference_type>(size)), "truncation");
        field(0, 0, "DOS signature", 2); field(0x3c, 0xffffffff, "PE offset");
        field(0x3c, nt + 1, "unaligned PE offset"); field(nt, 0, "PE signature");
        field(nt + 4, 0x14c, "machine", 2); field(nt + 6, 0, "zero sections", 2);
        field(nt + 6, 97, "excess sections", 2); field(nt + 20, 112, "optional size", 2);
        field(opt, 0x10b, "optional magic", 2); field(opt + 108, 15, "directory count");
        field(opt + 32, 0, "section alignment"); field(opt + 36, 3, "file alignment");
        field(opt + 56, 0xffffffff, "image limit"); field(opt + 56, 0, "empty image");
        field(opt + 60, 0x4000, "headers beyond file"); field(opt + 60, 0, "empty headers");
        field(opt + 24, 0x800000000000ull, "base outside user address space", 8);
        field(sec + 12, 0, "section overlaps headers"); field(sec + 12, 0x1001, "section alignment");
        field(sec + 8, 0xffffffff, "virtual range"); field(sec + 20, 0xfffffe00, "raw range");
        field(sec + 20, 0, "raw overlaps headers"); field(sec + 16, 0x400, "truncated raw data");
        field(opt + 16, 0x1000, "non-executable entry"); field(opt + 16, 0x4000, "entry outside image");
        b = two_sections(); put(b, sec + 40 + 12, 0x1000); reject(b, "overlapping virtual sections");
        b = two_sections(); put(b, sec + 40 + 16, 0x200); put(b, sec + 40 + 20, 0x200); reject(b, "overlapping raw sections");
        b = fixture(); put(b, opt + 112, 0x1ff0); put(b, opt + 116, 0x20); reject(b, "directory outside image");
        b = fixture(); put(b, opt + 112 + 4 * 8, 0x3f0); put(b, opt + 116 + 4 * 8, 0x20); reject(b, "certificate outside file");
        // Deterministic bounded mutation smoke test; ASan/UBSan check the parser, not the Windows loader.
        std::mt19937 rng(0x5342u);
        for (unsigned i = 0; i < 10000; ++i) {
            b = good;
            for (unsigned j = 0; j < 4; ++j) b[rng() % b.size()] = static_cast<uint8_t>(rng());
            try { (void)rt::pe::validate(b); } catch (const std::runtime_error&) {}
        }
        std::cout << "PE validation PASS: positive/negative fixtures, 1024 truncations, 10000 mutations\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}

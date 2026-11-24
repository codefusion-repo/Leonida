#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace rt::pe {

// Deliberately support the loader's AMD64/PE32+ subset, not every legal PE variant.
inline constexpr uint64_t max_file_bytes = 1ull << 30;
inline constexpr uint64_t max_image_bytes = 2ull << 30;

struct Directory {
    uint32_t rva, size;
};

struct Section {
    uint32_t rva, virtual_size, raw_offset, raw_size;
    uint32_t characteristics;
    uint32_t copy_size() const {
        return std::min(raw_size, virtual_size ? virtual_size : raw_size);
    }
    uint64_t extent() const { return std::max(virtual_size, raw_size); }
};

struct Layout {
    uint64_t image_base;
    uint32_t image_size, headers_size, entry_rva;
    std::array<Directory, 16> directories{};
    std::vector<Section> sections;
};

inline bool contains(uint64_t total, uint64_t offset, uint64_t size) {
    return offset <= total && size <= total - offset;
}

inline bool power_of_two(uint32_t value) {
    return value && !(value & (value - 1));
}

inline bool overlaps(uint64_t a, uint64_t an, uint64_t b, uint64_t bn) {
    // All ranges are bounded before this helper is called.
    return an && bn && a < b + bn && b < a + an;
}

inline void require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}

inline uint64_t read_le(std::span<const uint8_t> bytes, uint64_t offset, unsigned width) {
    require(width <= 8 && contains(bytes.size(), offset, width), "truncated PE field");
    uint64_t result = 0;
    for (unsigned i = 0; i < width; ++i)
        result |= uint64_t(bytes[static_cast<size_t>(offset + i)]) << (8 * i);
    return result;
}

inline Layout validate(std::span<const uint8_t> bytes) {
    constexpr uint64_t dos_size = 64, nt_prefix = 24, optional_size = 240, section_size = 40;
    require(bytes.size() >= dos_size && bytes.size() <= max_file_bytes, "invalid PE file size");
    require(read_le(bytes, 0, 2) == 0x5a4d, "invalid DOS signature");
    const uint64_t nt = read_le(bytes, 0x3c, 4);
    require(nt >= dos_size && nt % 8 == 0 && contains(bytes.size(), nt, nt_prefix + optional_size),
            "invalid PE header offset");
    require(read_le(bytes, nt, 4) == 0x4550 && read_le(bytes, nt + 4, 2) == 0x8664,
            "not an AMD64 PE image");
    const uint64_t characteristics = read_le(bytes, nt + 22, 2);
    require(characteristics & 0x0002u, "PE is not an executable image");
    const uint64_t count = read_le(bytes, nt + 6, 2);
    require(count >= 1 && count <= 96, "unsupported PE section count");
    require(read_le(bytes, nt + 20, 2) == optional_size, "unsupported PE optional header size");
    const uint64_t opt = nt + nt_prefix;
    require(read_le(bytes, opt, 2) == 0x20b && read_le(bytes, opt + 108, 4) == 16,
            "unsupported PE32+ optional header or directory count");
    const uint64_t table = opt + optional_size;
    require(contains(bytes.size(), table, count * section_size), "truncated PE section table");

    Layout result{};
    result.entry_rva = static_cast<uint32_t>(read_le(bytes, opt + 16, 4));
    result.image_base = read_le(bytes, opt + 24, 8);
    const auto section_align = static_cast<uint32_t>(read_le(bytes, opt + 32, 4));
    const auto file_align = static_cast<uint32_t>(read_le(bytes, opt + 36, 4));
    result.image_size = static_cast<uint32_t>(read_le(bytes, opt + 56, 4));
    result.headers_size = static_cast<uint32_t>(read_le(bytes, opt + 60, 4));
    require(power_of_two(file_align) && file_align >= 512 && file_align <= 65536 &&
            power_of_two(section_align) && section_align >= 4096 && section_align >= file_align,
            "unsupported PE alignment");
    require(result.image_size && result.image_size <= max_image_bytes && result.image_size % section_align == 0,
            "invalid PE image size");
    require(result.headers_size && result.headers_size % file_align == 0 &&
            contains(bytes.size(), 0, result.headers_size) &&
            contains(result.image_size, 0, result.headers_size) &&
            contains(result.headers_size, table, count * section_size), "invalid PE header size");
    require(result.image_base && result.image_base % 65536 == 0 &&
            contains(0x0000800000000000ull, result.image_base, result.image_size), "invalid PE image base");

    const uint64_t first_rva = (uint64_t(result.headers_size) + section_align - 1) & ~(uint64_t(section_align) - 1);
    bool entry_valid = result.entry_rva == 0;
    uint64_t raw_end = result.headers_size;
    for (uint64_t i = 0; i < count; ++i) {
        const auto pos = table + i * section_size;
        Section s{static_cast<uint32_t>(read_le(bytes, pos + 12, 4)),
                  static_cast<uint32_t>(read_le(bytes, pos + 8, 4)),
                  static_cast<uint32_t>(read_le(bytes, pos + 20, 4)),
                  static_cast<uint32_t>(read_le(bytes, pos + 16, 4)),
                  static_cast<uint32_t>(read_le(bytes, pos + 36, 4))};
        require(s.extent() && s.rva >= first_rva && s.rva % section_align == 0 &&
                contains(result.image_size, s.rva, s.extent()), "invalid PE virtual section range");
        if (s.raw_size) {
            require(s.raw_offset >= result.headers_size && s.raw_offset % file_align == 0 &&
                    s.raw_size % file_align == 0 && contains(bytes.size(), s.raw_offset, s.raw_size),
                    "invalid PE raw section range");
            raw_end = std::max(raw_end, uint64_t(s.raw_offset) + s.raw_size);
        }
        for (const auto& other : result.sections) {
            require(!overlaps(s.rva, s.extent(), other.rva, other.extent()), "overlapping PE virtual sections");
            require(!overlaps(s.raw_offset, s.raw_size, other.raw_offset, other.raw_size), "overlapping PE raw sections");
        }
        if (result.entry_rva >= s.rva && uint64_t(result.entry_rva) - s.rva < s.copy_size() &&
            (s.characteristics & 0x20000000u)) entry_valid = true;
        result.sections.push_back(s);
    }
    require(entry_valid, "invalid PE entry point");

    for (size_t i = 0; i < result.directories.size(); ++i) {
        auto& d = result.directories[i];
        d.rva = static_cast<uint32_t>(read_le(bytes, opt + 112 + i * 8, 4));
        d.size = static_cast<uint32_t>(read_le(bytes, opt + 116 + i * 8, 4));
        // The AMD64 subset does not use reserved or global-pointer directories.
        if (i == 7 || i == 8 || i == 15) {
            require(!d.rva && !d.size, "unsupported PE data directory");
            continue;
        }
        require(bool(d.rva) == bool(d.size), "inconsistent PE data directory");
        if (!d.size) continue;
        if (i == 4) {
            // Certificates live outside mapped section data. This is not signature verification.
            require(d.rva >= raw_end && d.rva % 8 == 0 && d.size % 8 == 0 &&
                    contains(bytes.size(), d.rva, d.size), "invalid PE certificate range");
            continue;
        }
        require(contains(result.image_size, d.rva, d.size), "invalid PE data directory range");
        // Directories consumed by the current mapper must contain at least their fixed
        // prefix, be naturally aligned, and be entirely in one copied section.
        // Internal records and referenced RVAs require separate validation before use.
        uint32_t minimum = 0;
        switch (i) {
            case 0: minimum = 40; break;  // export directory
            case 1: minimum = 20; break;  // import descriptor
            case 5: minimum = 8; break;   // base relocation block
            case 13: minimum = 32; break; // delay import descriptor
            default: break;
        }
        if (minimum) {
            require(d.size >= minimum && d.rva % 4 == 0, "invalid PE directory prefix");
            const bool backed = std::any_of(result.sections.begin(), result.sections.end(), [&](const Section& s) {
                return d.rva >= s.rva && contains(s.copy_size(), uint64_t(d.rva) - s.rva, d.size);
            });
            require(backed, "PE directory is not backed by copied section data");
        }
    }
    return result;
}

}  // namespace rt::pe

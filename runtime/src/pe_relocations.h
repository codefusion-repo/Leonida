#pragma once
#include "pe_validation.h"

namespace rt::pe {

// Plans are produced from immutable file bytes, never from the writable mapped image.
class RelocationPlan {
    uint32_t image_size_;
    bool present_;
    std::vector<uint32_t> targets_;
    RelocationPlan(uint32_t image_size, bool present, std::vector<uint32_t> targets)
        : image_size_(image_size), present_(present), targets_(std::move(targets)) {}
    friend RelocationPlan plan_relocations(std::span<const uint8_t>, const Layout&);
public:
    bool present() const { return present_; }
    size_t size() const { return targets_.size(); }
    void apply(std::span<uint8_t> image, uint64_t preferred, uint64_t actual) const {
        require(image.size() == image_size_, "relocation image size mismatch");
        if (preferred == actual) return;
        require(present_, "rebasing requires relocations");
        // Unsigned arithmetic implements PE's modulo-2^64 adjustment in either direction.
        const uint64_t delta = actual - preferred;
        for (const uint32_t target : targets_) {
            const uint64_t value = read_le(image, target, 8) + delta;
            for (unsigned i = 0; i < 8; ++i)
                image[static_cast<size_t>(target) + i] = static_cast<uint8_t>(value >> (8 * i));
        }
    }
};

inline RelocationPlan plan_relocations(std::span<const uint8_t> file, const Layout& layout) {
    constexpr uint32_t max_directory = 16u * 1024u * 1024u;
    constexpr size_t max_targets = 1u << 20;
    const auto dir = layout.directories[5];
    if (!dir.size) {
        require(!dir.rva, "inconsistent relocation directory");
        return RelocationPlan(layout.image_size, false, {});
    }
    require(dir.size <= max_directory && dir.rva % 4 == 0 &&
            contains(layout.image_size, dir.rva, dir.size), "invalid relocation directory");
    uint64_t file_offset = 0;
    bool backed = false;
    for (const auto& section : layout.sections) {
        if (dir.rva >= section.rva && contains(section.copy_size(), uint64_t(dir.rva) - section.rva, dir.size)) {
            file_offset = uint64_t(section.raw_offset) + dir.rva - section.rva;
            backed = contains(file.size(), file_offset, dir.size);
            break;
        }
    }
    require(backed, "relocation directory is not backed by file data");
    const auto bytes = file.subspan(static_cast<size_t>(file_offset), dir.size);
    std::vector<uint32_t> targets;
    uint64_t cursor = 0;
    while (cursor < bytes.size()) {
        require(contains(bytes.size(), cursor, 8), "truncated relocation block");
        const uint64_t page = read_le(bytes, cursor, 4);
        const uint64_t length = read_le(bytes, cursor + 4, 4);
        require(page % 4096 == 0 && page < layout.image_size, "invalid relocation page");
        require(length >= 8 && length % 4 == 0 && contains(bytes.size(), cursor, length),
                "invalid relocation block size");
        for (uint64_t pos = 8; pos < length; pos += 2) {
            const uint64_t entry = read_le(bytes, cursor + pos, 2);
            const uint64_t type = entry >> 12;
            if (type == 0) continue; // ABSOLUTE padding
            require(type == 10, "unsupported relocation type");
            const uint64_t target = page + (entry & 0xfff);
            require(contains(layout.image_size, target, 8) && target >= layout.headers_size,
                    "invalid relocation target");
            require(!overlaps(target, 8, dir.rva, dir.size), "relocation overlaps its metadata");
            const bool in_section = std::any_of(layout.sections.begin(), layout.sections.end(), [&](const Section& s) {
                const uint64_t extent = s.virtual_size ? s.virtual_size : s.raw_size;
                return target >= s.rva && contains(extent, target - s.rva, 8);
            });
            require(in_section, "relocation target outside section");
            require(targets.size() < max_targets, "too many relocation targets");
            targets.push_back(static_cast<uint32_t>(target));
        }
        cursor += length;
    }
    std::sort(targets.begin(), targets.end());
    for (size_t i = 1; i < targets.size(); ++i)
        require(uint64_t(targets[i - 1]) + 8 <= targets[i], "overlapping relocation targets");
    return RelocationPlan(layout.image_size, true, std::move(targets));
}

} // namespace rt::pe

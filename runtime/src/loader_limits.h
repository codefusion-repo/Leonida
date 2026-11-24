#pragma once
#include <cstdint>
#include <stdexcept>

namespace rt {
struct Limits {
    static constexpr uint64_t max_file = 256ull * 1024 * 1024;
    static constexpr uint64_t max_image = 512ull * 1024 * 1024;
    static constexpr uint64_t max_combined = max_file + max_image;
    uint64_t file_bytes = max_file;
    uint64_t image_bytes = max_image;
    uint64_t combined_bytes = max_combined;
    void validate_policy() const {
        if (!file_bytes || !image_bytes || !combined_bytes ||
            file_bytes > max_file || image_bytes > max_image || combined_bytes > max_combined)
            throw std::runtime_error("invalid loader resource policy");
    }
    void check(uint64_t file, uint64_t image) const {
        if (file > file_bytes || image > image_bytes ||
            file > combined_bytes || image > combined_bytes - file)
            throw std::runtime_error("loader resource budget exceeded");
    }
};
}

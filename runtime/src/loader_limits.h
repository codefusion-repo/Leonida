#pragma once
#include <cstdint>
#include <stdexcept>

namespace rt {
struct Limits {
    uint64_t file_bytes = 256ull * 1024 * 1024;
    uint64_t image_bytes = 512ull * 1024 * 1024;
    uint64_t combined_bytes = 768ull * 1024 * 1024;
    void check(uint64_t file, uint64_t image) const {
        if (file > file_bytes || image > image_bytes ||
            file > combined_bytes || image > combined_bytes - file)
            throw std::runtime_error("loader resource budget exceeded");
    }
};
}

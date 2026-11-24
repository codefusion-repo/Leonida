// Diagnostic-only PE mapper; never executes image code.
#pragma once
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "loader_limits.h"

namespace rt {
enum class Binding { Shim, Host, Module, Unimplemented };
struct ImportRecord {
    std::string dll, name;
    Binding binding;
};
struct ImageDeleter {
    void operator()(uint8_t* p) const noexcept;
};
class Loader;
class Module {
    friend class Loader;
    std::unique_ptr<uint8_t, ImageDeleter> allocation_;
    Module() = default;
public:
    Module(const Module&) = delete;
    Module& operator=(const Module&) = delete;
    std::string name;
    std::filesystem::path path;
    uint64_t preferred_base = 0;
    uint32_t size = 0, entry_rva = 0;
    bool relocated = false;
    std::vector<ImportRecord> imports;
    std::map<std::string, uint32_t> exports;
    const uint8_t* base() const noexcept { return allocation_.get(); }
};

class Loader {
    Limits limits_;
    std::unique_ptr<Module> module_;
public:
    explicit Loader(Limits limits = {}) : limits_(limits) {}
    Loader(const Loader&) = delete;
    Loader& operator=(const Loader&) = delete;
    Loader(Loader&&) = delete;
    Loader& operator=(Loader&&) = delete;
    const Module& load(const std::filesystem::path& image);
    const Module* module() const noexcept { return module_.get(); }
};
}

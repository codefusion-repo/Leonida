// Native PE mapper for Xbox Series (x86-64) images.
// Maps an explicit image, applies relocations and reports registered shim coverage.
// It never runs code from the image: DllMain, TLS callbacks and the entry point are left to the caller.
#pragma once
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>
#include "pe_symbols.h"

namespace rt {

enum class Binding { Shim, Host, Module, Unimplemented };

struct ImportRecord {
    std::string dll;
    std::string name;   // "#123" for ordinals
    Binding binding;
};

struct Module {
    std::string name;
    std::filesystem::path path;
    uint8_t* base = nullptr;
    uint64_t preferred_base = 0;
    uint32_t size = 0;
    uint32_t entry_rva = 0;
    bool relocated = false;
    std::vector<ImportRecord> imports;
    std::vector<pe::ImportSymbol> pending_imports;
    std::map<std::string, void*> exports;  // by name, plus "#ordinal"
};

class Loader {
public:
    Loader() = default;
    ~Loader();

    // Inspects an explicit image only. Throws std::runtime_error on failure.
    Module& load(const std::filesystem::path& image);

    const std::vector<Module*>& modules() const { return order_; }

private:
    Module& map_image(const std::filesystem::path& path);
    void bind_imports(Module& m);
    std::map<std::string, Module*> by_name_;  // lower-case file name
    std::vector<Module*> order_;
};

std::string lower(std::string s);

}  // namespace rt

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
    ~Module() = default;
    friend struct std::default_delete<Module>;
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

// Fault controls exist only in the dedicated lifecycle test executable.
#ifdef LEONIDA_LOADER_FAULT_TEST
enum class FaultStage { None, Allocated, Copied, Relocated, ProtectFailure, Sealed };
struct FaultProbe {
    FaultStage requested = FaultStage::None;
    FaultStage reached = FaultStage::None;
    uintptr_t address = 0;
    uint32_t size = 0;
    uint32_t protection_error = 0;
    bool verified_pages = false;
};
#endif

class Loader {
    const Limits limits_;
#ifdef LEONIDA_LOADER_FAULT_TEST
    FaultProbe* probe_ = nullptr;
    void checkpoint(FaultStage stage, const Module& m);
#endif
    std::unique_ptr<Module> module_;
public:
    explicit Loader(Limits limits = {}) : limits_(limits) { limits_.validate_policy(); }
#ifdef LEONIDA_LOADER_FAULT_TEST
    void test_probe(FaultProbe* probe) noexcept { probe_ = probe; }
#endif
    Loader(const Loader&) = delete;
    Loader& operator=(const Loader&) = delete;
    Loader(Loader&&) = delete;
    Loader& operator=(Loader&&) = delete;
    const Module& load(const std::filesystem::path& image);
    const Module* module() const noexcept { return module_.get(); }
};
}

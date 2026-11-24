#include "pe_loader.h"
#include "pe_validation.h"
#include "pe_relocations.h"
#include "pe_symbols.h"
#include "dll_policy.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <new>
#include <utility>

#include "../shims/diagnostic_registry.h"

namespace rt {

namespace {

std::vector<uint8_t> read_file(const std::filesystem::path& p, const Limits& limits) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("cannot open " + p.string());
    const std::streamoff size = f.tellg();
    if (size < 0 || static_cast<uint64_t>(size) > pe::max_file_bytes)
        throw std::runtime_error("invalid PE file size");
    if (size < 64) throw std::runtime_error("invalid PE file size");
    limits.check(static_cast<uint64_t>(size), 0);
    std::vector<uint8_t> file(static_cast<size_t>(size));
    f.seekg(0);
    if (!f || (!file.empty() && !f.read(reinterpret_cast<char*>(file.data()), size)))
        throw std::runtime_error("cannot read complete PE file");
    return file;
}

// Verify the entire owned range, not just the old protection of its first page.
void verify_data_pages(const uint8_t* bytes, uint32_t size, DWORD expected) {
    const auto begin = reinterpret_cast<uintptr_t>(bytes);
    if (!begin || !size || size > UINTPTR_MAX - begin)
        throw std::runtime_error("invalid diagnostic page range");
    const auto end = begin + size;
    for (auto cursor = begin; cursor < end;) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) != sizeof(info) ||
            info.State != MEM_COMMIT || info.Type != MEM_PRIVATE || info.Protect != expected ||
            reinterpret_cast<uintptr_t>(info.AllocationBase) != begin)
            throw std::runtime_error("unexpected diagnostic page state");
        const auto region = reinterpret_cast<uintptr_t>(info.BaseAddress);
        if (region > cursor || info.RegionSize > UINTPTR_MAX - region ||
            region + info.RegionSize <= cursor)
            throw std::runtime_error("invalid diagnostic page region");
        cursor = region + info.RegionSize;
    }
}

}  // namespace

void ImageDeleter::operator()(uint8_t* p) const noexcept {
    if (p) VirtualFree(p, 0, MEM_RELEASE);
}

#ifdef LEONIDA_LOADER_FAULT_TEST
void Loader::checkpoint(FaultStage stage, const Module& m) {
    if (!probe_) return;
    verify_data_pages(m.base(), m.size, stage == FaultStage::Sealed ? PAGE_READONLY : PAGE_READWRITE);
    probe_->verified_pages = true;
    probe_->reached = stage;
    probe_->address = reinterpret_cast<uintptr_t>(m.base());
    probe_->size = m.size;
    if (probe_->requested == stage) {
        if (stage == FaultStage::Copied) throw std::bad_alloc();
        throw std::runtime_error("injected lifecycle failure");
    }
}
#endif

const Module& Loader::load(const std::filesystem::path& path) {
    if (module_) throw std::runtime_error("diagnostic loader already owns an image");
    auto file = read_file(path, limits_);
    const auto layout = pe::validate(file);
    limits_.check(file.size(), layout.image_size);
    const auto relocations = pe::plan_relocations(file);
    const auto symbols = pe::plan_symbols(file);

    // Own all intermediate state locally until the transaction succeeds.
    std::unique_ptr<Module> candidate(new Module);
    auto& m = *candidate;
    m.name = path.filename().string();
    m.path = path;
    m.preferred_base = layout.image_base;
    m.size = layout.image_size;
    m.entry_rva = layout.entry_rva;
    m.imports.reserve(symbols.imports.size());
    for (const auto& item : symbols.imports) {
        const std::string sym = item.by_ordinal ? "#" + std::to_string(item.ordinal) : item.name;
        const auto diagnostic = dll::classify(item.dll, sym, shims::registered);
        m.imports.push_back({diagnostic.key, diagnostic.symbol,
                             diagnostic.registered ? Binding::Shim : Binding::Unimplemented});
    }
    for (const auto& e : symbols.exports) m.exports.emplace(e.key, e.rva);

    m.allocation_.reset(static_cast<uint8_t*>(VirtualAlloc(
        reinterpret_cast<void*>(layout.image_base), layout.image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)));
    if (!m.allocation_) {
        if (!relocations.present())
            throw std::runtime_error("preferred base is taken and the image has no relocations");
        m.allocation_.reset(static_cast<uint8_t*>(VirtualAlloc(
            nullptr, layout.image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)));
        if (!m.allocation_) throw std::runtime_error("VirtualAlloc failed");
    }
#ifdef LEONIDA_LOADER_FAULT_TEST
    checkpoint(FaultStage::Allocated, m);
#endif
    auto* bytes = m.allocation_.get();
    std::memcpy(bytes, file.data(), layout.headers_size);
    for (const auto& sec : layout.sections)
        if (const auto n = sec.copy_size())
            std::memcpy(bytes + sec.rva, file.data() + sec.raw_offset, n);
#ifdef LEONIDA_LOADER_FAULT_TEST
    checkpoint(FaultStage::Copied, m);
#endif
    const auto actual = reinterpret_cast<uint64_t>(bytes);
    relocations.apply(std::span<uint8_t>(bytes, m.size), actual);
    m.relocated = actual != layout.image_base;
#ifdef LEONIDA_LOADER_FAULT_TEST
    checkpoint(FaultStage::Relocated, m);
#endif
    // Diagnostic images are never executable, irrespective of PE section flags.
    DWORD previous = 0;
#ifdef LEONIDA_LOADER_FAULT_TEST
    // Decommit one page of our own test allocation. The actual Windows
    // protection call must fail for a range containing uncommitted pages.
    const bool force_protect_failure = probe_ && probe_->requested == FaultStage::ProtectFailure;
    if (force_protect_failure) {
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        if (!system.dwPageSize || m.size < system.dwPageSize || m.size % system.dwPageSize ||
            !VirtualFree(bytes + m.size - system.dwPageSize, system.dwPageSize, MEM_DECOMMIT))
            throw std::runtime_error("cannot prepare protection failure fixture");
    }
#endif
    if (!VirtualProtect(bytes, m.size, PAGE_READONLY, &previous)) {
#ifdef LEONIDA_LOADER_FAULT_TEST
        if (force_protect_failure) {
            probe_->protection_error = GetLastError();
            probe_->reached = FaultStage::ProtectFailure;
        }
#endif
        throw std::runtime_error("cannot seal diagnostic image");
    }
#ifdef LEONIDA_LOADER_FAULT_TEST
    if (force_protect_failure) throw std::runtime_error("unexpected protection success on decommitted page");
#endif
    if (previous != PAGE_READWRITE)
        throw std::runtime_error("unexpected diagnostic page protection");
    verify_data_pages(bytes, m.size, PAGE_READONLY);
#ifdef LEONIDA_LOADER_FAULT_TEST
    checkpoint(FaultStage::Sealed, m);
#endif
    module_ = std::move(candidate);
    return *module_;
}
} // namespace rt

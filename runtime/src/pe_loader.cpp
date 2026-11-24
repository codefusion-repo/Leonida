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

#include "../shims/diagnostic_registry.h"

namespace rt {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

namespace {

std::vector<uint8_t> read_file(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("cannot open " + p.string());
    const std::streamoff size = f.tellg();
    if (size < 0 || static_cast<uint64_t>(size) > pe::max_file_bytes)
        throw std::runtime_error("invalid PE file size");
    std::vector<uint8_t> file(static_cast<size_t>(size));
    f.seekg(0);
    if (!f || (!file.empty() && !f.read(reinterpret_cast<char*>(file.data()), size)))
        throw std::runtime_error("cannot read complete PE file");
    return file;
}

}  // namespace

Loader::~Loader() {
    for (auto* m : order_) {
        if (m->base) VirtualFree(m->base, 0, MEM_RELEASE);
        delete m;
    }
}

Module& Loader::load(const std::filesystem::path& image) {
    std::string key = lower(image.filename().string());
    if (auto it = by_name_.find(key); it != by_name_.end()) return *it->second;
    Module& m = map_image(image);
    bind_imports(m);
    // Keep mapped bytes non-executable during diagnostic-only dry-run.
    return m;
}

Module& Loader::map_image(const std::filesystem::path& path) {
    auto file = read_file(path);
    // Validate all header and section ranges before creating a module or mapping memory.
    const auto layout = pe::validate(file);
    const auto relocations = pe::plan_relocations(file);
    const auto symbols = pe::plan_symbols(file);

    auto* m = new Module;
    m->name = path.filename().string();
    m->path = path;
    m->preferred_base = layout.image_base;
    m->size = layout.image_size;
    m->entry_rva = layout.entry_rva;
    by_name_[lower(m->name)] = m;
    order_.push_back(m);

    m->base = static_cast<uint8_t*>(
        VirtualAlloc(reinterpret_cast<void*>(layout.image_base), layout.image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!m->base) {
        if (!relocations.present())
            throw std::runtime_error(m->name + ": preferred base is taken and the image has no relocations");
        m->base = static_cast<uint8_t*>(VirtualAlloc(nullptr, layout.image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!m->base) throw std::runtime_error(m->name + ": VirtualAlloc failed");
    }

    std::memcpy(m->base, file.data(), layout.headers_size);
    for (const auto& sec : layout.sections) {
        if (const auto n = sec.copy_size())
            std::memcpy(m->base + sec.rva, file.data() + sec.raw_offset, n);
    }

    const auto actual = reinterpret_cast<uint64_t>(m->base);
    relocations.apply(std::span<uint8_t>(m->base, m->size), actual);
    m->relocated = actual != layout.image_base;
    for (const auto& e : symbols.exports) m->exports.emplace(e.key, m->base + e.rva);
    m->pending_imports = symbols.imports;
    return *m;
}

void Loader::bind_imports(Module& m) {
    // Diagnostic-only: do not discover dependencies, load host libraries,
    // allocate executable thunks or write function addresses into the image.
    for (const auto& item : m.pending_imports) {
        const std::string sym = item.by_ordinal ? "#" + std::to_string(item.ordinal) : item.name;
        const auto diagnostic = dll::classify(item.dll, sym, shims::registered);
        m.imports.push_back({diagnostic.key, diagnostic.symbol,
                             diagnostic.registered ? Binding::Shim : Binding::Unimplemented});
    }
    m.pending_imports.clear();
}

}  // namespace rt

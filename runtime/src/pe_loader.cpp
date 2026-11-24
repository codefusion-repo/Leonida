#include "pe_loader.h"
#include "pe_validation.h"
#include "pe_relocations.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include "../shims/shims.h"

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

template <class T>
T* at(uint8_t* base, uint32_t rva) { return reinterpret_cast<T*>(base + rva); }

// The Xbox builds of the MSVC runtime import the same CRT the desktop does, so the host's own copies are used.
bool prefer_host_copy(const std::string& dll) {
    static const char* names[] = {"vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_1.dll",
                                  "msvcp140_2.dll", "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
                                  "concrt140.dll", "vccorlib140.dll", "vcomp140.dll"};
    for (auto* n : names)
        if (dll == n) return true;
    return false;
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
    protect_sections(m);
    return m;
}

Module& Loader::map_image(const std::filesystem::path& path) {
    auto file = read_file(path);
    // Validate all header and section ranges before creating a module or mapping memory.
    const auto layout = pe::validate(file);
    const auto relocations = pe::plan_relocations(file);

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
    parse_exports(*m);
    return *m;
}

void Loader::parse_exports(Module& m) {
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.Size) return;
    auto* ed = at<IMAGE_EXPORT_DIRECTORY>(m.base, dir.VirtualAddress);
    auto* funcs = at<uint32_t>(m.base, ed->AddressOfFunctions);
    auto* names = at<uint32_t>(m.base, ed->AddressOfNames);
    auto* ords = at<uint16_t>(m.base, ed->AddressOfNameOrdinals);
    for (uint32_t i = 0; i < ed->NumberOfFunctions; ++i)
        if (funcs[i]) m.exports["#" + std::to_string(ed->Base + i)] = m.base + funcs[i];
    for (uint32_t i = 0; i < ed->NumberOfNames; ++i)
        m.exports[at<char>(m.base, names[i])] = m.base + funcs[ords[i]];
    // Forwarded exports (RVA inside the export directory) aren't followed yet; none of the bundled DLLs use them.
}

void* Loader::resolve(Module& m, const std::string& dll, const std::string& name, uint16_t ordinal, bool by_ordinal) {
    std::string key = lower(dll);
    std::string sym = by_ordinal ? "#" + std::to_string(ordinal) : name;

    if (void* p = shims::find(key, sym)) {
        m.imports.push_back({dll, sym, Binding::Shim});
        return p;
    }
    // Bundled game module (an Xbox build that ships beside the game)?
    auto bundled = game_dir_ / dll;
    if (!prefer_host_copy(key) && std::filesystem::exists(bundled)) {
        Module& dep = load(bundled);
        if (auto it = dep.exports.find(sym); it != dep.exports.end()) {
            m.imports.push_back({dll, sym, Binding::Module});
            return it->second;
        }
    }
    // Host Windows: system DLLs and API sets. LOAD_LIBRARY_SEARCH_SYSTEM32 keeps the game folder out of the search.
    if (HMODULE h = LoadLibraryExA(dll.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        FARPROC p = GetProcAddress(h, by_ordinal ? MAKEINTRESOURCEA(ordinal) : name.c_str());
        if (p) {
            m.imports.push_back({dll, sym, Binding::Host});
            return reinterpret_cast<void*>(p);
        }
    }
    m.imports.push_back({dll, sym, Binding::Unimplemented});
    return shims::make_unimplemented_thunk(dll, sym);
}

void Loader::bind_imports(Module& m) {
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);

    auto bind_thunks = [&](const std::string& dll, IMAGE_THUNK_DATA64* lookup, IMAGE_THUNK_DATA64* iat) {
        for (; lookup->u1.AddressOfData; ++lookup, ++iat) {
            bool by_ord = IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal);
            uint16_t ord = by_ord ? (uint16_t)IMAGE_ORDINAL64(lookup->u1.Ordinal) : 0;
            std::string name = by_ord ? "" : at<IMAGE_IMPORT_BY_NAME>(m.base, (uint32_t)lookup->u1.AddressOfData)->Name;
            iat->u1.Function = reinterpret_cast<uint64_t>(resolve(m, dll, name, ord, by_ord));
        }
    };

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size) {
        for (auto* d = at<IMAGE_IMPORT_DESCRIPTOR>(m.base, dir.VirtualAddress); d->Name; ++d) {
            std::string dll = at<char>(m.base, d->Name);
            uint32_t lookup = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
            bind_thunks(dll, at<IMAGE_THUNK_DATA64>(m.base, lookup), at<IMAGE_THUNK_DATA64>(m.base, d->FirstThunk));
        }
    }
    // Delay imports are bound eagerly: simpler, and the full import surface shows up in --dry-run.
    auto& ddir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (ddir.Size) {
        for (auto* d = at<IMAGE_DELAYLOAD_DESCRIPTOR>(m.base, ddir.VirtualAddress); d->DllNameRVA; ++d) {
            std::string dll = at<char>(m.base, d->DllNameRVA);
            bind_thunks(dll, at<IMAGE_THUNK_DATA64>(m.base, d->ImportNameTableRVA),
                        at<IMAGE_THUNK_DATA64>(m.base, d->ImportAddressTableRVA));
        }
    }
}

void Loader::protect_sections(Module& m) {
    auto* nt = at<IMAGE_NT_HEADERS64>(m.base, reinterpret_cast<IMAGE_DOS_HEADER*>(m.base)->e_lfanew);
    DWORD old;
    VirtualProtect(m.base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        bool x = sec->Characteristics & IMAGE_SCN_MEM_EXECUTE, w = sec->Characteristics & IMAGE_SCN_MEM_WRITE;
        DWORD prot = x ? (w ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) : (w ? PAGE_READWRITE : PAGE_READONLY);
        SIZE_T size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (size) VirtualProtect(m.base + sec->VirtualAddress, size, prot, &old);
    }
    FlushInstructionCache(GetCurrentProcess(), m.base, m.size);
}

}  // namespace rt

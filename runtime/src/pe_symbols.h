#pragma once
#include "pe_relocations.h"
#include <utility>
#include <string>
#include <set>

namespace rt::pe {
struct ImportSymbol { std::string dll, name; uint16_t ordinal; bool by_ordinal; uint32_t iat; };
struct ExportSymbol { std::string key; uint32_t rva; };
struct Symbols { std::vector<ImportSymbol> imports; std::vector<ExportSymbol> exports; };

// Read only bytes that the mapper actually copies from the original file.
class SymbolReader {
    std::span<const uint8_t> file_;
    Layout layout_;
public:
    explicit SymbolReader(std::span<const uint8_t> file) : file_(file), layout_(validate(file)) {}
    const Layout& layout() const { return layout_; }
    std::span<const uint8_t> tail(uint64_t rva) const {
        for (const auto& s : layout_.sections) {
            if (rva >= s.rva && rva - s.rva < s.copy_size()) {
                const auto delta = rva - s.rva;
                return file_.subspan(static_cast<size_t>(s.raw_offset + delta), static_cast<size_t>(s.copy_size() - delta));
            }
        }
        throw std::runtime_error("symbol metadata outside copied section");
    }
    uint64_t read(uint64_t rva, unsigned width) const { return read_le(tail(rva), 0, width); }
    void range(uint64_t rva, uint64_t size) const {
        if (size) require(size <= tail(rva).size(), "truncated symbol metadata");
    }
    std::string string(uint64_t rva) const {
        auto b = tail(rva);
        std::string result;
        for (size_t i = 0; i < b.size() && i < 1024; ++i) {
            if (!b[i]) { require(!result.empty(), "empty symbol string"); return result; }
            require(b[i] >= 0x21 && b[i] <= 0x7e, "invalid symbol character");
            result.push_back(static_cast<char>(b[i]));
        }
        throw std::runtime_error("unterminated symbol string");
    }
    void target(uint64_t rva, uint64_t width) const {
        for (const auto& s : layout_.sections) {
            const auto extent = s.virtual_size ? s.virtual_size : s.raw_size;
            if (rva >= s.rva && contains(extent, rva - s.rva, width)) return;
        }
        throw std::runtime_error("symbol target outside section");
    }
    void iat(uint64_t rva, uint64_t size, bool delay) const {
        require(rva % 8 == 0 && size && size % 8 == 0, "unaligned IAT");
        range(rva, size);
        target(rva, size);
        const auto declared = layout_.directories[12];
        if (!delay && declared.size)
            require(rva >= declared.rva && contains(declared.size, rva - declared.rva, size), "IAT outside declared directory");
        bool non_executable = false;
        for (const auto& s : layout_.sections) {
            if (rva >= s.rva && contains(s.copy_size(), rva - s.rva, size))
                non_executable = !(s.characteristics & 0x20000000u);
        }
        require(non_executable, "IAT must be in non-executable section");
        for (size_t i = 0; i < layout_.directories.size(); ++i) {
            if (i == 4 || i == 12) continue; // certificate file offset; IAT directory itself
            const auto d = layout_.directories[i];
            require(!overlaps(rva, size, d.rva, d.size), "IAT overlaps directory metadata");
        }
    }
};

inline Symbols plan_symbols(std::span<const uint8_t> file) {
    constexpr size_t max_records = 65536, max_descriptors = 4096;
    constexpr uint64_t ordinal_flag = uint64_t(1) << 63;
    SymbolReader reader(file);
    const auto& l = reader.layout();
    const auto relocations = plan_relocations(file);
    Symbols result;
    struct Range { uint32_t start, size; bool shared; };
    std::vector<Range> ranges;
    auto record = [&](uint64_t rva, uint64_t size, bool shared = false, bool allow_reloc = false) {
        if (!size) return;
        require(contains(l.image_size, rva, size) && ranges.size() < 4 * max_records + 4 * max_descriptors,
                "symbol metadata range limit");
        for (const size_t index : {size_t(2), size_t(3), size_t(5), size_t(6), size_t(9), size_t(10), size_t(11), size_t(14)}) {
            const auto d = l.directories[index];
            require(!overlaps(rva, size, d.rva, d.size), "symbol metadata overlaps unrelated directory");
        }
        if (!allow_reloc)
            require(!relocations.touches(static_cast<uint32_t>(rva), static_cast<uint32_t>(size)), "relocation overlaps symbol metadata");
        ranges.push_back({static_cast<uint32_t>(rva), static_cast<uint32_t>(size), shared});
    };
    auto read_string = [&](uint64_t rva, uint64_t prefix = 0) {
        auto value = reader.string(rva + prefix);
        const uint64_t length = prefix + value.size() + 1;
        reader.range(rva, length);
        record(rva, length, true);
        return value;
    };
    std::set<uint32_t> slots;
    std::set<std::string> keys;
    size_t string_bytes = 0;
    auto account = [&](const std::string& s) {
        string_bytes += s.size();
        require(string_bytes <= 16u * 1024u * 1024u, "symbol string budget exceeded");
    };
    auto add_export = [&](std::string key, uint32_t rva) {
        require(result.exports.size() < max_records, "too many exports");
        account(key);
        require(keys.insert(key).second, "duplicate export key");
        result.exports.push_back({std::move(key), rva});
    };
    const auto ed = l.directories[0];
    if (ed.size) {
        require(reader.read(ed.rva, 4) == 0, "reserved export flags");
        require(!relocations.touches(ed.rva, ed.size), "relocation overlaps export directory");
        record(ed.rva, 40);
        (void)read_string(reader.read(ed.rva + 12, 4));
        const uint64_t base = reader.read(ed.rva + 16, 4);
        const uint64_t nf = reader.read(ed.rva + 20, 4), nn = reader.read(ed.rva + 24, 4);
        const uint64_t funcs = reader.read(ed.rva + 28, 4), names = reader.read(ed.rva + 32, 4), ords = reader.read(ed.rva + 36, 4);
        require(nf <= max_records && nn <= max_records && base <= 65535 && nf <= 65536 - base, "export count or ordinal limit");
        require((!nf || (funcs && funcs % 4 == 0 && base != 0)) &&
                (!nn || (names && names % 4 == 0 && ords && ords % 2 == 0)), "invalid export table alignment");
        reader.range(funcs, nf * 4); reader.range(names, nn * 4); reader.range(ords, nn * 2);
        record(funcs, nf * 4); record(names, nn * 4); record(ords, nn * 2);
        std::vector<uint32_t> targets;
        for (uint64_t i = 0; i < nf; ++i) {
            const auto rva = static_cast<uint32_t>(reader.read(funcs + i * 4, 4));
            targets.push_back(rva);
            if (!rva) continue;
            require(!overlaps(rva, 1, ed.rva, ed.size), "forwarded exports unsupported");
            reader.target(rva, 1);
            add_export("#" + std::to_string(base + i), rva);
        }
        for (uint64_t i = 0; i < nn; ++i) {
            const auto ord = reader.read(ords + i * 2, 2);
            require(ord < targets.size() && targets[static_cast<size_t>(ord)] != 0, "invalid export ordinal");
            auto name = read_string(reader.read(names + i * 4, 4));
            require(name.front() != '#', "reserved export key");
            add_export(std::move(name), targets[static_cast<size_t>(ord)]);
        }
    }
    size_t descriptors = 0;
    auto bind = [&](uint64_t dll_rva, uint64_t lookup, uint64_t iat, bool delay) {
        auto dll = read_string(dll_rva);
        // Only simple DLL basenames; reject path separators, device/path syntax and traversal.
        for (char c : dll)
            require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.', "invalid DLL basename");
        require(dll.size() > 4 && dll.find("..") == std::string::npos, "invalid DLL basename");
        auto ext = dll.substr(dll.size() - 4);
        for (char& c : ext) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        require(ext == ".dll" && dll.front() != '.', "invalid DLL extension");
        require(lookup && iat && lookup % 8 == 0 && (!delay || lookup != iat), "invalid thunk address");
        // Both arrays must terminate within the same respective copied section.
        const auto lookup_bytes = reader.tail(lookup);
        const auto iat_bytes = reader.tail(iat);
        for (uint64_t pos = 0; ; pos += 8) {
            require(contains(lookup_bytes.size(), pos, 8), "unterminated thunk table");
            const auto value = read_le(lookup_bytes, pos, 8);
            const uint64_t slot = iat + pos;
            require(contains(iat_bytes.size(), pos, 8), "unterminated IAT");
            const auto initial = read_le(iat_bytes, pos, 8);
            require(delay || initial == value, "unsupported bound or inconsistent IAT");
            if (!value) {
                require(!initial, "nonzero IAT terminator");
                const auto length = pos + 8;
                reader.iat(iat, length, delay);
                if (lookup != iat) record(lookup, length);
                record(iat, pos, false, delay);
                record(iat + pos, 8);
                break;
            }
            require(slots.insert(static_cast<uint32_t>(slot)).second, "overlapping IAT slots");
            require(slots.size() <= max_records, "IAT slot limit");
            require(result.imports.size() < max_records, "import record limit");
            ImportSymbol item{dll, "", 0, bool(value & ordinal_flag), static_cast<uint32_t>(slot)};
            if (item.by_ordinal) {
                require((value & ~(ordinal_flag | 0xffffu)) == 0 && (value & 0xffffu) != 0, "invalid ordinal thunk");
                item.ordinal = static_cast<uint16_t>(value);
            } else {
                require(value <= 0x7fffffffull && value % 2 == 0, "invalid name thunk");
                item.name = read_string(value, 2);
                require(item.name.front() != '#', "reserved import key");
            }
            account(item.dll); account(item.name);
            result.imports.push_back(std::move(item));
        }
    };
    for (const size_t index : {size_t(1), size_t(13)}) {
        const auto d = l.directories[index];
        if (!d.size) continue;
        const uint64_t width = index == 1 ? 20 : 32;
        require(d.size <= 1024u * 1024u && d.size % width == 0, "invalid import directory size");
        record(d.rva, d.size);
        bool terminated = false;
        for (uint64_t pos = 0; contains(d.size, pos, width); pos += width) {
            const uint64_t rva = uint64_t(d.rva) + pos;
            std::array<uint32_t, 8> f{};
            bool zero = true;
            for (uint64_t j = 0; j < width / 4; ++j) {
                f[static_cast<size_t>(j)] = static_cast<uint32_t>(reader.read(rva + j * 4, 4));
                zero = zero && !f[static_cast<size_t>(j)];
            }
            if (zero) {
                for (uint64_t p = pos + width; p < d.size; p += 4)
                    require(reader.read(uint64_t(d.rva) + p, 4) == 0, "nonzero descriptor tail");
                terminated = true; break;
            }
            require(++descriptors <= max_descriptors, "import descriptor limit");
            if (index == 1) {
                require(f[3] && f[4] && !f[1] && (!f[2] || f[2] == UINT32_MAX), "unsupported bound import descriptor");
                bind(f[3], f[0] ? f[0] : f[4], f[4], false);
            } else {
                require(f[0] == 1 && f[1] && f[2] && f[3] && f[4] && !f[5] && !f[6] && !f[7],
                        "unsupported delay import descriptor");
                require(f[2] % 8 == 0, "unaligned delay module handle");
                reader.target(f[2], 8);
                bool writable = false;
                for (const auto& s : l.sections) {
                    const uint64_t extent = s.virtual_size ? s.virtual_size : s.raw_size;
                    if (f[2] >= s.rva && contains(extent, uint64_t(f[2]) - s.rva, 8))
                        writable = (s.characteristics & 0xc0000000u) == 0xc0000000u && !(s.characteristics & 0x20000000u);
                }
                require(writable, "delay module handle must be in writable data");
                record(f[2], 8);
                bind(f[1], f[4], f[3], true);
            }
        }
        require(terminated, "unterminated import descriptors");
    }
    // Exact sharing of strings is permitted. Structural ranges and IAT slots
    // must not alias any other recorded metadata, except the explicit OFT==IAT case.
    std::sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b) {
        return a.start != b.start ? a.start < b.start : a.size < b.size;
    });
    std::vector<Range> distinct;
    for (const auto& range : ranges) {
        if (!distinct.empty()) {
            const auto& prev = distinct.back();
            if (range.start == prev.start && range.size == prev.size && range.shared && prev.shared) continue;
            require(uint64_t(prev.start) + prev.size <= range.start, "overlapping symbol metadata");
        }
        distinct.push_back(range);
    }
    for (const auto& e : result.exports) {
        const auto it = std::upper_bound(distinct.begin(), distinct.end(), e.rva,
            [](uint32_t rva, const Range& range) { return rva < range.start; });
        if (it != distinct.begin()) {
            const auto& prev = *(it - 1);
            require(!overlaps(e.rva, 1, prev.start, prev.size), "export targets symbol metadata");
        }
    }
    return result;
}
} // namespace rt::pe

// gta6rt: native runtime for the Xbox Series build.
//
//   gta6rt --dry-run <image> [--game-dir DIR]
//       Maps only the explicit image, applies relocations and reports registered shim coverage.
//       No code from the image runs.
#include <windows.h>

#include <cstdio>
#include <map>
#include <string>

#include "pe_loader.h"

namespace {

const char* binding_name(rt::Binding b) {
    switch (b) {
        case rt::Binding::Shim: return "shim";
        case rt::Binding::Host: return "host";
        case rt::Binding::Module: return "module";
        default: return "UNIMPLEMENTED";
    }
}

int usage() {
    std::fprintf(stderr, "usage: gta6rt --dry-run <image> [--game-dir DIR]\n");
    return 2;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::filesystem::path image, game_dir;
    bool dry_run = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--dry-run") dry_run = true;
        else if (a == L"--game-dir" && i + 1 < argc) game_dir = argv[++i];
        else if (image.empty()) image = a;
        else return usage();
    }
    if (image.empty()) return usage();
    if (!dry_run) {
        std::fprintf(stderr, "Only --dry-run exists so far: running game code needs the shims listed by it first.\n");
        return 2;
    }
    if (!game_dir.empty()) std::fprintf(stderr, "note: --game-dir is ignored in diagnostic-only mode\n");

    try {
        rt::Loader loader;
        loader.load(image);
        int unimplemented = 0;
        for (auto* m : loader.modules()) {
            std::map<rt::Binding, int> counts;
            for (auto& r : m->imports) counts[r.binding]++;
            std::printf("%-36s base=%p%s size=%u entry=+%#x  shim=%d host=%d module=%d unimplemented=%d\n",
                        m->name.c_str(), m->base, m->relocated ? " (relocated)" : "", m->size, m->entry_rva,
                        counts[rt::Binding::Shim], counts[rt::Binding::Host], counts[rt::Binding::Module],
                        counts[rt::Binding::Unimplemented]);
            for (auto& r : m->imports)
                if (r.binding == rt::Binding::Unimplemented || r.binding == rt::Binding::Shim) {
                    std::printf("    %-13s %s!%s\n", binding_name(r.binding), r.dll.c_str(), r.name.c_str());
                    unimplemented += r.binding == rt::Binding::Unimplemented;
                }
        }
        std::printf("%zu module(s) mapped, %d unimplemented import(s)\n", loader.modules().size(), unimplemented);
        return unimplemented ? 3 : 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}

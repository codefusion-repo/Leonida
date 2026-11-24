#include "../src/pe_loader.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <type_traits>
#include <stdexcept>

static_assert(!std::is_copy_constructible_v<rt::Loader>);
static_assert(!std::is_move_constructible_v<rt::Loader>);
static_assert(!std::is_copy_constructible_v<rt::Module>);

void check(bool ok) { if (!ok) throw std::logic_error("lifecycle invariant failed"); }
template<class F> void reject(F f) {
    bool failed = false;
    try { f(); } catch (const std::runtime_error&) { failed = true; }
    check(failed);
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return 2;
    try {
        const std::filesystem::path good = argv[1], bad = argv[2];
        const uint8_t* address = nullptr;
        {
            rt::Loader loader;
            reject([&] { loader.load(bad); });
            check(!loader.module());
            const auto& m = loader.load(good);
            address = m.base();
            check(address && loader.module() == &m);
            MEMORY_BASIC_INFORMATION info{};
            check(VirtualQuery(address, &info, sizeof(info)) != 0 &&
                  info.State == MEM_COMMIT && info.Protect == PAGE_READWRITE);
            reject([&] { loader.load(good); });
            reject([&] { loader.load(bad); });
            check(loader.module() == &m && m.base() == address);
        }
        MEMORY_BASIC_INFORMATION info{};
        check(VirtualQuery(address, &info, sizeof(info)) != 0 && info.State == MEM_FREE);
        for (auto limits : {rt::Limits{64, 8192, 9000}, rt::Limits{4096, 4096, 9000},
                            rt::Limits{4096, 8192, 8192}}) {
            rt::Loader limited(limits);
            reject([&] { limited.load(good); });
            check(!limited.module());
        }
        std::cout << "Loader lifecycle PASS: rollback, retry, duplicate rejection, budgets, page release\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}

#include "../src/pe_loader.h"
#include "../src/diagnostic_mitigation.h"
#include <windows.h>
#include <iostream>
#include <type_traits>
#include <stdexcept>
#include <new>

static_assert(!std::is_copy_constructible_v<rt::Loader>);
static_assert(!std::is_move_constructible_v<rt::Loader>);
static_assert(!std::is_copy_assignable_v<rt::Loader>);
static_assert(!std::is_move_assignable_v<rt::Loader>);
static_assert(!std::is_copy_constructible_v<rt::Module>);
static_assert(!std::is_move_constructible_v<rt::Module>);
static_assert(!std::is_destructible_v<rt::Module>);

void check(bool ok, const char* why) { if (!ok) throw std::logic_error(why); }
template<class F> void reject(F f) {
    bool failed = false;
    try { f(); } catch (const std::runtime_error&) { failed = true; }
    check(failed, "expected runtime_error");
}
void pages(uintptr_t address, uint32_t size, bool live, DWORD protection = PAGE_READONLY) {
    check(address != 0 && size != 0, "missing allocation observation");
    MEMORY_BASIC_INFORMATION info{};
    for (uintptr_t p = address; p < address + size;) {
        check(VirtualQuery(reinterpret_cast<const void*>(p), &info, sizeof(info)) != 0, "VirtualQuery failed");
        if (live) {
            check(info.State == MEM_COMMIT && info.Protect == protection &&
                  reinterpret_cast<uintptr_t>(info.AllocationBase) == address, "page not owned with expected data protection");
        } else {
            check(info.State == MEM_FREE, "page not released");
        }
        const auto next = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
        check(next > p, "invalid page region");
        p = next;
    }
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return 2;
    try {
        rt::prohibit_dynamic_code();
        const std::filesystem::path good = argv[1], bad = argv[2];
        uintptr_t address = 0;
        uint32_t size = 0;
        {
            rt::Loader loader;
            rt::FaultProbe probe;
            loader.test_probe(&probe);
            reject([&] { loader.load(bad); });
            check(!loader.module() && !probe.address, "preflight failure allocated or published");

            // Fail at each boundary after native allocation, including bad_alloc.
            for (const auto stage : {rt::FaultStage::Allocated, rt::FaultStage::Copied, rt::FaultStage::Relocated,
                                     rt::FaultStage::ProtectFailure, rt::FaultStage::Sealed}) {
                for (int iteration = 0; iteration < 8; ++iteration) {
                    probe = {stage};
                    bool failed = false;
                    try { loader.load(good); }
                    catch (const std::bad_alloc&) { failed = stage == rt::FaultStage::Copied; }
                    catch (const std::runtime_error&) { failed = stage != rt::FaultStage::Copied; }
                    check(failed && probe.reached == stage && !loader.module(), "fault not reached or module published");
                    check(probe.verified_pages, "live protection not verified");
                    check((stage == rt::FaultStage::ProtectFailure) == (probe.protection_error != 0),
                          "real protection failure not observed or unexpected Win32 error");
                    pages(probe.address, probe.size, false);
                }
            }
            probe = {};
            const auto& m = loader.load(good);
            address = reinterpret_cast<uintptr_t>(m.base());
            size = m.size;
            check(size == 0x3000, "executable-metadata fixture missing");
            check(address && loader.module() == &m, "retry did not publish module");
            pages(address, size, true);
            probe = {};
            reject([&] { loader.load(good); });
            reject([&] { loader.load(bad); });
            check(loader.module() == &m && reinterpret_cast<uintptr_t>(m.base()) == address &&
                  !probe.address, "duplicate load changed state");
            loader.test_probe(nullptr);
        }
        pages(address, size, false);
        for (auto limits : {rt::Limits{64, 12288, 16000}, rt::Limits{4096, 4096, 16000},
                            rt::Limits{4096, 12288, 12288}}) {
            rt::Loader limited(limits);
            rt::FaultProbe probe;
            limited.test_probe(&probe);
            reject([&] { limited.load(good); });
            check(!limited.module() && !probe.address, "budget failure allocated or published");
        }
        // A deliberately occupied preferred base cannot be used or freed by a failed load.
        auto* occupied = VirtualAlloc(reinterpret_cast<void*>(address), size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        check(reinterpret_cast<uintptr_t>(occupied) == address, "could not reserve synthetic collision");
        std::unique_ptr<uint8_t, rt::ImageDeleter> guard(static_cast<uint8_t*>(occupied));
        rt::Loader collision;
        reject([&] { collision.load(good); });
        check(!collision.module(), "collision published module");
        pages(address, size, true, PAGE_READWRITE);
        guard.reset();
        pages(address, size, false);

        std::cout << "Loader lifecycle PASS: 40 injected faults (8 real VirtualProtect failures), all live protections, rollback/retry, collision, budgets, page release\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}

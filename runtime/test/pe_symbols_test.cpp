#include "../src/pe_symbols.h"
#include <iostream>
#include <random>

namespace {
using Bytes = std::vector<uint8_t>;
constexpr size_t nt = 0x80, opt = nt + 24, sec = opt + 240;
void put(Bytes& b, size_t p, uint64_t v, unsigned width = 4) {
    for (unsigned i = 0; i < width; ++i) b.at(p + i) = static_cast<uint8_t>(v >> (8 * i));
}
void str(Bytes& b, size_t p, const std::string& s) {
    for (char c : s) b.at(p++) = static_cast<uint8_t>(c);
    b.at(p) = 0;
}
void check(bool ok) { if (!ok) throw std::logic_error("symbol test mismatch"); }
Bytes fixture() {
    Bytes b(0x800);
    put(b, 0, 0x5a4d, 2); put(b, 0x3c, nt);
    put(b, nt, 0x4550); put(b, nt+4, 0x8664, 2); put(b, nt+6, 1, 2);
    put(b, nt+20, 240, 2); put(b, nt+22, 2, 2); put(b, opt, 0x20b, 2);
    put(b, opt+24, 0x140000000ull, 8); put(b, opt+32, 0x1000); put(b, opt+36, 0x200);
    put(b, opt+56, 0x2000); put(b, opt+60, 0x200); put(b, opt+108, 16);
    put(b, sec+8, 0x600); put(b, sec+12, 0x1000); put(b, sec+16, 0x600); put(b, sec+20, 0x200); put(b, sec+36, 0xc0000040);
    put(b, opt+112, 0x1000); put(b, opt+116, 40);
    put(b, 0x210, 1); put(b, 0x214, 1); put(b, 0x218, 1);
    put(b, 0x21c, 0x1050); put(b, 0x220, 0x1054); put(b, 0x224, 0x1058);
    put(b, 0x250, 0x1500); put(b, 0x254, 0x1060); str(b, 0x260, "Data");
    put(b, opt+120, 0x1080); put(b, opt+124, 40);
    put(b, 0x280, 0x1100); put(b, 0x28c, 0x1140); put(b, 0x290, 0x1180);
    put(b, 0x300, 0x1160, 8); put(b, 0x308, 0x8000000000000007ull, 8);
    str(b, 0x340, "test.dll"); str(b, 0x362, "Example");
    put(b, opt+112+13*8, 0x1200); put(b, opt+116+13*8, 64);
    put(b, 0x400, 1); put(b, 0x404, 0x1140); put(b, 0x40c, 0x1280); put(b, 0x410, 0x1260);
    put(b, 0x460, 0x1160, 8);
    return b;
}
void reject(const Bytes& b) {
    try { (void)rt::pe::plan_symbols(b); } catch (const std::runtime_error&) { return; }
    throw std::logic_error("invalid symbols accepted");
}
}
int main() {
    try {
        const auto good = fixture();
        auto p = rt::pe::plan_symbols(good);
        check(p.exports.size()==2 && p.exports[0].key=="#1" && p.exports[1].key=="Data" && p.exports[1].rva==0x1500);
        check(p.imports.size()==3 && p.imports[0].name=="Example" && p.imports[1].ordinal==7 && p.imports[2].iat==0x1280);
        auto bad = [&](size_t offset, uint64_t value, unsigned width=4) { auto b=good; put(b,offset,value,width); reject(b); };
        bad(0x214,0xffffffff); bad(0x258,1,2); bad(0x250,0x1010); bad(0x250,0x1fff);
        bad(0x28c,0); bad(0x290,0x1080); bad(0x300,0x100000000ull,8);
        bad(0x308,0x8000000000010007ull,8); bad(0x400,0); bad(0x40c,0x1180);
        bad(opt+124,20); bad(opt+116+13*8,32);
        auto b=good; str(b,0x340,"../x.dll"); reject(b);
        b=good; put(b,0x300,0x15ff,8); reject(b);
        b=good; put(b,0x280,0x15f8); put(b,0x7f8,0x1160,8); reject(b);
        b=good; str(b,0x260,"#1"); reject(b);
        b=good; put(b,0x280,0); put(b,0x380,0x1160,8); check(rt::pe::plan_symbols(b).imports.size()==2);
        std::mt19937 rng(0x533233u);
        for (unsigned i=0;i<10000;++i) {
            b=good;
            for(unsigned j=0;j<4;++j) b[rng()%b.size()]=static_cast<uint8_t>(rng());
            try { (void)rt::pe::plan_symbols(b); } catch(const std::runtime_error&) {}
        }
        std::cout<<"PE symbols PASS: full PE fixtures, 10000 mutations\n";
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}

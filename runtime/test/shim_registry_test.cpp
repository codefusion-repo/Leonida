#include "../shims/shims.h"
#include <iostream>
int main() {
    // Only register a data marker; never call a shim or an image address.
    int marker = 0;
    const rt::shims::Entry entry{"fixture.dll", "Present", &marker};
    rt::shims::Table table(&entry, 1);
    if (rt::shims::find("fixture.dll", "Present") != &marker ||
        rt::shims::find("fixture.dll", "Absent") != nullptr ||
        rt::shims::find("unknown.dll", "Present") != nullptr) return 1;
    std::cout << "Shim registry PASS: unknown symbols fail closed\n";
}

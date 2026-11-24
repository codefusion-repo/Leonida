#include "shims.h"
#include <map>
#include <string>

namespace rt::shims {
namespace {
std::map<std::string, void*>& table() {
    static std::map<std::string, void*> entries;
    return entries;
}
}

Table::Table(const Entry* entries, size_t count) {
    for (size_t i = 0; i < count; ++i)
        table()[std::string(entries[i].dll) + "!" + entries[i].name] = entries[i].fn;
}

void* find(const std::string& dll_lower, const std::string& name) {
    const auto it = table().find(dll_lower + "!" + name);
    return it == table().end() ? nullptr : it->second;
}

} // namespace rt::shims

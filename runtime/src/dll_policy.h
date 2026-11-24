#pragma once
#include <string>
#include <string_view>
#include <stdexcept>

namespace rt::dll {
inline std::string normalize(std::string_view name) {
    if (name.size() <= 4 || name.size() > 255)
        throw std::runtime_error("invalid DLL basename length");
    std::string key;
    for (char c : name) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '_' || c == '.'))
            throw std::runtime_error("invalid DLL basename character");
        key.push_back(c);
    }
    if (key.front() == '.' || key.find("..") != std::string::npos ||
        !key.ends_with(".dll"))
        throw std::runtime_error("invalid DLL basename");
    const auto stem = key.substr(0, key.find('.'));
    if (stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" ||
        stem == "conin" || stem == "conout" ||
        (stem.size() == 4 && (stem.starts_with("com") || stem.starts_with("lpt")) &&
         stem[3] >= '0' && stem[3] <= '9'))
        throw std::runtime_error("reserved Windows device basename");
    return key;
}
struct Diagnostic {
    std::string key, symbol;
    bool registered;
};
// Query only the supplied static registry. Never load or call a function.
template<class Registry>
Diagnostic classify(std::string_view name, std::string_view symbol, Registry&& registry) {
    auto key = normalize(name);
    if (symbol.empty()) throw std::runtime_error("empty import symbol");
    return {key, std::string(symbol), registry(key, std::string(symbol)) != nullptr};
}
} // namespace rt::dll

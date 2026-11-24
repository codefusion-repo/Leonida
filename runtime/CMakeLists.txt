cmake_minimum_required(VERSION 3.24)
project(gta6rt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "gta6rt must be built for x64 (run from an x64 Native Tools prompt or vcvars64.bat)")
endif()

add_executable(gta6rt
  src/main.cpp
  src/pe_loader.cpp
)
target_compile_definitions(gta6rt PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
target_compile_options(gta6rt PRIVATE /W4 /permissive- /utf-8)
# Diagnostic-only target: no callable shim or executable thunk objects are linked.

# GPU test and pipeline tools (need the Vulkan SDK headers; they load vulkan-1.dll at run time).
find_package(Vulkan QUIET)
if(Vulkan_FOUND)
  foreach(tool vk_harness vk_texture_test vk_compute_test vk_store_test vk_pipeline_check)
    add_executable(${tool} test/${tool}.cpp)
    target_include_directories(${tool} PRIVATE ${Vulkan_INCLUDE_DIRS})
    target_compile_definitions(${tool} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  endforeach()
else()
  message(STATUS "Vulkan SDK not found: GPU test tools and vk_pipeline_check are not built")
endif()

# Opt-in, data-only PE validation tests; never launch the runtime or a game image.
option(LEONIDA_PE_VALIDATION_TESTS "Build PE preflight tests" OFF)
if(LEONIDA_PE_VALIDATION_TESTS)
  enable_testing()
  add_executable(pe_validation_test test/pe_validation_test.cpp)
  target_compile_options(pe_validation_test PRIVATE /W4 /permissive- /utf-8)
  add_test(NAME pe_validation COMMAND pe_validation_test)
  add_executable(pe_relocation_test test/pe_relocation_test.cpp)
  target_compile_options(pe_relocation_test PRIVATE /W4 /permissive- /utf-8)
  add_test(NAME pe_relocations COMMAND pe_relocation_test)
  add_executable(pe_symbols_test test/pe_symbols_test.cpp)
  target_compile_options(pe_symbols_test PRIVATE /W4 /permissive- /utf-8)
  add_test(NAME pe_symbols COMMAND pe_symbols_test)
  add_executable(dll_policy_test test/dll_policy_test.cpp)
  target_compile_options(dll_policy_test PRIVATE /W4 /permissive- /utf-8)
  add_test(NAME dll_policy COMMAND dll_policy_test)
  add_executable(loader_limits_test test/loader_limits_test.cpp)
  target_compile_options(loader_limits_test PRIVATE /W4 /permissive- /utf-8)
  add_test(NAME loader_limits COMMAND loader_limits_test)
  add_executable(loader_lifecycle_test test/loader_lifecycle_test.cpp src/pe_loader.cpp)
  target_compile_definitions(loader_lifecycle_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
  target_compile_options(loader_lifecycle_test PRIVATE /W4 /permissive- /utf-8)
endif()

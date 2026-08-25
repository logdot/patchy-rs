cmake_minimum_required(VERSION 3.24)

project(Patchy VERSION 0.2.0 LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Patchy currently supports only 64-bit Windows")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Patchy requires a 64-bit CMake toolchain")
endif()

find_program(PATCHY_CARGO_EXECUTABLE cargo REQUIRED)

set(
    PATCHY_CARGO_TARGET
    "x86_64-pc-windows-msvc"
    CACHE STRING
    "Rust target used to build Patchy"
)
set(
    PATCHY_CARGO_PROFILE
    "release"
    CACHE STRING
    "Cargo profile used to build Patchy"
)
set(
    PATCHY_CARGO_TARGET_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/cargo-target"
    CACHE PATH
    "Cargo target directory used by the Patchy CMake build"
)
option(PATCHY_BUILD_EXAMPLE "Build the C++ injected-module example" OFF)
option(PATCHY_EXAMPLE_LINK_STATIC "Link the C++ example to Patchy's static library" OFF)

if(PATCHY_CARGO_PROFILE STREQUAL "release")
    set(_patchy_cargo_profile_arguments --release)
    set(_patchy_artifact_profile "release")
elseif(PATCHY_CARGO_PROFILE STREQUAL "dev")
    set(_patchy_cargo_profile_arguments)
    set(_patchy_artifact_profile "debug")
else()
    set(_patchy_cargo_profile_arguments --profile "${PATCHY_CARGO_PROFILE}")
    set(_patchy_artifact_profile "${PATCHY_CARGO_PROFILE}")
endif()

set(
    _patchy_artifact_directory
    "${PATCHY_CARGO_TARGET_DIR}/${PATCHY_CARGO_TARGET}/${_patchy_artifact_profile}"
)
set(_patchy_shared_library "${_patchy_artifact_directory}/patchy_ffi.dll")
set(_patchy_import_library "${_patchy_artifact_directory}/patchy_ffi.dll.lib")
set(_patchy_static_library "${_patchy_artifact_directory}/patchy_ffi.lib")
set(_patchy_debug_symbols "${_patchy_artifact_directory}/patchy_ffi.pdb")

file(
    GLOB_RECURSE
    _patchy_rust_sources
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.rs"
    "${CMAKE_CURRENT_SOURCE_DIR}/patchy-ffi/src/*.rs"
)

add_custom_command(
    OUTPUT
        "${_patchy_shared_library}"
        "${_patchy_import_library}"
        "${_patchy_static_library}"
    COMMAND
        "${CMAKE_COMMAND}" -E env
        "CARGO_TARGET_DIR=${PATCHY_CARGO_TARGET_DIR}"
        "${PATCHY_CARGO_EXECUTABLE}" build
        --package patchy-ffi
        --target "${PATCHY_CARGO_TARGET}"
        ${_patchy_cargo_profile_arguments}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
        "${CMAKE_CURRENT_SOURCE_DIR}/patchy-ffi/Cargo.toml"
        ${_patchy_rust_sources}
    COMMENT "Building Patchy C ABI libraries with Cargo"
    VERBATIM
)

add_custom_target(
    patchy_cargo_build
    ALL
    DEPENDS
        "${_patchy_shared_library}"
        "${_patchy_import_library}"
        "${_patchy_static_library}"
)

add_library(patchy_ffi_shared SHARED IMPORTED GLOBAL)
set_target_properties(
    patchy_ffi_shared
    PROPERTIES
        IMPORTED_LOCATION "${_patchy_shared_library}"
        IMPORTED_IMPLIB "${_patchy_import_library}"
        INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
add_dependencies(patchy_ffi_shared patchy_cargo_build)
add_library(Patchy::ffi ALIAS patchy_ffi_shared)

add_library(patchy_ffi_static STATIC IMPORTED GLOBAL)
set_target_properties(
    patchy_ffi_static
    PROPERTIES
        IMPORTED_LOCATION "${_patchy_static_library}"
        INTERFACE_COMPILE_DEFINITIONS PATCHY_STATIC
        INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include"
        INTERFACE_LINK_LIBRARIES "advapi32;bcrypt;kernel32;ntdll;userenv;ws2_32"
)
add_dependencies(patchy_ffi_static patchy_cargo_build)
add_library(Patchy::ffi_static ALIAS patchy_ffi_static)

include(CMakePackageConfigHelpers)

set(_patchy_package_directory "lib/cmake/Patchy")
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PatchyConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/PatchyConfig.cmake"
    INSTALL_DESTINATION "${_patchy_package_directory}"
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/PatchyConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)

install(FILES "${_patchy_shared_library}" DESTINATION bin)
install(FILES "${_patchy_import_library}" DESTINATION lib)
install(FILES "${_patchy_static_library}" DESTINATION lib)
install(FILES "${_patchy_debug_symbols}" DESTINATION bin OPTIONAL)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/patchy.h" DESTINATION include)
install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/PatchyConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/PatchyConfigVersion.cmake"
    DESTINATION "${_patchy_package_directory}"
)
install(
    FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
        "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
    DESTINATION .
)
install(
    DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/examples/cpp"
    DESTINATION examples
    PATTERN "build" EXCLUDE
)

if(PATCHY_BUILD_EXAMPLE)
    add_subdirectory(examples/cpp)
endif()

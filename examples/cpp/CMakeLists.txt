cmake_minimum_required(VERSION 3.24)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(PatchyCppExample LANGUAGES CXX)
    option(PATCHY_EXAMPLE_LINK_STATIC "Link to Patchy's static library" OFF)
    find_package(Patchy CONFIG REQUIRED)
endif()

add_library(patchy_cpp_example MODULE install_overwrite.cpp)
target_compile_features(patchy_cpp_example PRIVATE cxx_std_17)

if(PATCHY_EXAMPLE_LINK_STATIC)
    target_link_libraries(patchy_cpp_example PRIVATE Patchy::ffi_static)
else()
    target_link_libraries(patchy_cpp_example PRIVATE Patchy::ffi)
    add_custom_command(
        TARGET patchy_cpp_example
        POST_BUILD
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
            "$<TARGET_FILE:Patchy::ffi>"
            "$<TARGET_FILE_DIR:patchy_cpp_example>"
        VERBATIM
    )
endif()

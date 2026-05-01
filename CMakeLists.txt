cmake_minimum_required(VERSION 3.20)
project(agent_safe_guard_native LANGUAGES C CXX)

option(SG_BUILD_NATIVE "Build native daemon and hook clients" ON)

if(NOT SG_BUILD_NATIVE)
  return()
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SG_BUILD_REPOMAP "Build repomap module (requires third_party submodules)" ON)
option(SG_BUILD_TESTS "Build C++ unit tests (uses third_party/doctest)" OFF)
# Sanitizer mode for bounds-checked test/debug builds. Acceptable values:
#   address, undefined, address;undefined, thread, leak, off (or empty).
# Memory safety in this project is non-negotiable — every CI build runs the
# unit suite with SG_SANITIZER=address. See CLAUDE.md "Memory & resource
# safety" for the contract that mandates this.
set(SG_SANITIZER "" CACHE STRING "Sanitizer to enable (address, undefined, thread, ...)")

if(SG_SANITIZER AND NOT SG_SANITIZER STREQUAL "off")
  message(STATUS "agent-safe-guard: building with -fsanitize=${SG_SANITIZER}")
  add_compile_options(-fsanitize=${SG_SANITIZER} -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=${SG_SANITIZER})
endif()

if(SG_BUILD_REPOMAP)
  add_subdirectory(third_party)
endif()

add_subdirectory(native)

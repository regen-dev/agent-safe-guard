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

if(SG_BUILD_REPOMAP)
  add_subdirectory(third_party)
endif()

add_subdirectory(native)

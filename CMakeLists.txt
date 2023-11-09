cmake_minimum_required(VERSION 3.17)

project(reflective_loader)

set(CMAKE_C_STANDARD 11)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(DEBUG)
endif()

add_executable(ReflectiveLoader src/reflective_loader.c)

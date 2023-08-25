
cmake_minimum_required(VERSION 3.17)

project(ReflectiveLoader)

set(CMAKE_C_STANDARD 11)

option(DEBUG_MODE "Build with debug information" OFF)

if(DEBUG_MODE)
  set(CMAKE_BUILD_TYPE Debug)
  add_definitions(-DDEBUG)
else()
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(ReflectiveLoader src/reflective_loader.c)
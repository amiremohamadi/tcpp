cmake_minimum_required(VERSION 3.15)

project(
    tcpp
    DESCRIPTION "C++ implemention of tcp"
)

set(CMAKE_CXX_STANDARD 11)

# required modules
include(ExternalProject)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
)


file(GLOB SRCS
    "${CMAKE_SOURCE_DIR}/src/*.cc"
)

add_executable(tcpp main.cc ${SRCS})


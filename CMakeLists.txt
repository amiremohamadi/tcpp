cmake_minimum_required(VERSION 3.15)

project(
    tcpp
    DESCRIPTION "C++ implemention of tcp"
)

set(CMAKE_CXX_STANDARD 11)

# required modules
include(ExternalProject)

# include thirdparties and base include directories
include(${CMAKE_SOURCE_DIR}/third_party/fmt.cmake)
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${FMT_INCLUDE}
)


file(GLOB SRCS
    "${CMAKE_SOURCE_DIR}/src/*.cc"
)

# add_subdirectory(${CMAKE_BINARY_DIR}/${FMT_PREFIX}/src/${FMT_PREFIX})
add_executable(tcpp main.cc ${SRCS})
target_link_libraries(tcpp ${FMT_LIB})


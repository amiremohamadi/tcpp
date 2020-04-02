# we're using fmt 6.1.2 version
set(FMT_PREFIX fmt612)
set(FMT_URL https://github.com/fmtlib/fmt/releases/download/6.1.2/fmt-6.1.2.zip)

ExternalProject_Add(
    ${FMT_PREFIX}
    PREFIX ${FMT_PREFIX}
    URL ${FMT_URL}
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND cmake .
    BUILD_COMMAND cmake --build .
    INSTALL_COMMAND ""
)

set(FMT_LIB ${CMAKE_BINARY_DIR}/${FMT_PREFIX}/src/${FMT_PREFIX}/libfmt.a)


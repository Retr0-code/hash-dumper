cmake_minimum_required(VERSION 3.16.0)

project(hash_dumper
    VERSION 1.0.3
    DESCRIPTION "Windows NTLM hash dumper"
    HOMEPAGE_URL "https://github.com/Retr0-code/hash-dumper"
)

# Initializing parameters
option(DEBUG "Sets compilation flags for debugging" OFF)
option(RELEASE "Sets compilation flags for optimized binary" OFF)
option(BUILD32 "Sets compilation flags for 32-bit mode" OFF)
set(INSTALL_PREFIX /usr/local/bin CACHE PATH "Path for installed binaries")

# Checking parameters
set(CMAKE_INSTALL_PREFIX ${INSTALL_PREFIX})

if ((DEBUG) AND (NOT RELEASE))
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
        add_compile_options(-O0)
        add_compile_options(-ggdb)

    elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        add_compile_options(-O0)
        add_compile_options(-g)

    else()
        message(FATAL_ERROR "Unknown compiler ${CMAKE_C_COMPILER_ID}")
    endif()

    message(STATUS "Enabled debug mode")

endif()

if ((NOT DEBUG) AND (RELEASE))
    message(STATUS "Enabled release with -O3")
    add_compile_options(-O3)
endif()

if (BUILD32)
    message(STATUS "Enabled 32-bit mode")
    add_compile_options(-m32)
    add_link_options(-m32)
    SET(CMAKE_LIBRARY_PATH "/usr/lib/i386-linux-gnu")
    include_directories(BEFORE /usr/include/i386-linux-gnu)
endif()

# Source code paths
set(EXEC_SRC
    src/main.c
    src/hive.c
    src/crypto.c
    src/dump_hives.c
    src/functional.c
    src/arg_parser.c
    src/dump_bootkey.c
    src/dump_hashes.c
    src/string-hashtable/hash_table.c
    )

# Link openssl and build executable
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} ${EXEC_SRC})
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

install(TARGETS ${PROJECT_NAME} DESTINATION .)
message(STATUS "WARNING! Installation prefix ${CMAKE_INSTALL_PREFIX}")

# Cleanup cache
unset(DEBUG CACHE)
unset(RELEASE CACHE)
unset(BUILD32 CACHE)
unset(INSTALL_PREFIX CACHE)

unset(CMAKE_LIBRARY_PATH CACHE)
unset(CMAKE_INSTALL_PREFIX CACHE)

unset(OPENSSL_FOUND CACHE)
unset(OPENSSL_INCLUDE_DIR CACHE)
unset(OPENSSL_CRYPTO_LIBRARY CACHE)
unset(OPENSSL_CRYPTO_LIBRARIES CACHE)
unset(OPENSSL_SSL_LIBRARY CACHE)
unset(OPENSSL_SSL_LIBRARIES CACHE)
unset(OPENSSL_LIBRARIES CACHE)
unset(OPENSSL_VERSION CACHE)

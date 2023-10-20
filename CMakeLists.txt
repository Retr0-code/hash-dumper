cmake_minimum_required(VERSION 3.17.0)

project(hash-dumper
    VERSION 0.1
    DESCRIPTION "Windows NTLM hash dumper"
    HOMEPAGE_URL "https://github.com/Retr0-code/hash-dumper"
)

set(EXEC_SRC
    src/main.c
    src/hive.c
    src/crypto.c
    src/dump_hives.c
    src/functional.c
    src/arg_parser.c
    src/dump_bootkey.c
    src/string-hashtable/hash_table.c
    )

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} ${EXEC_SRC})
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

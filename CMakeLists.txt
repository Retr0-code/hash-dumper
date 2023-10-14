cmake_minimum_required(VERSION 3.17.0)

project(hash-dumper
    VERSION 0.1
    DESCRIPTION "Windows NTLM hash dumper"
    HOMEPAGE_URL "https://github.com/Retr0-code/hash-dumper"
)

set(EXEC_SRC
    main.c
    hive.c
    hash_dump.c
    functional.c
    dump_bootkey.c
    )

set(EXEC_HEAD
    hive.h
    hash_dump.h
    functional.h
    dump_bootkey.h
    )

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} ${EXEC_SRC})
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
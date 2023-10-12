/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

	This header describes functions for linux integration and utilitarian functions
*/

#ifndef FUNCTIONAL_H
#define FUNCTIONAL_H

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/md5.h>

#if defined(__linux__) || defined(__unix__)

#include <wchar.h>
#include <byteswap.h>

typedef unsigned long long errno_t;

#define BYTE_SWAP16(x) bswap_16(x)
#define BYTE_SWAP32(x) bswap_32(x)
#define BYTE_SWAP64(x) bswap_64(x)

#define GetLastError() errno

wchar_t* fgetws(wchar_t* str, int numChars, FILE* stream);


#elif defined(_WIN32) || defined(_WIN64)

#define BYTE_SWAP16(x) _byteswap_ushort(x)
#define BYTE_SWAP32(x) _byteswap_ulong(x)
#define BYTE_SWAP64(x) _byteswap_uint64(x)

#endif

// Allocates memory and returns status on error
#define malloc_check(ptr_name, mem_size, status) malloc(mem_size); \
if (ptr_name == NULL) \
{ \
	errno = ENOMEM; \
	return status; \
}

// Allocates memory on error deletes specied pointers and returns status
#define malloc_check_clean(ptr_name, mem_size, status, ptrs_amount, ...) malloc(mem_size); \
if (ptr_name == NULL) \
{ \
	cleanup_pointers(ptrs_amount, __VA_ARGS__); \
	errno = ENOMEM; \
	return status; \
}

// Deallocates pointers (if amount of pointers are odd then you have to pass aditional NULL)
void cleanup_pointers(size_t amount, ...);

// Returns md5 hash of specified data
uint8_t* get_md5(const char* data, size_t data_size);

#endif

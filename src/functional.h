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

/*! \file functional.h
 *	\brief This header describes functions for linux integration and utilitarian functions.
 */

#ifndef FUNCTIONAL_H
#define FUNCTIONAL_H

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <uchar.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#if defined(__linux__) || defined(__unix__)

#include <byteswap.h>

typedef unsigned long long errno_t;

#define BYTE_SWAP16(x) bswap_16(x)
#define BYTE_SWAP32(x) bswap_32(x)
#define BYTE_SWAP64(x) bswap_64(x)

#define GetLastError() errno

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

/*! \fn void cleanup_pointers(size_t amount, ...)
 *	\brief Deallocates pointers of specified amount.
 *	\param[in] amount	amount of specified pointers.
 *	\param[in] ...		pointers variadic list.
 */
void cleanup_pointers(size_t amount, ...);

/*! \fn char* get_random_string(size_t length)
 *	\brief Generates random ASCII string of specified length.
 *	\param[in] length	length of ASCII string.
 */
char* get_random_string(size_t length);

/*! \fn void bytes_to_hex(uint8_t* input, size_t length, char* output)
 *	\brief Converts array of bytes to ASCII hexadecimal string.
 *	\param[in] input	array of uint8_t (bytes).
 *	\param[in] length	length of bytes meant to be read.
 *	\param[out] output	ASCII hexadecimal string.
 */
void bytes_to_hex(uint8_t* input, size_t length, char* output);

#ifdef __linux__

/*! \fn wchar_t* u16_to_u32(const char16_t* u16_input_str)
 *	\brief Converts UTF-16 string to UTF-32 string.
 *	\param[in] u16_input_str	UTF-16 const string (must have NULL terminator in the end).
 *	\return	linux UTF-32 wchar_t string or NULL on error.
 */
wchar_t* u16_to_u32(const char16_t* u16_input_str);

#endif

#endif

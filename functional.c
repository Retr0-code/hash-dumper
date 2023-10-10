/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

	This file defines functions for linux integration and utilitarian functions
*/
#include "functional.h"

void cleanup_pointers(size_t amount, ...)
{
    va_list pointers;
    va_start(pointers, amount);

    for (; amount > 0; amount--)
        free(va_arg(pointers, char*));

    va_end(pointers);
}

uint8_t* get_md5(const char* data, size_t data_size)
{
	EVP_MD_CTX* context = EVP_MD_CTX_new();
	const EVP_MD* md5 = EVP_md5();

	// Initializing context with md5 algorithm
	if (EVP_DigestInit_ex2(context, md5, NULL) == 0)
	{
		EVP_MD_CTX_free(context);
		EVP_MD_free(md5);
		errno = EFAULT;
		return NULL;
	}
	
	size_t hash_size = EVP_MD_size(md5);
	uint8_t* raw_hash = OPENSSL_malloc(hash_size);

	// Hashing given data
	if (EVP_DigestUpdate(context, data, data_size) == 0)
	{
		EVP_MD_CTX_free(context);
		EVP_MD_free(md5);
		errno = EBADF;
		return NULL;
	}

	// Saving the hash to array
	if (EVP_DigestFinal_ex(context, raw_hash, NULL) == 0)
	{
		EVP_MD_CTX_free(context);
		EVP_MD_free(md5);
		return NULL;
	}

	EVP_MD_CTX_free(context);
	EVP_MD_free(md5);
	return raw_hash;
}

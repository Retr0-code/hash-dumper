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


#if defined(__linux__) || defined(__unix__)
wchar_t* fgetws(wchar_t* str, int num_chars, FILE* stream)
{
	wchar_t* temp_str = malloc_check(num_chars * sizeof(wchar_t), NULL);
	wchar_t read_char = 0xffff;
	size_t read_amount = 0;
	--num_chars;

	// While char is not a null or new line and amount of read bytes is less then allocated memory
	for (; (read_char != (wchar_t)'\0' || read_char != (wchar_t)0x0D0A) && (read_amount < num_chars); read_amount++)
	{
		if (fread(&read_char, sizeof(read_char), 1, stream) != 1)
		{
			free(temp_str);
			return NULL;
		}

		temp_str[read_amount] = read_char;
	}
	++read_amount;

	temp_str[read_amount] = '\0';

	if (read_amount == num_chars)
	{
		str = temp_str;
		return temp_str;
	}

	str = malloc_check(read_amount, NULL);
	memcpy(str, temp_str, sizeof(wchar_t) * read_amount);
	free(temp_str);
	return str;
}
#endif

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

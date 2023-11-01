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

char* get_random_string(size_t length)
{
	// Validating parameter
	if (length == 0)
	{
		errno = EINVAL;
		return NULL;
	}

	// Allocating string
	char* str = malloc_check(str, length + 1, NULL);
	srand(time(NULL));

	// Generating string
	for (size_t i = 0; i < length; i++)
		str[i] = rand() % (0x5b - 0x41) + 0x41;

	str[length] = '\0';
	return str;
}

void bytes_to_hex(uint8_t* input, size_t length, char* output)
{
	for (size_t i = 0; i < length; i++)
		output += sprintf(output, "%02x", input[i]);
}

#ifdef __linux__

wchar_t* u16_to_u32(const char16_t* u16_input_str)
{
	if (u16_input_str == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	size_t u16_length = 0;
	while (u16_input_str[u16_length++]);
	--u16_length;

	wchar_t* u32_output_str = malloc_check(u32_output_str, (u16_length + 1) * sizeof(wchar_t), NULL);
	memset(u32_output_str, 0, (u16_length + 1) * sizeof(wchar_t));
	for (size_t i = 0; i < u16_length; i++)
		u32_output_str[i] = u16_input_str[i];

	return u32_output_str;
}

#endif
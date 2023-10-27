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
		return -1;
	}

	// Allocating string
	char* str = malloc_check(str, length + 1, -2);
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

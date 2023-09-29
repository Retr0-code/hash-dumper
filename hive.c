/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.


----

	References used:
	 - Registry hive basics and structure / https://binaryforay.blogspot.com/2015/01/registry-hive-basics.html?m=1
	 - Windows registry foremat specs / https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
*/


#include "hive.h"

int read_hive_header(FILE* hive_ptr, hive_header_t* hive_header_ptr)
{
	// Validates hive fd
	if (hive_ptr == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	// Checks if allocated
	if (hive_header_ptr == NULL)
		return -2;

	// Set cursor to specified offset
	if (fseek(hive_ptr, 0, SEEK_SET) != 0)
		return -3;

	// Read signature struct
	if (fread(hive_header_ptr, sizeof(hive_header_t) - sizeof(wchar_t) * 255, 1, hive_ptr) != 1)
		return -4;

#if (ENDIANNESS == LITTLE_ENDIAN)
	hive_header_ptr->last_write_time = _byteswap_uint64(hive_header_ptr->last_write_time);
#endif

	// Check signature
	if (hive_header_ptr->signature != HIVE_SIGN)
	{
		errno = EBADF;
		return -5;
	}

	// Get filename
	if (fgetws(hive_header_ptr->name, 255, hive_ptr) == NULL)
	{
		return -6;
	}

	return 0;
}

int read_key(const uint64_t offset, const uint32_t root_offset, FILE* hive_ptr, abstract_key_t* key)
{
	// Validates hive fd
	if (hive_ptr == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	// Checks if allocated
	if (key == NULL)
		return -2;


	// Set cursor to specified offset
	if (_fseeki64(hive_ptr, offset, SEEK_SET) != 0)
		return -3;

	if (offset % 0x1000 == 0)
	{
		// Read hbin signature
		uint32_t hbin;
		if (fread(&hbin, sizeof(uint32_t), 1, hive_ptr) != 1)
			return -4;

		// Validate key signature
		if (hbin != HBIN_SIGN)
		{
			errno = EBADF;
			return -5;
		}
	}

	// Set cursor to root offset
	if (_fseeki64(hive_ptr, root_offset - 4, SEEK_CUR) != 0)
		return -6;

	// Read sign and size
	if (fread(key, sizeof(abstract_key_t) - sizeof(key->data), 1, hive_ptr) != 1)
		return -7;

	// Allocate memory for key data
	key->data = malloc(0 - key->size);
	if (key->data == NULL)
		return -8;

	// Read the key
	if (fread(key->data, 0 - key->size, 1, hive_ptr) != 1)
		return -9;

	return 0;
}

named_key_t* convert_to_nk(abstract_key_t* reg_key)
{
	named_key_t* nk_ptr = malloc(sizeof(named_key_t));

	if (nk_ptr == NULL)
		return -1;

	// Copies base values to new struct
	memcpy(nk_ptr, reg_key, sizeof(abstract_key_t) - sizeof(char*));
	
	// Validates a signature
	if (nk_ptr->signature != NK_SIGN)
	{
		errno = EBADF;
		return -2;
	}

	memcpy(
		&nk_ptr->flags,
		reg_key->data,
		(sizeof(abstract_key_t) - sizeof(char*)) - reg_key->size
	);

	// Allocate memory for key's name
	nk_ptr->name = malloc(nk_ptr->name_length + 1);
	if (nk_ptr->name == NULL)
		return -3;

	memcpy(nk_ptr->name, &reg_key->data[sizeof(named_key_t) - sizeof(char*) - 6], nk_ptr->name_length);

	nk_ptr->name[nk_ptr->name_length] = '\0';

#if (ENDIANNESS == LITTLE_ENDIAN)
	nk_ptr->flags = _byteswap_ushort(nk_ptr->flags);
#endif

	return nk_ptr;
}

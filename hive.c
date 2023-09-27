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
	hive_header_ptr->signature = _byteswap_ulong(hive_header_ptr->signature);
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

int read_key(uint64_t offset, uint32_t root_offset, FILE* hive_ptr, abstract_key_t* key)
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

	// Read hbin signature
	char hbin[4];
	if (fread(hbin, 4, 1, hive_ptr) != 1)
		return -4;

	// Validate key signature
	if (strcmp(hbin, "hbin") == 0)
	{
		errno = EINVAL;
		return -5;
	}

	// Set cursor to root offset
	if (_fseeki64(hive_ptr, root_offset - 4, SEEK_CUR) != 0)
		return -6;

	// Read sign and size
	if (fread(key, sizeof(abstract_key_t) - sizeof(key->data), 1, hive_ptr) != 1)
		return -7;

#if (ENDIANNESS == LITTLE_ENDIAN)
	key->signature = _byteswap_ushort(key->signature);
#endif

	if (key->size < 0)
		key->size = 0 - key->size;

	key->data = malloc(key->size);
	if (key->data == NULL)
		return -8;

	if (fread(key->data, key->size, 1, hive_ptr) != 1)
		return -9;

	return 0;
}

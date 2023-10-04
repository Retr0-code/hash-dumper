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

#if (HV_ENDIANNESS == HV_BIG_ENDIAN)
	hive_header_ptr->last_write_time = BYTE_SWAP64(hive_header_ptr->last_write_time);
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

int read_named_key(const uint32_t root_offset, FILE* hive_ptr, named_key_t* nk_ptr)
{
	if (root_offset == 0)
	{
		errno = EINVAL;
		return -1;
	}

	// Validation of hive fd
	if (hive_ptr == NULL)
	{
		errno = EINVAL;
		return -2;
	}

	// Checking if allocated
	if (nk_ptr == NULL)
		return -3;

	// Setting cursor to named key offset
	if (fseek(hive_ptr, 0x1000 + root_offset, SEEK_SET) != 0)
		return -4;

	// Reading structure
	if (fread(nk_ptr, sizeof(named_key_t) - sizeof(nk_ptr->name), 1, hive_ptr) != 1)
		return -5;

	// Validation of a signature
	if (nk_ptr->signature != NK_SIGN)
	{
		errno = EBADF;
		return -6;
	}

	// If size less then 0 it means that node is in use, otherwise it's not
	if (nk_ptr->size >= 0)
	{
		errno = EBADF;
		return -7;
	}

	// Inverse the size
	nk_ptr->size = 0 - nk_ptr->size;

#if (HV_ENDIANNESS == HV_BIG_ENDIAN)
	nk_ptr->flags = BYTE_SWAP16(nk_ptr->flags);
#endif

	nk_ptr->name = malloc(nk_ptr->name_length + 1);
	if (nk_ptr->name == NULL)
		return -8;

	if (fread(nk_ptr->name, nk_ptr->name_length, 1, hive_ptr) != 1)
		return -9;

	nk_ptr->name[nk_ptr->name_length] = '\0';
	return 0;
}

int read_vk_list(const uint32_t root_offset, FILE* hive_ptr, value_list_t* vk_list_ptr)
{
	// Validation of parameters
	if (root_offset == 0)
	{
		errno = EINVAL;
		return -1;
	}

	if (hive_ptr == NULL)
	{
		errno = EINVAL;
		return -2;
	}

	if (vk_list_ptr == NULL)
	{
		errno = EINVAL;
		return -3;
	}

	// Setting cursor by offset parameter
	if (fseek(hive_ptr, 0x1000 + root_offset, SEEK_SET) != 0)
		return -4;

	// Reading size of a list
	if (fread(&vk_list_ptr->size, sizeof(int32_t), 1, hive_ptr) != 1)
		return -5;

	// If size less then 0 it means that node is in use, otherwise it's not
	if (vk_list_ptr->size >= 0)
	{
		errno = EBADF;
		return -6;
	}

	vk_list_ptr->size = 0 - vk_list_ptr->size;

	vk_list_ptr->offsets = malloc(vk_list_ptr->size * sizeof(uint32_t));
	if (vk_list_ptr->offsets == NULL)
	{
		errno = EFAULT;
		return -7;
	}

	// Reading offsets
	if (fread(vk_list_ptr->offsets, vk_list_ptr->size * sizeof(uint32_t), 1, hive_ptr) != 1)
		return -8;

	return 0;
}

int read_value_key(const uint32_t root_offset, FILE* hive_ptr, value_key_t* vk_ptr)
{
	if (root_offset == 0)
	{
		errno = EINVAL;
		return -1;
	}

	// Validation of hive fd
	if (hive_ptr == NULL)
	{
		errno = EINVAL;
		return -2;
	}

	// Checking if allocated
	if (vk_ptr == NULL)
		return -3;

	// Setting cursor to value key offset
	if (fseek(hive_ptr, 0x1000 + root_offset, SEEK_SET) != 0)
		return -4;

	if (fread(vk_ptr, sizeof(value_key_t) - sizeof(vk_ptr->name), 1, hive_ptr) != 1)
		return -5;

	// Validation of a signature
	if (vk_ptr->signature != VK_SIGN)
	{
		errno = EBADF;
		return -6;
	}

	// If size less then 0 it means that node is in use, otherwise it's not
	if (vk_ptr->size >= 0)
	{
		errno = EBADF;
		return -7;
	}

	// Inverse the size
	vk_ptr->size = 0 - vk_ptr->size;

#if (HV_ENDIANNESS == HV_BIG_ENDIAN)
	nk_ptr->flags = BYTE_SWAP16(nk_ptr->flags);
#endif

	// If value does not have a name then it is (Default)
	if (vk_ptr->name_length == 0)
	{
		vk_ptr->name = "(Default)";
		return 0;
	}

	vk_ptr->name = malloc(vk_ptr->size + 1);
	if (vk_ptr->name == NULL)
		return -8;

	// Reading value's name (ASCII)
	if (fread(vk_ptr->name, vk_ptr->name_length, 1, hive_ptr) != 1)
		return -9;

	vk_ptr->name[vk_ptr->name_length] = '\0';

	return 0;
}

reg_path_t* reg_make_path(const uint32_t depth, const char** reg_path)
{
	// Validation of given parameters
	if (depth == 0)
	{
		errno = EINVAL;
		return NULL;
	}

	if (reg_path == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	// Allocation of registry path struct
	reg_path_t* reg_path_ptr = malloc(sizeof(reg_path_t));

	if (reg_path_ptr == NULL)
	{
		errno = EFAULT;
		return NULL;
	}

	// Setting given values
	reg_path_ptr->size = depth;
	reg_path_ptr->nodes = reg_path;

	// Allocation of hints list (first 4 bytes from name)
	reg_path_ptr->nodes_hints = malloc(reg_path_ptr->size * sizeof(uint32_t));
	if (reg_path_ptr->nodes_hints == NULL)
	{
		free(reg_path_ptr);
		errno = EFAULT;
		return NULL;
	}

	// Filling signatures values
	for (size_t i = 0; i < reg_path_ptr->size; i++)
		reg_path_ptr->nodes_hints[i] = *((uint32_t*)(reg_path_ptr->nodes[i]));

	return reg_path_ptr;
}

int reg_enum_subkey(const named_key_t* base_nk_ptr, const reg_path_t* reg_path_ptr, FILE* hive_ptr, named_key_t* out_nk_ptr)
{
	// Validation of parameters
	if (base_nk_ptr == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	if (reg_path_ptr == NULL)
	{
		errno = EINVAL;
		return -2;
	}

	if (hive_ptr == NULL)
	{
		errno = EINVAL;
		return -3;
	}
	
	if (out_nk_ptr == NULL)
	{
		errno = EINVAL;
		return -4;
	}

	// Condition to end a recursion
	if (reg_path_ptr->size == 0)
		return 0;
	else
		out_nk_ptr->name = NULL;	// Because we do not need a name, when node is not requiered

	// Setting cursor by offset parameter
	if (fseek(hive_ptr, 0x1000 + base_nk_ptr->subkey_offset, SEEK_SET) != 0)
		return -5;

	// Reading fast leaf (offsets list)
	fast_leaf_t sub_keys;
	if (fread(&sub_keys, sizeof(fast_leaf_t) - sizeof(sub_keys.elements), 1, hive_ptr) != 1)
		return -6;

	// Validation of a signature
	if (sub_keys.signature != LF_SIGN)
	{
		errno = EBADF;
		return -7;
	}

	// Checking if elements are existing
	if (sub_keys.elements_amount == 0)
	{
		return -8;
	}

	// If size less then 0 it means that node is in use, otherwise it's not
	if (sub_keys.size >= 0)
	{
		errno = EBADF;
		return -9;
	}

	sub_keys.size = 0 - sub_keys.size;

	// Allocating space for fast leaf elements
	sub_keys.elements = malloc(sub_keys.elements_amount * sizeof(lf_element_t));
	if (sub_keys.elements == NULL)
	{
		errno = EFAULT;
		return -10;
	}

	// Reading elements to array
	if (fread(sub_keys.elements, sub_keys.elements_amount * sizeof(lf_element_t), 1, hive_ptr) != 1)
	{
		free(sub_keys.elements);
		return -11;
	}

	// Searching for offset of embedded key
	uint32_t embedded_nk_offset = 0;
	for (size_t lf_index = 0; lf_index < sub_keys.elements_amount; lf_index++)
	{
		if (sub_keys.elements[lf_index].name_hint == reg_path_ptr->nodes_hints[0])
		{
			embedded_nk_offset = sub_keys.elements[lf_index].node_offset;
			
			if (out_nk_ptr->name != NULL)
				free(out_nk_ptr->name);

			// Reading new key
			if (read_named_key(embedded_nk_offset, hive_ptr, out_nk_ptr))
			{
				free(sub_keys.elements);
				return -14;
			}

			// Checking names if hints are identical
			if (strcmp(out_nk_ptr->name, reg_path_ptr->nodes[0]) == 0)
				break;
		}
	}

	// Checking if embedded key exists in base key
	if (embedded_nk_offset == 0)
	{
		free(sub_keys.elements);
		errno = ENOENT;
		return -12;
	}

	// Delete first node of path
	reg_path_t next_key_path = {
		.size = reg_path_ptr->size - 1,
		.nodes = &reg_path_ptr->nodes[1],
		.nodes_hints = &reg_path_ptr->nodes_hints[1]
	};

	// Start enumeration from new key
	if (reg_enum_subkey(out_nk_ptr, &next_key_path, hive_ptr, out_nk_ptr) != 0)
	{
		free(sub_keys.elements);
		return -15;
	}

	free(sub_keys.elements);
	return 0;
}

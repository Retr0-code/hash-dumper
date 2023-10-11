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

-----

	 	This file defines functions for API for interaction with registry hive file
*/


#include "hive.h"

int read_hive_header(FILE* hive_ptr, hive_header_t* hive_header_ptr)
{
	// Validating parameters
	if (hive_ptr == NULL || hive_header_ptr == NULL)
	{
		errno = EINVAL;
		return hv_invalid_arg;
	}

	// Set cursor to specified offset
	if (fseek(hive_ptr, 0, SEEK_SET) != 0)
		return hv_seek_error;

	// Read signature struct
	if (fread(hive_header_ptr, sizeof(hive_header_t) - sizeof(wchar_t) * 255, 1, hive_ptr) != 1)
		return hv_read_error;

#if (HV_ENDIANNESS == HV_BIG_ENDIAN)
	hive_header_ptr->last_write_time = BYTE_SWAP64(hive_header_ptr->last_write_time);
#endif

	// Check signature
	if (hive_header_ptr->signature != HIVE_SIGN)
	{
		errno = EBADF;
		return hv_invalid_signature;
	}

	// Get filename
	if (fgetws(hive_header_ptr->name, 255, hive_ptr) == NULL)
		return hv_read_error;

	return hv_success;
}

int read_named_key(const uint32_t root_offset, FILE* hive_ptr, named_key_t* nk_ptr)
{
	// Validating parameters
	if (root_offset == 0 || hive_ptr == NULL || nk_ptr == NULL)
	{
		errno = EINVAL;
		return hv_invalid_arg;
	}

	// Setting cursor to named key offset
	if (hive_file_seek(hive_ptr, root_offset) != 0)
		return hv_seek_error;

	// Reading structure
	if (hive_read_struct(hive_ptr, nk_ptr, sizeof(named_key_t) - sizeof(nk_ptr->name)) != 1)
		return hv_read_error;

	// Validation of a signature
	if (nk_ptr->signature != NK_SIGN)
	{
		errno = EBADF;
		return hv_invalid_signature;
	}

	// If size less then 0 it means that node is in use, otherwise it's not
	if (nk_ptr->size >= 0)
	{
		errno = EBADF;
		return hv_inactive_cell;
	}

	// Inverse the size
	nk_ptr->size = 0 - nk_ptr->size;

#if (HV_ENDIANNESS == HV_BIG_ENDIAN)
	nk_ptr->flags = BYTE_SWAP16(nk_ptr->flags);
#endif

	nk_ptr->name = malloc(nk_ptr->name_length + 1);
	if (nk_ptr->name == NULL)
	{
		errno = EFAULT;
		return hv_alloc_error;
	}

	if (fread(nk_ptr->name, nk_ptr->name_length, 1, hive_ptr) != 1)
		return hv_read_error;

	nk_ptr->name[nk_ptr->name_length] = '\0';
	return hv_success;
}

int read_vk_list(const uint32_t root_offset, FILE* hive_ptr, value_list_t* vk_list_ptr)
{
	// Validating parameters
	if (root_offset == 0 || hive_ptr == NULL || vk_list_ptr == NULL)
	{
		errno = EINVAL;
		return hv_invalid_arg;
	}

	// Setting cursor by offset parameter
	if (hive_file_seek(hive_ptr, root_offset) != 0)
		return hv_seek_error;

	// Reading size of a list
	if (fread(&vk_list_ptr->size, sizeof(int32_t), 1, hive_ptr) != 1)
		return hv_read_error;

	// If size less then 0 it means that node is in use, otherwise it's not
	if (vk_list_ptr->size >= 0)
	{
		errno = EBADF;
		return hv_inactive_cell;
	}

	vk_list_ptr->size = 0 - vk_list_ptr->size;

	vk_list_ptr->offsets = malloc(vk_list_ptr->size * sizeof(uint32_t));
	if (vk_list_ptr->offsets == NULL)
	{
		errno = EFAULT;
		return hv_alloc_error;
	}

	// Reading offsets
	if (fread(vk_list_ptr->offsets, vk_list_ptr->size * sizeof(uint32_t), 1, hive_ptr) != 1)
		return hv_read_error;

	return hv_success;
}

int read_value_key(const uint32_t root_offset, FILE* hive_ptr, value_key_t* vk_ptr)
{
	// Validating parameters
	if (root_offset == 0 || hive_ptr == NULL || vk_ptr == NULL)
	{
		errno = EINVAL;
		return hv_invalid_arg;
	}

	// Setting cursor to value key offset
	if (hive_file_seek(hive_ptr, root_offset) != 0)
		return hv_seek_error;

	if (hive_read_struct(hive_ptr, vk_ptr, sizeof(value_key_t) - sizeof(vk_ptr->name)) != 1)
		return hv_read_error;

	// Validation of a signature
	if (vk_ptr->signature != VK_SIGN)
	{
		errno = EBADF;
		return hv_invalid_signature;
	}

	// If size less then 0 it means that node is in use, otherwise it's not
	if (vk_ptr->size >= 0)
	{
		errno = EBADF;
		return hv_inactive_cell;
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
		return hv_success;
	}

	vk_ptr->name = malloc(vk_ptr->size + 1);
	if (vk_ptr->name == NULL)
		return hv_alloc_error;

	// Reading value's name (ASCII)
	if (fread(vk_ptr->name, vk_ptr->name_length, 1, hive_ptr) != 1)
		return hv_read_error;

	vk_ptr->name[vk_ptr->name_length] = '\0';

	return hv_success;
}

reg_path_t* reg_make_path(const uint32_t depth, const char** reg_path)
{
	// Validating parameters
	if (depth == 0 || reg_path == NULL)
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
	// Validating parameters
	if (base_nk_ptr == NULL || reg_path_ptr == NULL || hive_ptr == NULL || out_nk_ptr == NULL)
	{
		errno = EINVAL;
		return hv_invalid_arg;
	}

	// Condition to end a recursion
	if (reg_path_ptr->size == 0)
		return hv_success;
	else
		out_nk_ptr->name = NULL;	// Because we do not need a name, when node is not requiered

	// Setting cursor by offset parameter
	if (hive_file_seek(hive_ptr, base_nk_ptr->subkey_offset) != 0)
		return hv_seek_error;

	// Reading fast leaf (offsets list)
	fast_leaf_t sub_keys;
	if (hive_read_struct(hive_ptr, &sub_keys, sizeof(fast_leaf_t) - sizeof(sub_keys.elements)) != 1)
		return hv_read_error;

	// Validation of a signature
	if (sub_keys.signature != LF_SIGN)
	{
		errno = EBADF;
		return hv_invalid_signature;
	}

	// Checking if elements are existing
	if (sub_keys.elements_amount == 0)
		return hv_inactive_cell;

	// If size less then 0 it means that node is in use, otherwise it's not
	if (sub_keys.size >= 0)
	{
		errno = EBADF;
		return hv_inactive_cell;
	}

	sub_keys.size = 0 - sub_keys.size;

	// Allocating space for fast leaf elements
	sub_keys.elements = malloc(sub_keys.elements_amount * sizeof(lf_element_t));
	if (sub_keys.elements == NULL)
	{
		errno = EFAULT;
		return hv_alloc_error;
	}

	// Reading elements to array
	if (fread(sub_keys.elements, sub_keys.elements_amount * sizeof(lf_element_t), 1, hive_ptr) != 1)
	{
		free(sub_keys.elements);
		return hv_read_error;
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
			{
				int result = read_named_key(embedded_nk_offset, hive_ptr, out_nk_ptr);
				if (result != hv_success)
				{
					free(sub_keys.elements);
					return result;
				}
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
		return hv_no_entity;
	}

	// Delete first node of path
	reg_path_t next_key_path = {
		.size = reg_path_ptr->size - 1,
		.nodes = &reg_path_ptr->nodes[1],
		.nodes_hints = &reg_path_ptr->nodes_hints[1]
	};

	// Start enumeration from new key
	{
		int result = reg_enum_subkey(out_nk_ptr, &next_key_path, hive_ptr, out_nk_ptr);
		if (result != hv_success)
		{
			free(sub_keys.elements);
			return result;
		}
	}

	free(sub_keys.elements);
	return hv_success;
}

int reg_enum_value(const named_key_t* base_nk_ptr, const char* value_name, FILE* hive_ptr, value_key_t* out_vk_ptr)
{
	// Validating parameters
	if (base_nk_ptr == NULL || value_name == NULL || hive_ptr == NULL || out_vk_ptr == NULL)
	{
		errno = EINVAL;
		return hv_invalid_arg;
	}

	// Allocating value list
	value_list_t value_list;
	{
		int result = read_vk_list(base_nk_ptr->value_offset, hive_ptr, &value_list);
		if (result != hv_success)
			return result;
	}

	// Allocating temporary value key
	value_key_t vk_temp;
	// Iterate through values
	for (size_t i = 0; i < base_nk_ptr->values_amount; i++)
	{
		// Read value from offset from the list
		{
			int result = read_value_key(value_list.offsets[i], hive_ptr, &vk_temp);
			if (result != hv_success)
				return result;
		}

		// Validating temp value
		if (strcmp(vk_temp.name, value_name) == 0)
		{
			memcpy(out_vk_ptr, &vk_temp, sizeof(value_key_t));
			return hv_success;
		}
	}

	errno = ENXIO;
	return hv_no_entity;
}

void* reg_get_value(const value_key_t* vk_ptr, FILE* hive_ptr)
{
	// Validating parameters
	if (vk_ptr == NULL || hive_ptr == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	// Allocating space for a value
	void* value = malloc(vk_ptr->data_size);
	if (value == NULL)
	{
		errno = EFAULT;
		return NULL;
	}

	// Moving cursor to value position
	if (hive_file_seek(hive_ptr, vk_ptr->data_offset_val + 4) != 0)
		return NULL;

	// Reading value
	if (fread(value, vk_ptr->data_size, 1, hive_ptr) != 1)
	{
		free(value);
		return NULL;
	}

	return value;
}

wchar_t* reg_get_class(named_key_t* nk_ptr, FILE* hive_ptr)
{
    // Validating parameters
	if (nk_ptr == NULL || hive_ptr == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	// Moving cursor to value position
	if (hive_file_seek(hive_ptr, nk_ptr->class_name_offset) != 0)
		return NULL;

	// Reading length
	if (fread(&nk_ptr->class_length, sizeof(nk_ptr->class_length), 1, hive_ptr) != 1)
		return NULL;

	if (nk_ptr->class_length >= 0)
	{
		errno = EBADF;
		return NULL;
	}

	nk_ptr->class_length = 0 - nk_ptr->class_length;

	// Allocating space for a value
	wchar_t* class_value = malloc(nk_ptr->class_length);
	if (class_value == NULL)
	{
		errno = EFAULT;
		return NULL;
	}

	// Reading value
	if (fread(class_value, nk_ptr->class_length, 1, hive_ptr) != 1)
	{
		free(class_value);
		return NULL;
	}

	return class_value;
}

inline int hive_file_seek(FILE* hive_ptr, const uint32_t root_offset)
{
	return fseek(hive_ptr, 0x1000 + root_offset, SEEK_SET);
}

inline size_t hive_read_struct(FILE* hive_ptr, void* hive_struct, size_t read_size)
{
	return fread(hive_struct, read_size, 1, hive_ptr);
}

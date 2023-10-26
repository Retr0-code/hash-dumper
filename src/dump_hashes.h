#ifndef DUMP_HASHES_H
#define DUMP_HASHES_H

#include <stdlib.h>
#include <stdint.h>

#include "hive.h"
#include "crypto.h"


typedef struct
{
	uint32_t rid;
	size_t v_size;
	void* v_value;
	wchar_t* name;
	uint8_t nthash[16];
	uint8_t lmhash[16];
} reg_user_t;

// Reads users named keys from SAM hive. Writes array to users_keys and size of the array to users_amount
int dump_users_keys(FILE* sam_hive, named_key_t** users_keys_array, size_t* users_amount);

// Dumps V value of specified user's key
int dump_v_value(FILE* sam_hive, named_key_t* user_key_ptr, reg_user_t* user_info_ptr);

// Writes ASCII name to user_info_ptr->name
int dump_user_name(reg_user_t* user_info_ptr);

#endif

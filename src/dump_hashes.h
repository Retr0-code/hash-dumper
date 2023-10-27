#ifndef DUMP_HASHES_H
#define DUMP_HASHES_H

#include <stdlib.h>
#include <stdint.h>

#include "hive.h"
#include "crypto.h"

#define EMPTY_LM_HASH	"\xaa\xd3\xb4\x35\xb5\x14\x04\xee\xaa\xd3\xb4\x35\xb5\x14\x04\xee"
#define EMPTY_NT_HASH	"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"
#define NTPASSWORD		"NTPASSWORD"
#define LMPASSWORD		"LMPASSWORD"

typedef struct
{
	uint32_t sid;
	size_t v_size;
	void* v_value;
	wchar_t* name;
	uint8_t* nthash;
	uint8_t* lmhash;
} ntlm_user_t;

typedef enum
{
	hash_lm,
	hash_nt
} hash_type_e;

int ntlm_user_init(ntlm_user_t* user_info_ptr);

int ntlm_user_destroy(ntlm_user_t* user_info_ptr);

// Reads users named keys from SAM hive. Writes array to users_keys and size of the array to users_amount
int dump_users_keys(FILE* sam_hive, named_key_t** users_keys_array, size_t* users_amount);

// Dumps V value of specified user's key
int dump_v_value(FILE* sam_hive, named_key_t* user_key_ptr, ntlm_user_t* user_info_ptr);

// Writes ASCII name to user_info_ptr->name
int dump_user_name(ntlm_user_t* user_info_ptr);

// Dumps users NT and LM hashes to struct
int dump_user_ntlm(ntlm_user_t* user_info_ptr, const uint8_t* hashed_bootkey);

// Decrypts NT/LM hash
int decrypt_ntlm_hash(ntlm_user_t* user_info_ptr, const uint8_t* hashed_bootkey, hash_type_e hash_type);

// Decrypts salted/NTLMv2 hash
int decrypt_salted_hash(
	uint8_t* enc_hash,
	uint8_t* hashed_bootkey,
	uint8_t* salt,
	ntlm_user_t* user_info_ptr,
	uint8_t* decrypted_hash
);

// Converts RID to DES keys
int sid_to_des_keys(uint32_t rid, uint64_t* key1, uint64_t* key2);

// Permutates key to 8-byte DES key
uint64_t permutate_sid_key(uint64_t input_key);

#endif

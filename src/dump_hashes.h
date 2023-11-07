/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

	This header describes functions for dumping NTLM hashes from SAM and SYSTEM
*/

/*! \file dump_hashes.h
 *	\brief This header describes functions for dumping NTLM hashes from SAM and SYSTEM
 */

#ifndef DUMP_HASHES_H
#define DUMP_HASHES_H

#include <uchar.h>
#include <stdlib.h>
#include <stdint.h>

#include "hive.h"
#include "crypto.h"

#define EMPTY_LM_HASH	"\xaa\xd3\xb4\x35\xb5\x14\x04\xee\xaa\xd3\xb4\x35\xb5\x14\x04\xee"
#define EMPTY_NT_HASH	"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"
#define NTPASSWORD		"NTPASSWORD"
#define LMPASSWORD		"LMPASSWORD"

/*! \struct ntlm_user_t
 *	\brief Structs that contains main user info.
 */
typedef struct
{
	uint32_t sid;		//!< User's Security IDentificator.
	size_t v_size;		//!< Size of user's "V" value.
	uint8_t* v_value;	//!< Value of "V" user's value key.
	char16_t* name;		//!< UTF-16 username.
	uint8_t* nthash;	//!< Raw NT hash.
	uint8_t* lmhash;	//!< Raw LM hahs.
} ntlm_user_t;

/*! \enum hash_type_e
 *	\brief Enumeration of hash types used for hash decryption.
 */
typedef enum
{
	hash_lm,	//!< Indicates LM hash as 0.
	hash_nt		//!< Indicates NT hash as 1.
} hash_type_e;

/*!	\typedef decrypt_callback_t
 *	\brief Type for callback function of staged decryption.
 */
typedef int (*decrypt_callback_t)(
	const uint8_t* encrypted_hash,
	const uint8_t* hashed_bootkey,
	const uint8_t* salt,
	const ntlm_user_t* user_info_ptr,
	uint8_t* output
	);

/*! \fn int ntlm_user_init(ntlm_user_t* user_info_ptr)
 *	\brief Initializes \a ntlm_user_t structure.
 *	\param[out] user_info_ptr	User NTLM descriptor unitizalized structure.
 *	\return 0 on success or negative number correlated to step on error.
 */
int ntlm_user_init(ntlm_user_t* user_info_ptr);

/*! \fn int ntlm_user_destroy(ntlm_user_t* user_info_ptr)
 *	\brief Deletes \a ntlm_user_t structure.
 *	\param[in] user_info_ptr	User NTLM descriptor initialized structure.
 *	\return 0 on success or negative number correlated to step on error.
 */
int ntlm_user_destroy(ntlm_user_t* user_info_ptr);

/*! \fn int dump_users_keys(FILE* sam_hive, named_key_t** users_keys_array, size_t* users_amount)
 *	\brief Reads users named keys from SAM hive. Writes array to users_keys and size of the array to users_amount.
 *	\param[in] sam_hive				pointer to file descriptor of SAM hive file.
 *	\param[out] users_keys_array	array of named/node keys of every user.
 *	\param[out] users_amount		amount of parsed users keys.
 *	\return 0 on success or negative number correlated to step on error.
 */
int dump_users_keys(FILE* sam_hive, named_key_t** users_keys_array, size_t* users_amount);

/*! \fn int dump_v_value(FILE* sam_hive, named_key_t* user_key_ptr, ntlm_user_t* user_info_ptr)
 *	\brief Dumps "V" value of specified user's named/node key.
 *	\param[in] sam_hive			pointer to file descriptor of SAM hive file.
 *	\param[in] user_key_ptr		named/node key of specified user.
 *	\param[out] user_info_ptr	user NTLM descriptor structure.
 *	\return 0 on success or negative number correlated to step on error.
 */
int dump_v_value(FILE* sam_hive, named_key_t* user_key_ptr, ntlm_user_t* user_info_ptr);

/*! \fn int dump_user_name(ntlm_user_t* user_info_ptr)
 *	\brief Reads UTF-16 name to user_info_ptr->name from "V" value.
 *	\param[in] user_info_ptr	user NTLM descriptor structure.
 *	\return 0 on success or negative number correlated to step on error.
 */
int dump_user_name(ntlm_user_t* user_info_ptr);

/*! \fn int dump_user_ntlm(ntlm_user_t* user_info_ptr, const uint8_t* hashed_bootkey)
 *	\brief Dumps users NT and LM hashes and writes them to struct.
 *	\param[out] user_info_ptr	user NTLM descriptor structure.
 *	\param[in] hashed_bootkey	raw hashed bootkey.
 *	\return 0 on success or negative number correlated to step on error.
 */
int dump_user_ntlm(ntlm_user_t* user_info_ptr, const uint8_t* hashed_bootkey);

/*! \fn int decrypt_ntlm_hash(ntlm_user_t* user_info_ptr, const uint8_t* hashed_bootkey, const hash_type_e hash_type)
 *	\brief Decrypts NT/LM hash.
 *	\param[out] user_info_ptr	user NTLM descriptor structure.
 *	\param[in] hashed_bootkey	raw hashed bootkey.
 *	\param[in] hash_type		hash type from \a hash_type_e enum.
 *	\return 0 on success or negative number correlated to step on error.
 */
int decrypt_ntlm_hash(ntlm_user_t* user_info_ptr, const uint8_t* hashed_bootkey, const hash_type_e hash_type);

/*! \fn int decrypt_ntlm_hash_wrapper(
	const uint8_t* enc_hash,
	const uint8_t* hashed_bootkey,
	const uint8_t* salt,
	ntlm_user_t* user_info_ptr,
	decrypt_callback_t ntlm_version,
	uint8_t* decrypted_hash
)
 *	\brief Decrypt NTLMv1/2 hashes using callback function.
 *	\param[in] enc_hash			input emcrypted NT/LM hash.
 *	\param[in] hashed_bootkey	raw hashed bootkey used as decryption key.
 *	\param[in] salt				cipher salt.
 *	\param[out] user_info_ptr	user NTLM descriptor structure.
 *	\param[in] ntlm_version		function pointer correlated to NTLM version.
 *	\param[out] decrypted_hash	decrypted NT/LM hash (16 bytes in length).
 *	\return 0 on success or negative number correlated to step on error.
 */
int decrypt_ntlm_hash_wrapper(
	const uint8_t* enc_hash,
	const uint8_t* hashed_bootkey,
	const uint8_t* salt,
	ntlm_user_t* user_info_ptr,
	decrypt_callback_t ntlm_version,
	uint8_t* decrypted_hash
);

/*! \fn int decrypt_ntlmv1_callback(
	const uint8_t* encrypted_hash,
	const uint8_t* hashed_bootkey,
	const uint8_t* salt,
	const ntlm_user_t* user_info_ptr,
	uint8_t* output
)
 *	\brief Callback function for decrypt_ntlm_hash_wrapper, which does staged decryption of NTLMv1.
 *	\param[in] encrypted_hash	input emcrypted NT/LM hash.
 *	\param[in] hashed_bootkey	raw hashed bootkey used as decryption key.
 *	\param[in] salt				cipher salt.
 *	\param[out] user_info_ptr	user NTLM descriptor structure.
 *	\param[out] output			decrypted NT/LM hash (16 bytes in length).
 *	\return 0 on success or negative number correlated to step on error.
 */
int decrypt_ntlmv1_callback(
	const uint8_t* encrypted_hash,
	const uint8_t* hashed_bootkey,
	const uint8_t* salt,
	const ntlm_user_t* user_info_ptr,
	uint8_t* output
);

/*! \fn int decrypt_ntlmv2_callback(
	const uint8_t* encrypted_hash,
	const uint8_t* hashed_bootkey,
	const uint8_t* salt,
	const ntlm_user_t* user_info_ptr,
	uint8_t* output
)
 *	\brief Callback function for decrypt_ntlm_hash_wrapper, which does staged decryption of NTLMv2.
 *	\param[in] encrypted_hash	input emcrypted NT/LM hash.
 *	\param[in] hashed_bootkey	raw hashed bootkey used as decryption key.
 *	\param[in] salt				cipher salt.
 *	\param[out] user_info_ptr	user NTLM descriptor structure.
 *	\param[out] output			decrypted NT/LM hash (16 bytes in length).
 *	\return 0 on success or negative number correlated to step on error.
 */
int decrypt_ntlmv2_callback(
	const uint8_t* encrypted_hash,
	const uint8_t* hashed_bootkey,
	const uint8_t* salt,
	const ntlm_user_t* user_info_ptr,
	uint8_t* output
);

/*! \fn int sid_to_des_keys(uint32_t sid, uint64_t* key1, uint64_t* key2)
 *	\brief Converts SID to two DES keys.
 *	\param[in] sid		user's security id.
 *	\param[out] key1	DES key 1.
 *	\param[out] key2	DES key 2.
 *	\return 0 on success or negative number correlated to step on error.
 */
int sid_to_des_keys(uint32_t sid, uint64_t* key1, uint64_t* key2);

/*! \fn int sid_to_des_keys(uint32_t sid, uint64_t* key1, uint64_t* key2)
 *	\brief Permutates key to 8-byte DES key and set odd parity.
 *	\param[in] input_key	des 8-byte key.
 *	\return DES key.
 */
uint64_t permutate_sid_key_set_odd_parity(uint64_t input_key);

#endif

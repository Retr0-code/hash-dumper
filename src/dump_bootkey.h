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
	 - Syskey and SAM / https://moyix.blogspot.com/2008/02/syskey-and-sam.html

----

	This header describes a functionality to dump bootkey and hashed bootkey
*/
/*!	\file dump_bootkey.h
 *	\brief This header describes a functionality to dump bootkey and hashed bootkey
 */

#ifndef DUMP_BOOTKEY_H
#define DUMP_BOOTKEY_H

#include <wchar.h>
#include <uchar.h>
#include <wctype.h>
#include <stdlib.h>
#include <stdint.h>

#include "hive.h"
#include "crypto.h"

// Length of raw bytes bootkey
#define RAW_BOOTKEY_LENGTH 16

/*! \typedef hash_bootkey_t
 * \brief	A function pointer for hashing algorithms defined as \a ntlmv1_hash_bootkey and \a ntlmv2_hash_bootkey
 */
typedef int (*hash_bootkey_t)(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey);

/*!	\fn int dump_bootkey(FILE* sys_hive, char16_t* out_bootkey)
 *	\brief Reads UTF-16 raw bootkey from system hive
 *	\param[in] sys_hive		takes file descriptor to SYSTEM hive file.
 *	\param[out] out_bootkey	output UTF-16 string for read bootkey.
 *	\return		null on success or negative number correlated to step on error.
 */
int dump_bootkey(FILE* sys_hive, char16_t* out_bootkey);

/*!	\fn int get_hashed_bootkey(const char16_t* u16_bootkey, FILE* sam_hive, uint8_t* hashed_bootkey)
 *	\brief Constructs a hashed bootkey from read UTF-16 bootkey hex string
 *	\param[in] u16_bootkey		UTF-16 hex bootkey string read using \a dump_bootkey
 *	\param[in] sys_hive			takes file descriptor to SAM hive file.
 *	\param[out] hashed_bootkey	output hashed bootkey bytes array of size \a RAW_BOOTKEY_LENGTH.
 *	\return		null on success or negative number correlated to step on error.
 */
int get_hashed_bootkey(const char16_t* u16_bootkey, FILE* sam_hive, uint8_t* hashed_bootkey);

/*!	\fn uint8_t* bootkey_from_u16(const char16_t* wstr)
 *	\brief Converst bootkey wide char string to array of size 16 of one byte integers
 *	\param[in] wstr		UTF-16 bootkey uppercase string.
 *	\return		hashed bootkey bytes array of size \a RAW_BOOTKEY_LENGTH
 */
uint8_t* bootkey_from_u16(const char16_t* wstr);

/*!	\fn	static int ntlmv1_hash_bootkey(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey)
 *	\brief Generates NTLMv1 hashed bootkey
 *	\param[in] permutated_bootkey	permutated bootkey byte array.
 *	\param[in] f_value				"F" value from SAM\SAM\Domains\Account.
 *	\param[out] hashed_bootkey		output hashed bootkey bytes array of size \a RAW_BOOTKEY_LENGTH.
 *	\return		null on success or negative number correlated to step on error.
 */
static int ntlmv1_hash_bootkey(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey);

/*!	\fn	static int ntlmv2_hash_bootkey(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey)
 *	\brief Generates NTLMv2 hashed bootkey
 *	\param[in] permutated_bootkey	permutated bootkey byte array.
 *	\param[in] f_value				"F" value from SAM\SAM\Domains\Account.
 *	\param[out] hashed_bootkey		output hashed bootkey bytes array of size \a RAW_BOOTKEY_LENGTH.
 *	\return		null on success or negative number correlated to step on error.
 */
static int ntlmv2_hash_bootkey(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey);

#endif

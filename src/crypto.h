/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.


----

	References used:
	 - Syskey and SAM / https://moyix.blogspot.com/2008/02/syskey-and-sam.html
	 - OpenSSL 3.0 EVP API / https://www.openssl.org/docs/man3.0/man7/evp.html

----

	This header describes an API for openssl 3.0.11 and openssl 1.1.1 cryptographic functions
*/

/*! \file crypto.h
 *	\brief This header describes an API for openssl 3.0.11 and openssl 1.1.1 cryptographic functions
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>

#if (OPENSSL_VERSION_MAJOR >= 3)
#include <openssl/evp.h>
#include <openssl/provider.h>
#endif

#include "functional.h"

/*! \fn	uint8_t* get_md5(const char* data, size_t data_size)
 *	\brief Returns md5 hash of specified data.
 *	\param[in] data			input array of bytes.
 *	\param[in] data_size	length of data to hash.
 *	\return	calculated MD5 bytes array.
 */
uint8_t* get_md5(const char* data, size_t data_size);

/*! \fn	int rc4_encrypt(const uint8_t* data, int data_len, uint8_t* key, uint8_t* enc_data)
 *	\brief Encrypts data using RC4.
 *	\param[in] data			input array of bytes.
 *	\param[in] data_len		length of data to hash.
 *	\param[in] key			key used to encrypt.
 *	\param[out] enc_data	output encrypted data.
 *	\return	\a data_len on success or negative number correlated to step on error.
 */
int rc4_encrypt(const uint8_t* data, int data_len, uint8_t* key, uint8_t* enc_data);

/*! \fn	int aes_128_cbc_decrypt(const uint8_t* enc_data, int data_len, const uint8_t* key, const uint8_t* iv, uint8_t* dec_data)
 *	\brief Decryps data using AES-128-CBC.
 *	\param[in] enc_data		input array of bytes.
 *	\param[in] data_len		length of data to hash.
 *	\param[in] key			key used to encrypt.
 *	\param[in] iv			input vector.
 *	\param[out] dec_data	output encrypted data.
 *	\return	\a data_len on success or negative number correlated to step on error.
 */
int aes_128_cbc_decrypt(
	const uint8_t* enc_data,
	int data_len,
	const uint8_t* key,
	const uint8_t* iv,
	uint8_t* dec_data
);

/*! \fn	int des_ecb_decrypt(const uint8_t* enc_data, int data_len, const uint8_t* key, uint8_t* dec_data)
 *	\brief Decryps data using DES-ECB.
 *	\param[in] enc_data		input array of bytes.
 *	\param[in] data_len		length of data to hash.
 *	\param[in] key			key used to encrypt.
 *	\param[out] dec_data	output encrypted data.
 *	\return	\a data_len on success or negative number correlated to step on error.
 */
int des_ecb_decrypt(const uint8_t* enc_data, int data_len, const uint8_t* key, uint8_t* dec_data);

#if (OPENSSL_VERSION_MAJOR >= 3)

/*! \fn	static int openssl_evp_wrapper(const uint8_t* in_data, int data_len, const uint8_t* key, const uint8_t* iv, uint8_t* out_data, int encrypt_mode, int padding, const EVP_CIPHER* cipher)
 *	\brief Decryps/encrypts data using specified cipher.
 *	\param[in] in_data		input array of bytes.
 *	\param[in] data_len		length of data to hash.
 *	\param[in] key			key used to encrypt.
 *	\param[in] iv			input vector.
 *	\param[out] out_data	output encrypted data.
 *	\param[in] encrypt_mode	boolean value 1 for encryption and 0 decryption.
 *	\param[in] padding		data padding specific for given cipher.
 *	\param[in] cipher		evp cipher structure.
 *	\return	\a data_len on success or negative number correlated to step on error.
 */
static int openssl_evp_wrapper(
	const uint8_t* in_data,
	int data_len,
	const uint8_t* key,
	const uint8_t* iv,
	uint8_t* out_data,
	int encrypt_mode,
	int padding,
	const EVP_CIPHER* cipher
);
#endif

#endif
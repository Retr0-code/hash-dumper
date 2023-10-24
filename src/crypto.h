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

	This header describes an API for openssl 3.0.11 cryptographic functions
*/

#ifndef CRYPTO_H
#define CRYPTO_H

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/provider.h>

// Returns md5 hash of specified data
uint8_t* get_md5(const char* data, size_t data_size);

// Encrypts RC4
int rc4_encrypt(const uint8_t* data, size_t data_len, uint8_t* key, uint8_t* enc_data);

// Decryps AES 128 CBC
int aes_128_cbc_decrypt(
	const uint8_t* enc_data,
	int data_len,
	const uint8_t* key,
	const uint8_t* iv,
	uint8_t* dec_data
);

static int openssl_evp_wrapper(
	const uint8_t* in_data,
	int data_len,
	const uint8_t* key,
	const uint8_t* iv,
	uint8_t* out_data,
	int encrypt_mode,
	const EVP_CIPHER* cipher
);

#endif
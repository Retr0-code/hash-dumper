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

	This file defines an API for openssl 3.0.11 cryptographic functions
*/

#include "crypto.h"

uint8_t* get_md5(const char* data, size_t data_size)
{
	EVP_MD_CTX* context = EVP_MD_CTX_new();

	// Initializing context with md5 algorithm
	if (EVP_DigestInit_ex2(context, EVP_md5(), NULL) == 0)
	{
		EVP_MD_CTX_free(context);
		errno = EFAULT;
		return NULL;
	}

	size_t hash_size = EVP_MD_size(EVP_md5());
	uint8_t* raw_hash = OPENSSL_malloc(hash_size);

	// Hashing given data
	if (EVP_DigestUpdate(context, data, data_size) == 0)
	{
		EVP_MD_CTX_free(context);
		errno = EBADF;
		return NULL;
	}

	// Saving the hash to array
	if (EVP_DigestFinal_ex(context, raw_hash, NULL) == 0)
	{
		EVP_MD_CTX_free(context);
		return NULL;
	}

	EVP_MD_CTX_free(context);
	return raw_hash;
}

int rc4_encrypt(const uint8_t* data, size_t data_len, uint8_t* key, uint8_t* enc_data)
{
	// Loading legacy algorithms provider
	OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(NULL, "legacy");
	if (legacy == NULL) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	int result = openssl_evp_wrapper(data, data_len, key, NULL, enc_data, 1, EVP_rc4());

	// Unloading legacy provider
	OSSL_PROVIDER_unload(legacy);
	return result;
}

int aes_128_cbc_decrypt(
	const uint8_t* enc_data,
	int data_len,
	const uint8_t* key,
	const uint8_t* iv,
	uint8_t* dec_data
)
{
	return openssl_evp_wrapper(enc_data, data_len, key, iv, dec_data, 0, EVP_aes_128_cbc());
}

static int openssl_evp_wrapper(
	const uint8_t* in_data,
	int data_len,
	const uint8_t* key,
	const uint8_t* iv,
	uint8_t* out_data,
	int encrypt_mode,
	const EVP_CIPHER* cipher
)
{
	// Constructing a context cipher
	EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
	if (context == NULL)
	{
		errno = EBADF;
		return 0;
	}

	// Initializing cipher
	if (!EVP_CipherInit_ex(context, cipher, NULL, key, iv, encrypt_mode))
	{
		EVP_CIPHER_CTX_cleanup(context);
		EVP_CIPHER_CTX_free(context);
		return 0;
	}

	EVP_CIPHER_CTX_set_padding(context, 0);

	// Updating cipher using specified parameters
	int out_len;
	if (!EVP_CipherUpdate(context, out_data, &out_len, in_data, data_len))
	{
		EVP_CIPHER_CTX_cleanup(context);
		EVP_CIPHER_CTX_free(context);
		return 0;
	}

	// Writing final result
	if (!EVP_CipherFinal_ex(context, out_data, &out_len))
	{
		EVP_CIPHER_CTX_cleanup(context);
		EVP_CIPHER_CTX_free(context);
		return 0;
	}

	// Deleting the context
	EVP_CIPHER_CTX_cleanup(context);
	EVP_CIPHER_CTX_free(context);
	return data_len;
}

#include "crypto.h"

//uint8_t* get_md5(const char* data, size_t data_size)
//{
//	EVP_MD_CTX* context = EVP_MD_CTX_new();
//	const EVP_MD* md5 = EVP_md5();
//
//	// Initializing context with md5 algorithm
//	if (EVP_DigestInit_ex2(context, md5, NULL) == 0)
//	{
//		EVP_MD_CTX_free(context);
//		EVP_MD_free(md5);
//		errno = EFAULT;
//		return NULL;
//	}
//
//	size_t hash_size = EVP_MD_size(md5);
//	uint8_t* raw_hash = OPENSSL_malloc(hash_size);
//
//	// Hashing given data
//	if (EVP_DigestUpdate(context, data, data_size) == 0)
//	{
//		EVP_MD_CTX_free(context);
//		EVP_MD_free(md5);
//		errno = EBADF;
//		return NULL;
//	}
//
//	// Saving the hash to array
//	if (EVP_DigestFinal_ex(context, raw_hash, NULL) == 0)
//	{
//		EVP_MD_CTX_free(context);
//		EVP_MD_free(md5);
//		return NULL;
//	}
//
//	EVP_MD_CTX_free(context);
//	EVP_MD_free(md5);
//	return raw_hash;
//}

int aes_128_cbc_decrypt(uint8_t* enc_data, uint8_t* salt, int data_len, uint8_t* key, uint8_t* iv, uint8_t* dec_data)
{
	// Constructing a context for AES128 decryption
	EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
	if (context == NULL)
	{
		errno = EBADF;
		return 0;
	}

	// Initializing decryptor
	if (!EVP_DecryptInit_ex(context, EVP_aes_128_cbc(), NULL, key, iv))
	{
		EVP_CIPHER_CTX_cleanup(context);
		EVP_CIPHER_CTX_free(context);
		return 0;
	}

	EVP_CIPHER_CTX_set_padding(context, 0);

	// Decrypting using specified parameters
	int out_len;
	if (!EVP_DecryptUpdate(context, dec_data, &out_len, enc_data, data_len))
	{
		EVP_CIPHER_CTX_cleanup(context);
		EVP_CIPHER_CTX_free(context);
		return 0;
	}

	// Writing final result
	if (!EVP_DecryptFinal_ex(context, dec_data, &out_len))
	{
		EVP_CIPHER_CTX_cleanup(context);
		EVP_CIPHER_CTX_free(context);
		return 0;
	}

	// Deleting the context
	EVP_CIPHER_CTX_cleanup(context);
	EVP_CIPHER_CTX_free(context);
	return out_len << 1;
}

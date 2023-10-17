#ifndef CRYPTO_H
#define CRYPTO_H

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

// Returns md5 hash of specified data
//uint8_t* get_md5(const char* data, size_t data_size);

// Decryps AES 128 CBC
int aes_128_cbc_decrypt(uint8_t* enc_data, uint8_t* salt, int data_len, uint8_t* key, uint8_t* iv, uint8_t* dec_data);

#endif
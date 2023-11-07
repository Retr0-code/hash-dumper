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

    This file defines a functions to dump bootkey and hashed bootkey
*/

#include "dump_bootkey.h"

int dump_bootkey(FILE* sys_hive, char16_t* out_bootkey)
{
    // Validating parameters
    validate_parameters(sys_hive == NULL || out_bootkey == NULL, -1);

    // Allocating hive header
    hive_header_t* hive_header_ptr = malloc_check(hive_header_ptr, sizeof(hive_header_t), -2);
    // Allocating base named key
    named_key_t* base_nk_ptr = malloc_check(base_nk_ptr, sizeof(named_key_t), -3);
    if (hive_get_root(sys_hive, hive_header_ptr, base_nk_ptr) != hv_success)
    {
        cleanup_pointers(2, hive_header_ptr, base_nk_ptr);
        return -4;
    }

    // Allocating endpoint named key
    named_key_t* lsa_nk_ptr = malloc_check_clean(
        lsa_nk_ptr,
        sizeof(named_key_t),
        -5, 2,
        hive_header_ptr,
        base_nk_ptr
    );

    // Constructing registry path struct
    reg_path_t* reg_lsa_path = reg_make_path(3, "ControlSet001", "Control", "Lsa");
    if (reg_lsa_path == NULL)
    {
        cleanup_pointers(3, hive_header_ptr, base_nk_ptr, lsa_nk_ptr);
        return -6;
    }

    // Enumerating named key by specified path
    if (reg_enum_subkey(base_nk_ptr, reg_lsa_path, sys_hive, lsa_nk_ptr) != 0)
    {
        cleanup_pointers(4, hive_header_ptr, base_nk_ptr, lsa_nk_ptr, reg_lsa_path);
        return -7;
    }

    // Allocating endpoint named key for bootkey values
    named_key_t* endpoint_nk_ptr = malloc_check_clean(
        endpoint_nk_ptr,
        sizeof(named_key_t),
        -8, 4,
        hive_header_ptr,
        base_nk_ptr,
        lsa_nk_ptr,
        reg_lsa_path
    );

    // List of named keys to construct the bootkey
    const char* lsa_values[4] = {"JD", "Skew1", "GBG", "Data"};
    char16_t* bootkey_part = NULL;
    reg_path_t* reg_endpoint_path;
    for (size_t i = 0; i < 4; i++)
    {
        // Constructing path for enumeration
        reg_endpoint_path = reg_make_path(1, lsa_values[i]);
        if (reg_endpoint_path == NULL)
        {
            cleanup_pointers(5, hive_header_ptr, base_nk_ptr, lsa_nk_ptr, reg_lsa_path, reg_endpoint_path);
            return -9;
        }

        // Enumerating endpoint subkey in specific order
        if (reg_enum_subkey(lsa_nk_ptr, reg_endpoint_path, sys_hive, endpoint_nk_ptr) != 0)
        {
            cleanup_pointers(5, hive_header_ptr, base_nk_ptr, lsa_nk_ptr, reg_lsa_path, reg_endpoint_path);
            return -10;
        }

        // Reading hex UTF-16 bootkey part from class names of specified named keys
        bootkey_part = reg_get_class(endpoint_nk_ptr, sys_hive);
        if (bootkey_part == NULL)
        {
            cleanup_pointers(5, hive_header_ptr, base_nk_ptr, lsa_nk_ptr, reg_lsa_path, reg_endpoint_path);
            return -11;
        }

        // Constructing full bootkey
        memcpy(out_bootkey + i * 16 / sizeof(char16_t), bootkey_part, 16);
        free(bootkey_part);
    }

    out_bootkey[RAW_BOOTKEY_LENGTH * 2] = L'\0';

    for (size_t i = 0; i < RAW_BOOTKEY_LENGTH * 2; i++)
        out_bootkey[i] = towupper(out_bootkey[i]);

    cleanup_pointers(5, hive_header_ptr, base_nk_ptr, lsa_nk_ptr, reg_lsa_path, reg_endpoint_path);
    return 0;
}

int get_hashed_bootkey(const char16_t* u16_bootkey, FILE* sam_hive, uint8_t* hashed_bootkey)
{
    // Validating parameters
    validate_parameters(u16_bootkey == NULL || hashed_bootkey == NULL, -1);

    // Decoding hex string to raw values
    uint8_t* raw_bootkey = bootkey_from_u16(u16_bootkey);
    if (raw_bootkey == NULL)
        return -2;

    // Array of indexes for descramble the bootkey
    uint8_t permutations[RAW_BOOTKEY_LENGTH] = {
        0x8, 0x5, 0x4, 0x2,
        0xb, 0x9, 0xd, 0x3,
        0x0, 0x6, 0x1, 0xc,
        0xe, 0xa, 0xf, 0x7
    };

    uint8_t permutated_bootkey[RAW_BOOTKEY_LENGTH];

    // Permutating the bootkey
    for (size_t i = 0; i < RAW_BOOTKEY_LENGTH; i++)
        permutated_bootkey[i] = raw_bootkey[permutations[i]];

    // Allocating hive header
    hive_header_t* hive_header_ptr = malloc_check(hive_header_ptr, sizeof(hive_header_t), -3);
    // Allocating base named key
    named_key_t* base_nk_ptr = malloc_check_clean(base_nk_ptr, sizeof(named_key_t), -4, 2, hive_header_ptr, raw_bootkey);

    if (hive_get_root(sam_hive, hive_header_ptr, base_nk_ptr) != hv_success)
    {
        cleanup_pointers(3, hive_header_ptr, raw_bootkey, base_nk_ptr);
        return -5;
    }

    reg_path_t* reg_accounts_path = reg_make_path(3, "SAM", "Domains", "Account");

    if (reg_accounts_path == NULL)
    {
        cleanup_pointers(4, hive_header_ptr, raw_bootkey, base_nk_ptr, reg_accounts_path);
        return -6;
    }

    // Allocating endpoint named key
    named_key_t* accounts_nk_ptr = malloc_check_clean(
        accounts_nk_ptr,
        sizeof(named_key_t),
        -7, 4,
        hive_header_ptr,
        raw_bootkey,
        base_nk_ptr,
        reg_accounts_path
    );

    // Enumerating named key by specified path
    if (reg_enum_subkey(base_nk_ptr, reg_accounts_path, sam_hive, accounts_nk_ptr) != 0)
    {
        cleanup_pointers(5, hive_header_ptr, raw_bootkey, base_nk_ptr, reg_accounts_path, accounts_nk_ptr);
        return -8;
    }

    // Allocating value key for "F" value
    value_key_t* f_value_ptr = malloc_check_clean(
        f_value_ptr,
        sizeof(value_key_t),
        -9, 5,
        hive_header_ptr,
        raw_bootkey,
        base_nk_ptr,
        reg_accounts_path,
        accounts_nk_ptr
    );

    // Reading "F" value
    if (reg_enum_value(accounts_nk_ptr, "F", sam_hive, f_value_ptr) != 0)
    {
        cleanup_pointers(6,
            hive_header_ptr, raw_bootkey,
            base_nk_ptr, reg_accounts_path,
            accounts_nk_ptr, f_value_ptr
        );
        return -10;
    }

    // Saving "F" value
    uint8_t* f_value = reg_get_value(f_value_ptr, sam_hive);
    if (f_value == NULL)
    {
        cleanup_pointers(6, 
            hive_header_ptr, raw_bootkey,
            base_nk_ptr, reg_accounts_path,
            accounts_nk_ptr, f_value_ptr
        );
        return -11;
    }

    // Determining ntlm version based on F value version
    hash_bootkey_t hash_function = NULL;
    switch (f_value[0])
    {
    case 2:
        hash_function = &ntlmv1_hash_bootkey;
        break;
    case 3:
        hash_function = &ntlmv2_hash_bootkey;
        break;
    default:
        hash_function = NULL;
    }

    // Checking if read data is valid
    if (hash_function == NULL)
    {
        cleanup_pointers(7, 
            hive_header_ptr, raw_bootkey,
            base_nk_ptr, reg_accounts_path,
            accounts_nk_ptr, f_value_ptr, f_value
        );
        return -12;
    }

    // Hashing bootkey
    if ((*hash_function)(permutated_bootkey, f_value, hashed_bootkey) != 0)
    {
        cleanup_pointers(7,
            hive_header_ptr, raw_bootkey,
            base_nk_ptr, reg_accounts_path,
            accounts_nk_ptr, f_value_ptr, f_value
        );
        return -13;
    }

    cleanup_pointers(7, 
        hive_header_ptr, raw_bootkey,
        base_nk_ptr, reg_accounts_path,
        accounts_nk_ptr, f_value_ptr, f_value
    );
    return 0;
}

static uint8_t* bootkey_from_u16(const char16_t* wstr)
{
    // Validating parameter
    validate_parameters(wstr == NULL, NULL);

    // Checking a bootkey length
    size_t wstr_length = 0;
    while (wstr[wstr_length++]);
    --wstr_length;
    if (wstr_length != RAW_BOOTKEY_LENGTH * 2)
    {
        errno = EBADF;
        return NULL;
    }

    // Raw bootkey data array
    uint8_t* bootkey_decoded = malloc_check(bootkey_decoded, RAW_BOOTKEY_LENGTH, NULL);
    for (size_t i = 0; i < RAW_BOOTKEY_LENGTH; i++)
    {
        uint8_t fh = (*(wstr + (i << 1)) & 0x00ff);        // Taking first 4 bits of an integer
        uint8_t sh = (*(wstr + (i << 1) + 1) & 0x00ff);    // Taking second 4 bits of an integer

        // Converting half-bytes by symbolic table
        // Chars start from 0x41 and nums - from 0x30
        fh -= fh >= 'A' ? 0x37 : 0x30;
        sh -= sh >= 'A' ? 0x37 : 0x30;

        // Writing result to array
        bootkey_decoded[i] = (fh << 4) | sh;
    }

    return bootkey_decoded;
}

int ntlmv1_hash_bootkey(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey)
{
    // Validating parameters
    validate_parameters(permutated_bootkey == NULL || f_value == NULL || hashed_bootkey == NULL, -1);

    // Constants for hashed bootkey construction
    const char* aqwerty = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
    const char* anum = "0123456789012345678901234567890123456789\0";

    size_t total_length = strlen(aqwerty) + strlen(anum) + 0x20 + 2;
    uint8_t* pre_hashed_bootkey = malloc_check(
        pre_hashed_bootkey,
        total_length,
        -2
    );

    // Writing pre_hashed_bootkey in specific order
    memcpy(pre_hashed_bootkey, f_value + 0x70, 0x10);
    memcpy(pre_hashed_bootkey, aqwerty, strlen(aqwerty) + 1);
    memcpy(pre_hashed_bootkey, permutated_bootkey, 0x10);
    memcpy(pre_hashed_bootkey, anum + 0x70, strlen(anum) + 1);

    // MD5 surves RC4 encryption key
    uint8_t* md5_key = get_md5(pre_hashed_bootkey, total_length);
    if (md5_key == NULL)
    {
        free(pre_hashed_bootkey);
        return -3;
    }

    // Encrypting bootkey using rc4
    if (rc4_encrypt(f_value + 0x80, MD5_DIGEST_LENGTH, md5_key, hashed_bootkey) == 0)
    {
        free(pre_hashed_bootkey);
        free(md5_key);
        return -3;
    }

    free(pre_hashed_bootkey);
    free(md5_key);
    return 0;
}

int ntlmv2_hash_bootkey(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey)
{
    // Validating parameters
    validate_parameters(permutated_bootkey == NULL || f_value == NULL || hashed_bootkey == NULL, -1);

    // Allocating space for IV taken from F[0x78:0x88] and encrypted bootkey taken from F[0x88:0xA8]
    uint8_t* iv = malloc_check(iv, AES_BLOCK_SIZE, -3);
    uint8_t* encrypted_bootkey = malloc_check(encrypted_bootkey, 0x20, -4);
    memcpy(iv, f_value + 0x78, AES_BLOCK_SIZE);
    memcpy(encrypted_bootkey, f_value + 0x88, 0x20);

    // Decrypt bootkey
    if (aes_128_cbc_decrypt(encrypted_bootkey, 0x20, permutated_bootkey, iv, hashed_bootkey) == 0)
        return -2;

    // Saving only first half of hashed bootkey
    memset(hashed_bootkey + RAW_BOOTKEY_LENGTH, 0, RAW_BOOTKEY_LENGTH);

    return 0;
}

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

    int return_status = 0;

    // Allocating hive header
    hive_header_t* hive_header_ptr = malloc_check(hive_header_ptr, sizeof(hive_header_t), -2);
    // Allocating base named key
    named_key_t* base_nk_ptr = malloc_check(base_nk_ptr, sizeof(named_key_t), -3);
    if (hive_get_root(sys_hive, hive_header_ptr, base_nk_ptr) != hv_success)
    {
        return_status = -4;
        goto fn_end;
    }

    // Allocating endpoint named key
    named_key_t* lsa_nk_ptr = malloc_check_lambda(
        lsa_nk_ptr, sizeof(named_key_t),
        {
            return_status = -5; goto fn_end;
        }
    )

    // Constructing registry path struct
    reg_path_t* reg_lsa_path = reg_make_path(3, "ControlSet001", "Control", "Lsa");
    if (reg_lsa_path == NULL)
    {
        return_status = -6;
        goto fn_end;
    }

    // Enumerating named key by specified path
    if (reg_enum_subkey(base_nk_ptr, reg_lsa_path, sys_hive, lsa_nk_ptr) != 0)
    {
        return_status = -7;
        goto fn_end;
    }

    // Allocating endpoint named key for bootkey values
    named_key_t* endpoint_nk_ptr = malloc_check_lambda(
        endpoint_nk_ptr, sizeof(named_key_t),
        {
            return_status = -8;
            goto fn_end;
        }
    )

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
            return_status = -9;
            goto fn_end;
        }

        // Enumerating endpoint subkey in specific order
        if (reg_enum_subkey(lsa_nk_ptr, reg_endpoint_path, sys_hive, endpoint_nk_ptr) != 0)
        {
            return_status = -10;
            goto fn_end;
        }

        // Reading hex UTF-16 bootkey part from class names of specified named keys
        bootkey_part = reg_get_class(endpoint_nk_ptr, sys_hive);
        if (bootkey_part == NULL)
        {
            return_status = -11;
            goto fn_end;
        }

        // Constructing full bootkey
        memcpy(out_bootkey + i * 16 / sizeof(char16_t), bootkey_part, 16);
        free(bootkey_part);
    }

    out_bootkey[RAW_BOOTKEY_LENGTH * 2] = L'\0';

fn_end:
    if (hive_header_ptr != NULL)
        free(hive_header_ptr);
    
    reg_destroy_nk(base_nk_ptr);
    reg_destroy_nk(lsa_nk_ptr);
    reg_destroy_path(reg_lsa_path);
    reg_destroy_path(reg_endpoint_path);
    return return_status;
}

int get_hashed_bootkey(const char16_t* u16_bootkey, FILE* sam_hive, uint8_t* hashed_bootkey)
{
    // Validating parameters
    validate_parameters(u16_bootkey == NULL || hashed_bootkey == NULL, -1);

    int return_status = 0;

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
    named_key_t* base_nk_ptr = malloc_check_lambda(
        base_nk_ptr, sizeof(named_key_t),
        {
            return_status = -4;
            goto fn_end;
        }
    )

    if (hive_get_root(sam_hive, hive_header_ptr, base_nk_ptr) != hv_success)
    {
        return_status - 5;
        goto fn_end;
    }

    reg_path_t* reg_accounts_path = reg_make_path(3, "SAM", "Domains", "Account");

    if (reg_accounts_path == NULL)
    {
        return_status = -6;
        goto fn_end;
    }

    // Allocating endpoint named key
    named_key_t* accounts_nk_ptr = malloc_check_lambda(
        accounts_nk_ptr, sizeof(named_key_t),
        {
            return_status = -7;
            goto fn_end;
        }
    )

    // Enumerating named key by specified path
    if (reg_enum_subkey(base_nk_ptr, reg_accounts_path, sam_hive, accounts_nk_ptr) != 0)
    {
        return_status = -8;
        goto fn_end;
    }

    // Allocating value key for "F" value
    value_key_t* f_value_vk_ptr = malloc_check_lambda(
        f_value_vk_ptr, sizeof(value_key_t),
        {
            return_status = -9;
            goto fn_end;
        }
    );

    // Reading "F" value
    if (reg_enum_value(accounts_nk_ptr, "F", sam_hive, f_value_vk_ptr) != 0)
    {
        return_status = -10;
        goto fn_end;
    }

    // Saving "F" value
    uint8_t* f_value = reg_get_value(f_value_vk_ptr, sam_hive);
    if (f_value == NULL)
    {
        return_status = -11;
        goto fn_end;
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
        return_status = -12;
        goto fn_end;
    }

    // Hashing bootkey
    if ((*hash_function)(permutated_bootkey, f_value, hashed_bootkey) != 0)
    {
        return_status = -13;
    }

fn_end:
    reg_destroy_nk(base_nk_ptr);
    reg_destroy_path(reg_accounts_path);
    reg_destroy_nk(accounts_nk_ptr);
    reg_destroy_vk(f_value_vk_ptr);
    cleanup_pointers(3, hive_header_ptr, raw_bootkey, f_value);
    return return_status;
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
        uint8_t fh = (*(wstr + (i << 1)) & 0x00ff);   // Taking first 4 bits of an integer
        uint8_t sh = (*(wstr + (i << 1) + 1) & 0x00ff);    // Taking second 4 bits of an integer

        // Converting half-bytes by symbolic table
        // Chars start from 0x41 and nums - from 0x30
        if (fh >= 'A')
        {
            fh |= 32;
            fh -= 0x67;
        }
        else
           fh -= 0x30;

        if (fh >= 'A')
        {
            sh |= 32;
            sh -= 0x67;
        }
        else
           sh -= 0x30;
        
        // Writing result to array
        bootkey_decoded[i] = (fh << 4) | sh;
    }

    return bootkey_decoded;
}

int ntlmv1_hash_bootkey(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey)
{
    // Validating parameters
    validate_parameters(permutated_bootkey == NULL || f_value == NULL || hashed_bootkey == NULL, -1);

    int return_status = 0;

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
        return_status = -3;
        goto fn_end;
    }

    // Encrypting bootkey using rc4
    if (rc4_encrypt(f_value + 0x80, MD5_DIGEST_LENGTH, md5_key, hashed_bootkey) == 0)
        return_status = -4;

fn_end:
    cleanup_pointers(2, pre_hashed_bootkey, md5_key);
    return return_status;
}

int ntlmv2_hash_bootkey(uint8_t* permutated_bootkey, uint8_t* f_value, uint8_t* hashed_bootkey)
{
    // Validating parameters
    validate_parameters(permutated_bootkey == NULL || f_value == NULL || hashed_bootkey == NULL, -1);

    int return_status = 0;

    // Allocating space for IV taken from F[0x78:0x88] and encrypted bootkey taken from F[0x88:0xA8]
    uint8_t* iv = malloc_check(iv, AES_BLOCK_SIZE, -2);
    uint8_t* encrypted_bootkey = malloc_check(encrypted_bootkey, 0x20, -3);
    memcpy(iv, f_value + 0x78, AES_BLOCK_SIZE);
    memcpy(encrypted_bootkey, f_value + 0x88, 0x20);

    // Decrypt bootkey
    if (aes_128_cbc_decrypt(encrypted_bootkey, 0x20, permutated_bootkey, iv, hashed_bootkey) == 0)
    {
        return_status = -4;
        goto fn_end;
    }

    // Saving only first half of hashed bootkey
    memset(hashed_bootkey + RAW_BOOTKEY_LENGTH, 0, RAW_BOOTKEY_LENGTH);

fn_end:
    cleanup_pointers(2, iv, encrypted_bootkey);
    return return_status;
}

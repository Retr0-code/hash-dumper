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

int dump_bootkey(FILE* sys_hive, wchar_t* out_bootkey)
{
    // Validating parameters
    if (sys_hive == NULL || out_bootkey == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    // Allocating hive header
    hive_header_t* hive_header_ptr = malloc_check(hive_header_ptr, sizeof(hive_header_t), -2);

    // Reading header structure
    if (read_hive_header(sys_hive, hive_header_ptr) != 0)
    {
        free(hive_header_ptr);
        return -3;
    }

    // Allocating base named key
    named_key_t* base_nk_ptr = malloc_check(base_nk_ptr, sizeof(named_key_t), -4);

    // Reading named key structure
    if (read_named_key(hive_header_ptr->root_offset, sys_hive, base_nk_ptr) != 0)
    {
        free(hive_header_ptr);
        free(base_nk_ptr);
        return -5;
    }

    // Allocating endpoint named key
    named_key_t* lsa_nk_ptr = malloc_check_clean(
        lsa_nk_ptr,
        sizeof(named_key_t),
        -6,
        2,
        hive_header_ptr,
        base_nk_ptr
    );

    // Constructing registry path struct
    reg_path_t* reg_lsa_path = reg_make_path(3, "ControlSet001", "Control", "Lsa");
    if (reg_lsa_path == NULL)
    {
        cleanup_pointers(3, hive_header_ptr, base_nk_ptr, lsa_nk_ptr);
        return -7;
    }

    // Enumerating named key by specified path
    if (reg_enum_subkey(base_nk_ptr, reg_lsa_path, sys_hive, lsa_nk_ptr) != 0)
    {
        cleanup_pointers(4, hive_header_ptr, base_nk_ptr, lsa_nk_ptr, reg_lsa_path);
        return -8;
    }

    // Allocating endpoint named key for bootkey values
    named_key_t* endpoint_nk_ptr = malloc_check_clean(
        endpoint_nk_ptr,
        sizeof(named_key_t),
        -6, 4,
        hive_header_ptr,
        base_nk_ptr,
        lsa_nk_ptr,
        reg_lsa_path
    );

    // List of named keys to construct the bootkey
    const char* lsa_values[4] = {"JD", "Skew1", "GBG", "Data"};
    wchar_t* bootkey_part = NULL;
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
        memcpy(out_bootkey + i * 16 / sizeof(wchar_t), bootkey_part, 16);
        free(bootkey_part);
    }

    out_bootkey[RAW_BOOTKEY_LENGTH * 2] = L'\0';
    
    for (size_t i = 0; i < RAW_BOOTKEY_LENGTH * 2; i++)
        out_bootkey[i] = towupper(out_bootkey[i]);

    cleanup_pointers(5, hive_header_ptr, base_nk_ptr, lsa_nk_ptr, reg_lsa_path, reg_endpoint_path);
    return 0;
}

// TODO(Complete function)
int get_hashed_bootkey(const wchar_t* u16_bootkey, FILE* sam_hive, uint8_t* hashed_bootkey)
{
    // Validating parameters
    if (u16_bootkey == NULL || hashed_bootkey == NULL)
    {
        errno = EINVAL;
        return -1;
    }

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

    // Permutating the bootkey
    for (size_t i = 0; i < RAW_BOOTKEY_LENGTH; i++)
        raw_bootkey[i] = raw_bootkey[permutations[i]];

    // Allocating hive header
    hive_header_t* hive_header_ptr = malloc_check(hive_header_ptr, sizeof(hive_header_t), -3);

    // Reading header structure
    if (read_hive_header(sam_hive, hive_header_ptr) != 0)
    {
        free(hive_header_ptr);
        return -4;
    }

    // Allocating base named key
    named_key_t* base_nk_ptr = malloc_check_clean(base_nk_ptr, sizeof(named_key_t), -5, 1, hive_header_ptr);

    // Reading named key structure
    if (read_named_key(hive_header_ptr->root_offset, sam_hive, base_nk_ptr) != 0)
    {
        free(hive_header_ptr);
        free(base_nk_ptr);
        return -6;
    }

    reg_path_t* reg_accounts_path = reg_make_path(3, "SAM", "Domains", "Accounts");

    if (reg_accounts_path == NULL)
    {
        cleanup_pointers(3, hive_header_ptr, base_nk_ptr, reg_accounts_path);
        return -7;
    }

    // Allocating endpoint named key
    named_key_t* accounts_nk_ptr = malloc_check_clean(
        accounts_nk_ptr,
        sizeof(named_key_t),
        -8, 3,
        hive_header_ptr,
        base_nk_ptr,
        reg_accounts_path
    );

    // Enumerating named key by specified path
    if (reg_enum_subkey(base_nk_ptr, reg_accounts_path, sam_hive, accounts_nk_ptr) != 0)
    {
        cleanup_pointers(4, hive_header_ptr, base_nk_ptr, reg_accounts_path, accounts_nk_ptr);
        return -9;
    }

    value_key_t* f_value_ptr = malloc_check_clean(
        f_value_ptr,
        sizeof(value_key_t),
        -10, 4,
        hive_header_ptr,
        base_nk_ptr,
        reg_accounts_path,
        accounts_nk_ptr
    );

    if (reg_enum_value(accounts_nk_ptr, "F", sam_hive, f_value_ptr) != 0)
    {
        cleanup_pointers(5, hive_header_ptr, base_nk_ptr, reg_accounts_path, accounts_nk_ptr, f_value_ptr);
        return -11;
    }

    uint8_t* f_value = reg_get_value(f_value_ptr, sam_hive);
    if (f_value == NULL)
    {
        cleanup_pointers(5, hive_header_ptr, base_nk_ptr, reg_accounts_path, accounts_nk_ptr, f_value_ptr);
        return -12;
    }

    return 0;
}

uint8_t* bootkey_from_u16(const wchar_t* wstr)
{
    // Validating parameter
    if (wstr == NULL)
    {
        errno = EINVAL;
        return NULL;
    }

    // Checking a bootkey length
    size_t wstr_length = wcslen(wstr);
    if (wstr_length != RAW_BOOTKEY_LENGTH * 2)
    {
        errno = EBADF;
        return NULL;
    }

    // Raw bootkey data array
    uint8_t bootkey_decoded[RAW_BOOTKEY_LENGTH];
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

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

#include "dump_hashes.h"

int ntlm_user_init(ntlm_user_t* user_info_ptr)
{
    // Validating parameters
    if (user_info_ptr == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    user_info_ptr->lmhash = malloc_check(user_info_ptr->lmhash, 16, -2);
    user_info_ptr->nthash = malloc_check_clean(user_info_ptr->nthash, 16, -3, 1, user_info_ptr->lmhash);

    return 0;
}

int ntlm_user_destroy(ntlm_user_t* user_info_ptr)
{
    // Validating parameters
    if (user_info_ptr == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    free(user_info_ptr->lmhash);
    free(user_info_ptr->nthash);
    free(user_info_ptr->v_value);

    return 0;
}

int dump_users_keys(FILE* sam_hive, named_key_t** users_keys_array, size_t* users_amount)
{
    // Validating parameters
    if (sam_hive == NULL || users_amount == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    // Allocating hive header
    hive_header_t* hive_header_ptr = malloc_check(hive_header_ptr, sizeof(hive_header_t), -2);
    // Allocating base named key
    named_key_t* base_nk_ptr = malloc_check(base_nk_ptr, sizeof(named_key_t), -3);
    if (hive_get_root(sam_hive, hive_header_ptr, base_nk_ptr) != hv_success)
    {
        cleanup_pointers(2, hive_header_ptr, base_nk_ptr);
        return -4;
    }

    // Initializing path to users cells
    reg_path_t* reg_users_path = reg_make_path(4, "SAM", "Domains", "Account", "Users");
    if (reg_users_path == NULL)
    {
        cleanup_pointers(2, hive_header_ptr, base_nk_ptr);
        return -5;
    }

    // Allocating users named key
    named_key_t* users_nk_ptr = malloc_check_clean(
        base_nk_ptr,
        sizeof(named_key_t),
        -6, 2,
        hive_header_ptr, base_nk_ptr
    );

    // Enumerating named key by specified path
    if (reg_enum_subkey(base_nk_ptr, reg_users_path, sam_hive, users_nk_ptr) != 0)
    {
        cleanup_pointers(4, hive_header_ptr, base_nk_ptr, users_nk_ptr, reg_users_path);
        return -7;
    }

    fast_leaf_t subkey_list;
    if (read_subkey_list(users_nk_ptr->subkey_offset, sam_hive, &subkey_list) != hv_success)
    {
        cleanup_pointers(4, hive_header_ptr, base_nk_ptr, users_nk_ptr, reg_users_path);
        return -8;
    }

    // Hint for fast leaf
    uint32_t* hints = reg_users_path->nodes_hints;
    if (subkey_list.signature == LH_SIGN)
        hints = reg_users_path->nodes_hash;

    // Allocating an array of named keys with NULLs
    *users_keys_array = malloc_check_clean(
        users_keys_array,
        subkey_list.elements_amount * sizeof(named_key_t),
        -9, 5,
        hive_header_ptr, base_nk_ptr, users_nk_ptr, reg_users_path, hints
    );
    memset(*users_keys_array, NULL, subkey_list.elements_amount * sizeof(named_key_t));
    *users_amount = 0;

    // Iterate throug all Users subkeys
    for (size_t lf_index = 0; lf_index < subkey_list.elements_amount; lf_index++)
    {        
        // Read the named key
        if (read_named_key(subkey_list.elements[lf_index].node_offset, sam_hive, &(*users_keys_array)[*users_amount]) != hv_success)
        {
            cleanup_pointers(
                6,
                hive_header_ptr, base_nk_ptr,
                users_nk_ptr, reg_users_path,
                hints, *users_keys_array
            );

            return -11;
        }

        // Exclude Names from list of named keys
        if (strcmp("Names", (*users_keys_array)[*users_amount].name) == 0)
            continue;

        (*users_amount)++;
    }

    cleanup_pointers(
        5,
        hive_header_ptr, base_nk_ptr,
        users_nk_ptr, reg_users_path,
        hints
    );
    return 0;
}

// TODO(Complete the function)
int dump_v_value(FILE* sam_hive, named_key_t* user_key_ptr, ntlm_user_t* user_info_ptr)
{
    // Validating parameters
    if (sam_hive == NULL || user_key_ptr == NULL || user_info_ptr == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    // Reading value key
    value_key_t* v_key_ptr = malloc_check(v_key_ptr, sizeof(value_key_t), -2);
    if (reg_enum_value(user_key_ptr, "V", sam_hive, v_key_ptr) != hv_success)
    {
        free(v_key_ptr);
        return -3;
    }

    // Retrieving value of V
    void* v_value_ptr;
    if ((v_value_ptr = reg_get_value(v_key_ptr, sam_hive)) == NULL)
    {
        free(v_key_ptr);
        return -4;
    }

    user_info_ptr->sid = strtoul(user_key_ptr->name, NULL, 16);
    user_info_ptr->v_value = v_value_ptr;
    user_info_ptr->v_size = v_key_ptr->data_size;

    free(v_key_ptr);
    return 0;
}

int dump_user_name(ntlm_user_t* user_info_ptr)
{
    // Validating parameters
    if (user_info_ptr == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    uint32_t name_offset = 0;
    uint32_t name_length = 0;
    memcpy(&name_offset, ((const char*)user_info_ptr->v_value) + 0x0C, sizeof(uint32_t));
    memcpy(&name_length, ((const char*)user_info_ptr->v_value) + 0x10, sizeof(uint32_t));
    name_offset += 0xCC;

    user_info_ptr->name = malloc_check(user_info_ptr->name, name_length + 2, -2);
    memcpy(user_info_ptr->name, (const char*)user_info_ptr->v_value + name_offset, name_length);
    user_info_ptr->name[name_length >> 1] = L'\0';

    return 0;
}

int dump_user_ntlm(ntlm_user_t* user_info_ptr, const uint8_t* hashed_bootkey)
{
    // Validating parameters
    if (user_info_ptr == NULL || hashed_bootkey == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    int result = decrypt_ntlm_hash(user_info_ptr, hashed_bootkey, hash_lm);
    if (result != 0)
        return -2;

    result = decrypt_ntlm_hash(user_info_ptr, hashed_bootkey, hash_nt);
    if (result != 0)
        return -3;

    return 0;
}

int decrypt_ntlm_hash(ntlm_user_t* user_info_ptr, const uint8_t* hashed_bootkey, const hash_type_e hash_type)
{
    // Validating parameters
    if (user_info_ptr == NULL || hashed_bootkey == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    // Retrieving hash offset from V value
    uint32_t hash_offset = 0;
    memcpy(&hash_offset, (uint8_t*)user_info_ptr->v_value + 0xA8, sizeof(uint32_t));
    hash_offset += 0xCC;

    uint32_t hash_exists = 0;
    memcpy(&hash_exists, (uint8_t*)user_info_ptr->v_value + 0xA0 + (0x0C * hash_type), sizeof(uint32_t));

    // Retrieving hash revision from V value. Specific condition for LM hash
    uint8_t revision = *((uint8_t*)user_info_ptr->v_value + hash_offset + 2);
    if (hash_type == hash_lm)
    {
        uint32_t revision_offset = 0;
        memcpy(&revision_offset, (uint8_t*)user_info_ptr->v_value + 0x9C, sizeof(uint32_t));
        revision = *((uint8_t*)user_info_ptr->v_value + revision_offset + 0xCC + 2);
    }

    // Preparing arrays for encrypted hash and salt
    uint8_t encrypted_hash[32];
    uint8_t encrypted_hash_salt[16];
    memset(encrypted_hash, 0, 32);
    memset(encrypted_hash_salt, 0, 16);

    // Setting proper pointer to hash
    uint8_t* hash_pointer = hash_type ? user_info_ptr->nthash : user_info_ptr->lmhash;
    switch (revision)
    {
    case 1:
        if (hash_exists != 0x14)
        {
            //hash_pointer = hash_nt ? EMPTY_NT_HASH : EMPTY_LM_HASH;
            memcpy(hash_pointer, hash_type ? EMPTY_NT_HASH : EMPTY_LM_HASH, 16);
            return 0;
        }

        memcpy(encrypted_hash, ((uint8_t*)user_info_ptr->v_value) + hash_offset + 4, 16);
        // Decrypt NTLMv1 Hash (without a salt)
        if (decrypt_hash(
            encrypted_hash,
            hashed_bootkey,
            hash_type ? NTPASSWORD : LMPASSWORD,
            user_info_ptr,
            hash_pointer
        ) != 0)
            return -3;
        break;
    case 2:
        if (hash_exists != 0x38)
        {
            memcpy(hash_pointer, hash_type ? EMPTY_NT_HASH : EMPTY_LM_HASH, 16);
            return 0;
        }

        // Reading salt and encrypted hash (offset +4 if hash type is NT)
        memcpy(encrypted_hash_salt, (uint8_t*)user_info_ptr->v_value + hash_offset + 4 + (hash_type * 4), 16);
        memcpy(encrypted_hash, (uint8_t*)user_info_ptr->v_value + hash_offset + 20 + (hash_type * 4), 32);

        // Decrypt NTLMv2 Hash (with a salt)
        if (decrypt_salted_hash(
            encrypted_hash,
            hashed_bootkey,
            encrypted_hash_salt,
            user_info_ptr,
            hash_pointer
        ) != 0)
            return -4;

        break;

    default:
        return -2;
    }

    return 0;
}

int decrypt_hash(uint8_t* enc_hash, uint8_t* hashed_bootkey, uint8_t* ntlmphrase, ntlm_user_t* user_info_ptr, uint8_t* decrypted_hash)
{
    // Validating parameters
    if (enc_hash == NULL || hashed_bootkey == NULL || ntlmphrase == NULL || user_info_ptr == NULL || decrypted_hash == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    uint64_t des_key1 = 0;
    uint64_t des_key2 = 0;
    if (sid_to_des_keys(user_info_ptr->sid, &des_key1, &des_key2) != 0)
        return -2;

    des_key1 = BYTE_SWAP64(des_key1);
    des_key2 = BYTE_SWAP64(des_key2);

    // Constructing full data for RC4 key
    size_t ntlmphrase_len = strlen(ntlmphrase) + 1;
    uint8_t* full_data = malloc_check(full_data, 16 + sizeof(uint32_t) + ntlmphrase_len, -3);
    memcpy(full_data, hashed_bootkey, 16);
    memcpy(full_data + 16, &user_info_ptr->sid, sizeof(uint32_t));
    memcpy(full_data + 16 + sizeof(uint32_t), ntlmphrase, ntlmphrase_len);

    // MD5 of the data will be RC4 key
    uint8_t* md5_hash = get_md5(full_data, 16 + sizeof(uint32_t) + ntlmphrase_len);
    if (md5_hash == NULL)
    {
        free(full_data);
        return -4;
    }

    uint8_t pre_des_hash[32];
    if (rc4_encrypt(enc_hash, 16, md5_hash, pre_des_hash) == 0)
    {
        cleanup_pointers(2, full_data, md5_hash);
        return -5;
    }

    uint8_t* des_key = &des_key1;
    for (size_t i = 0; i < 16; i += sizeof(uint64_t), des_key = &des_key2)
    {
        if (des_ecb_decrypt(pre_des_hash + i, sizeof(uint64_t), des_key, decrypted_hash + i) == 0)
        {
            free(pre_des_hash);
            return -6;
        }
    }

    return 0;
}

int decrypt_salted_hash(uint8_t* enc_hash, uint8_t* hashed_bootkey, uint8_t* salt, ntlm_user_t* user_info_ptr, uint8_t* decrypted_hash)
{
    // Validating parameters
    if (enc_hash == NULL || hashed_bootkey == NULL || salt == NULL || user_info_ptr == NULL || decrypted_hash == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    uint64_t des_key1 = 0;
    uint64_t des_key2 = 0;
    if (sid_to_des_keys(user_info_ptr->sid, &des_key1, &des_key2) != 0)
        return -2;

    des_key1 = BYTE_SWAP64(des_key1);
    des_key2 = BYTE_SWAP64(des_key2);

    uint8_t* pre_des_hash = malloc_check(pre_des_hash, 32, -3);
    if (aes_128_cbc_decrypt(enc_hash, 32, hashed_bootkey, salt, pre_des_hash) == 0)
    {
        free(pre_des_hash);
        return -4;
    }

    uint8_t* des_key = &des_key1;
    for (size_t i = 0; i < 16; i += sizeof(uint64_t), des_key = &des_key2)
    {
        if (des_ecb_decrypt(pre_des_hash + i, sizeof(uint64_t), des_key, decrypted_hash + i) == 0)
        {
            free(pre_des_hash);
            return -6;
        }
    }

    return 0;
}

int sid_to_des_keys(uint32_t sid, uint64_t* key1, uint64_t* key2)
{
    // Validating parameters
    if (key1 == NULL || key2 == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    // Creating pointers to use uint64_t pointer as a byte array
    uint8_t* key1_array = key1;
    uint8_t* key2_array = key2;

    // Permutating first 7-byte key
    *key1 = (uint64_t)(sid);
    key1_array[4] = key1_array[0];
    key1_array[5] = key1_array[1];
    key1_array[6] = key1_array[2];
    *key1 = BYTE_SWAP64(*key1);

    // Permutating second 7-byte key
    key2_array[7] = key1_array[4];
    key2_array[6] = key1_array[7];
    key2_array[5] = key1_array[6];
    key2_array[4] = key1_array[5];

    key2_array[3] = key2_array[7];
    key2_array[2] = key2_array[6];
    key2_array[1] = key2_array[5];

    *key1 = permutate_sid_key_set_odd_parity(*key1);
    *key2 = permutate_sid_key_set_odd_parity(*key2);

    return 0;
}

uint64_t permutate_sid_key_set_odd_parity(uint64_t input_key)
{
    const uint8_t odd_parity[] = {
        1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
        16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
        32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
        49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
        64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
        81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
        97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
        112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
        128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
        145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
        161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
        176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
        193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
        208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
        224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
        241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254
    };

    uint64_t key = 0;
    uint8_t* key_array = &key;
    uint8_t* input_key_array = &input_key;

    key_array[7] = input_key_array[7] >> 1;
    key_array[6] = ((input_key_array[7] & 0x01) << 6) | (input_key_array[6] >> 2);
    key_array[5] = ((input_key_array[6] & 0x03) << 5) | (input_key_array[5] >> 3);
    key_array[4] = ((input_key_array[5] & 0x07) << 4) | (input_key_array[4] >> 4);
    key_array[3] = ((input_key_array[4] & 0x0F) << 3) | (input_key_array[3] >> 5);
    key_array[2] = ((input_key_array[3] & 0x1F) << 2) | (input_key_array[2] >> 6);
    key_array[1] = ((input_key_array[2] & 0x3F) << 1) | (input_key_array[1] >> 7);
    key_array[0] = (input_key_array[1] & 0x7F);

    for (size_t i = 0; i < 8; i++)
    {
        key_array[i] = key_array[i] << 1;
        key_array[i] = odd_parity[key_array[i]];
    }

    return key;
}


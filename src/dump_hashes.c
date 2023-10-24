#include "dump_hashes.h"

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
int dump_v_value(FILE* sam_hive, named_key_t* user_key_ptr, reg_user_t* user_info_ptr)
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

    user_info_ptr->v_value = v_value_ptr;
    user_info_ptr->v_size = v_key_ptr->data_size;

    uint32_t name_length = *((uint32_t*)(user_info_ptr->v_value) + 0x10) >> 1;
    user_info_ptr->username = malloc_check_clean(
        user_info_ptr->username,
        name_length,
        -5, 1,
        v_key_ptr
        );

    free(v_key_ptr);
    return 0;
}


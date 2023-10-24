#include "dump_hashes.h"

int dump_users_keys(FILE* sam_hive, named_key_t** users_keys_array, size_t* users_amount)
{
    // Validating errors
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
    users_keys_array = malloc_check_clean(
        users_keys_array,
        subkey_list.elements_amount * sizeof(named_key_t*),
        -9, 5,
        hive_header_ptr, base_nk_ptr, users_nk_ptr, reg_users_path, hints
    );
    memset(users_keys_array, NULL, subkey_list.elements_amount * sizeof(named_key_t*));
    *users_amount = 0;

    // Iterate throug all Users subkeys
    for (size_t lf_index = 0; lf_index < subkey_list.elements_amount; lf_index++)
    {
        // Allocating temporary name node key
        named_key_t* temp_name_key = malloc_check_clean(
            temp_name_key,
            sizeof(named_key_t),
            -10, 6,
            hive_header_ptr, base_nk_ptr,
            users_nk_ptr, reg_users_path,
            hints, users_keys_array
        );
        
        // Read the named key
        if (read_named_key(subkey_list.elements[lf_index].node_offset, sam_hive, temp_name_key) != hv_success)
        {
            cleanup_pointers(
                7,
                hive_header_ptr, base_nk_ptr,
                users_nk_ptr, reg_users_path,
                hints, users_keys_array,
                temp_name_key
            );

            return -11;
        }

        // Exclude Names from list of named keys
        if (strcmp("Names", temp_name_key->name) == 0)
        {
            free(temp_name_key);
            continue;
        }

        users_keys_array[*users_amount] = temp_name_key;
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

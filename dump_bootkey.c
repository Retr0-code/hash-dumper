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
    hive_header_t* hive_header_ptr = malloc(sizeof(hive_header_t));
    if (hive_header_ptr == NULL) 
        return -2;

    // Reading header structure
    if (read_hive_header(sys_hive, hive_header_ptr) != 0)
    {
        free(hive_header_ptr);
        return -3;
    }
    // Allocating base named key
    named_key_t* base_nk_ptr = malloc(sizeof(named_key_t));
    if (hive_header_ptr == NULL) 
    {
        free(hive_header_ptr);
        return -4;
    }

    // Reading named key structure
    if (read_named_key(hive_header_ptr->root_offset, sys_hive, base_nk_ptr) != 0)
    {
        free(hive_header_ptr);
        free(base_nk_ptr);
        return -5;
    }

    // Allocating endpoint named key
    named_key_t* lsa_nk_ptr = malloc(sizeof(named_key_t));
    if (lsa_nk_ptr == NULL) 
    {
        free(hive_header_ptr);
        free(base_nk_ptr);
        return -6;
    }

    const char* lsa_path[3] = {"CurrentControlSet", "Control", "Lsa"};
    reg_path_t* reg_lsa_path = reg_make_path(3, lsa_path);
    if (reg_lsa_path == NULL)
    {
        free(hive_header_ptr);
        free(base_nk_ptr);
        free(lsa_nk_ptr);
        return -7;
    }

    if (reg_enum_subkey(base_nk_ptr, reg_lsa_path, sys_hive, lsa_nk_ptr) != 0)
    {
        free(hive_header_ptr);
        free(base_nk_ptr);
        free(lsa_nk_ptr);
        free(reg_lsa_path);
        return -8;
    }

    named_key_t* endpoint_nk_ptr = malloc(sizeof(named_key_t));
    if (endpoint_nk_ptr == NULL)
    {
        free(hive_header_ptr);
        free(base_nk_ptr);
        free(lsa_nk_ptr);
        free(reg_lsa_path);
        return -8;
    }

    const char* lsa_values[4] = {"JD", "Skew1", "GBG", "Data"};
    reg_path_t* reg_endpoint_path;
    for (size_t i = 0; i < 4; i++)
    {
        reg_endpoint_path = reg_make_path(1, lsa_values[i]);

        if (reg_enum_subkey(base_nk_ptr, reg_endpoint_path, sys_hive, endpoint_nk_ptr) != 0)

        free(reg_endpoint_path);
    }

    free(hive_header_ptr);
    free(base_nk_ptr);
    free(lsa_nk_ptr);
    free(reg_lsa_path);
    return 0;
}

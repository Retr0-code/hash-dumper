/*
    Copyright (C) 2023 Nikita Retr0-code Korneev

    hash_dumper is free software: you can redistribute, modify it
    under the terms of the GNU Affero General Public License version 3.

    You should have received a copy of GNU Affero General Public License
    version 3 along with hash_dumper.
    If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

    This is a main file with primary logic for hash_dumper
*/

#include <errno.h>
#include <uchar.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

#include "arg_parser.h"
#include "functional.h"
#include "dump_hives.h"
#include "dump_hashes.h"
#include "dump_bootkey.h"

#if defined(_WIN32) || defined(_WIN64)
#define IS_WINDOWS 1
#else
#define IS_WINDOWS 0
#endif


#define PROGRAM_INFO    \
"hash-dumper is utility for dumping NTLMv1/2 hashes from windows registry hives SAM and SYSTEM. \
It can be used in realtime dumping mode, when hives will be dumped to temp files and then deleted, \
and mode where you can supply already dumped hives."

int main(int argc, char const *argv[])
{
    setlocale(LC_ALL, "");

    arg_parser_t* arg_parser = malloc(sizeof(arg_parser_t));

    {
        // Initializing arguments parser
        // To avoid auto resize allocating one more cell
        int res = arg_parser_init(5, PROGRAM_INFO, arg_parser);
        if (res != arg_success)
        {
            printf("[-] Error initializing argument parser: 0x%08x\n", res);
            return -1;
        }
    }

    // Adding arguments
    if (arg_add_amount(4, arg_parser,
        arg_init_arg(
            arg_flag,
            "--help",
            "Shows help message.",
            0),
        arg_init_arg(
            arg_flag,
            "--realtime",
            "Available only on windows machines. Dumps hashes from registry in realtime.",
            0),
        arg_init_arg(
            arg_parameter,
            "--sam",
            "Specifies SAM hive dump file.",
            NULL),
        arg_init_arg(
            arg_parameter,
            "--system",
            "Specifies SYSTEM hive dump file.",
            NULL)
    ) != arg_success)
    {
        puts("[-] Unable to add arguments");
        arg_parser_delete(arg_parser);
        return -1;
    }

    {
        // Parsing arguments of main
        int res = arg_parse(argc, argv, arg_parser);
        if (res != arg_success)
        {
            printf("[-] Parsing error: 0x%08x\n", res);
            if (res == arg_unknown)
                printf("Unknown arguments <%s> were given.\n", arg_get_unknown());

            arg_parser_delete(arg_parser);
            return -1;
        }
    }

    // Processing given arguments
    if (arg_get("--help", arg_parser)->value)
    {
        arg_show_help(arg_parser);
        arg_parser_delete(arg_parser);
        return 0;
    }

    argument_t* realtime_arg = arg_get("--realtime", arg_parser);
    int realtime_flag_count = 0;

    if (realtime_arg != NULL && IS_WINDOWS)
        realtime_flag_count = realtime_arg->value;
    
    int delete_hives = 0;
    argument_t* sam_arg = arg_get("--sam", arg_parser);
    argument_t* system_arg = arg_get("--system", arg_parser);
    if (realtime_flag_count)
    {
        delete_hives = 1;
        int res = resolve_temp_paths();
        if (res != 0)
        {
            printf("[-] Unable to save temp hives files 0x%08x\n", res);
            arg_parser_delete(arg_parser);
            return -1;
        }
    }
    else if (realtime_flag_count == 0 && sam_arg->value != NULL && system_arg->value != NULL)
        set_paths(system_arg->value, sam_arg->value);
    else
    {
        arg_show_help(arg_parser);
        arg_parser_delete(arg_parser);
        return 0;
    }

    arg_parser_delete(arg_parser);

    FILE* system_hive = NULL;
    FILE* sam_hive = NULL;
    if (open_hives(&system_hive, &sam_hive))
    {
        puts("[-] Unable to open hives files. Check if hives specified properly");
        return -1;
    }

    puts("[+] Hives successfully opened");

    char16_t boot_key_hex[33];
    {
        int result = dump_bootkey(system_hive, boot_key_hex);
        if (result != 0)
        {
            printf("[-] Unable to read bootkey: 0x%08x\n", result);
            close_hives(&system_hive, &sam_hive, delete_hives);
            return -1;
        }
    }
#ifdef __linux__
    wchar_t* boot_key_hex32 = u16_to_u32(boot_key_hex);
    printf("[+] Successfully dumped bootkey: %ls\n", boot_key_hex32);
    free(boot_key_hex32);
#else
    printf("[+] Successfully dumped bootkey: %ls\n", boot_key_hex);
#endif

    uint8_t hashed_bootkey[0x20];
    memset(hashed_bootkey, 0, 0x20);
    {
        int result = get_hashed_bootkey(boot_key_hex, sam_hive, hashed_bootkey);
        if (result != 0)
        {
            printf("[-] Failed to get hashed bootkey: 0x%08x\n", result);
            close_hives(&system_hive, &sam_hive, delete_hives);
            return -1;
        }
    }

    printf("[+] Successfully hashed the bootkey: ");
    for (size_t i = 0; i < 0x10; i++)
        printf("%02x", hashed_bootkey[i]);

    puts("\n");

    named_key_t* users_keys_list = NULL;
    size_t users_amount = 0;
    {
        int res = dump_users_keys(sam_hive, &users_keys_list, &users_amount);
        if (res != 0)
        {
            printf("[-] Error retrieving users keys: 0x%08x\n", res);
            close_hives(&system_hive, &sam_hive, delete_hives);
            return -1;
        }
    }

    char ascii_nthash[33];
    char ascii_lmhash[33];
    ntlm_user_t user;
    for (size_t i = 0; i < users_amount; i++)
    {
        ntlm_user_init(&user);
        int res = dump_v_value(sam_hive, &users_keys_list[i], &user);
        if (res != 0)
        {
            close_hives(&system_hive, &sam_hive, delete_hives);
            free(users_keys_list);
            printf("[-] Error dumping V: 0x%08x", res);
            return -1;
        }

        res = dump_user_name(&user);
        if (res != 0)
        {
            close_hives(&system_hive, &sam_hive, delete_hives);
            free(users_keys_list);
            printf("[-] Error reading user name from V: 0x%08x\n", res);
            return -1;
        }

        dump_user_ntlm(&user, hashed_bootkey);
        bytes_to_hex(user.nthash, 16, ascii_nthash);
        bytes_to_hex(user.lmhash, 16, ascii_lmhash);
        ascii_nthash[32] = '\0';
        ascii_lmhash[32] = '\0';

#ifdef __linux__
        wchar_t* user_name = u16_to_u32(user.name);
        if (user_name == NULL)
        {
            printf("[-] Unable to convert username with sid: %i\n", user.sid);
            user_name = L"Unknown";
        }

        printf("%ls:%i:%s:%s:::\n", user_name, user.sid, ascii_lmhash, ascii_nthash);
        free(user_name);
#else
        printf("%ls:%i:%s:%s:::\n", user.name, user.sid, ascii_lmhash, ascii_nthash);
#endif
        ntlm_user_destroy(&user);
    }

    close_hives(&system_hive, &sam_hive, delete_hives);
    free(users_keys_list);
    puts("\n[+] Successfully finished");
    return 0;
}

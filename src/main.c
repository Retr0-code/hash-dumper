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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "arg_parser.h"
#include "dump_hives.h"
#include "dump_bootkey.h"

int main(int argc, char const *argv[])
{
    arg_parser_t* arg_parser = malloc(sizeof(arg_parser_t));

    {
        int res = arg_parser_init(1, arg_parser);
        if (res != arg_success)
        {
            printf("Error initializing parser: %i\n", res);
            return -1;
        }
    }

    if (arg_add(arg_init_arg(
        arg_flag,
        "--realtime",
        "Available only on windows machines. Dumps hashes from registry in realtime.",
        0), arg_parser) != arg_success)
    {
        puts("Unable to add argument <--realtime>");
        return -1;
    }

    {
        int res = arg_parse(argc, argv, arg_parser);
        if (res != arg_success)
        {
            printf("Parsing error: %i\n", res);
            arg_parser_delete(arg_parser);
            return -1;
        }
    }

    if (arg_get("--realtime", arg_parser) == NULL)
    {
        puts("No argument");
        arg_parser_delete(arg_parser);
        return -1;
    }

    arg_parser_delete(arg_parser);
    exit(0);

#ifdef __linux__
    set_paths("hives/system.dump", "hives/sam.dump");
#elif defined(_WIN32) || defined(_WIN64)
    resolve_temp_paths();
#endif

    FILE* system_hive = NULL;
    FILE* sam_hive = NULL;
    if (open_hives(&system_hive, &sam_hive))
    {
        puts("Unable to open hives files");
        return -1;
    }

    wchar_t* boot_key_hex[33];
    {
        int result = dump_bootkey(system_hive, boot_key_hex);
        if (result != 0)
        {
            printf("Unable to read bootkey: %i\n", result);
            fclose(system_hive);
            free(boot_key_hex);
            return -1;
        }
    }

    printf("bootkey: %ls\n", boot_key_hex);

    uint8_t hashed_bootkey[0x20];
    memset(hashed_bootkey, 0, 0x20);
    {
        int result = get_hashed_bootkey(boot_key_hex, sam_hive, hashed_bootkey);
        if (result != 0)
            printf("%i\n", result);
    }

    puts("\nhashed bootkey:");
    for (size_t i = 0; i < 0x20; i++)
        printf("%02x", hashed_bootkey[i]);

    close_hives(&system_hive, &sam_hive);

    return 0;
}

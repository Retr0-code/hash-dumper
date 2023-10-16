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

#include "dump_hives.h"
#include "dump_bootkey.h"

int main(int argc, char const *argv[])
{
#ifdef __linux__
    set_paths("hives/system.dump", "hives/sam.dump");
#elif defined(_WIN32) || defined(_WIN64)
    resolve_temp_paths();
#endif

    FILE* system_hive = NULL;
    FILE* sam_hive = NULL;
    open_hives(&system_hive, &sam_hive);

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

    printf("%ls\n", boot_key_hex);

    uint8_t hashed_bootkey[32];
    get_hashed_bootkey(boot_key_hex, sam_hive, hashed_bootkey);

    for (size_t i = 0; i < 32; i++)
        printf("%02x", hashed_bootkey[i]);

    close_hives(&system_hive, &sam_hive);

    return 0;
}

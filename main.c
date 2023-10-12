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
#include <Windows.h>

#include "hash_dump.h"
#include "dump_bootkey.h"

int main(int argc, char const *argv[])
{
    FILE* system_hive = NULL;
    FILE* sam_hive = NULL;
    open_hives(&system_hive, &sam_hive);

    wchar_t* boot_key_hex[33];
    if (dump_bootkey(system_hive, boot_key_hex) != 0)
    {
        puts("Unable to read bootkey");
        fclose(system_hive);
        free(boot_key_hex);
        return -1;
    }

    printf("%ls\n", boot_key_hex);
    close_hives(&system_hive, &sam_hive);

    return 0;
}

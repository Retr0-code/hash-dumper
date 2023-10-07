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
    char path_for_save[MAX_PATH];
    if (GetEnvironmentVariableA("TEMP", path_for_save, MAX_PATH) == 0)
    {
        printf("Unable to resolve local variable: %i\n", GetLastError());
        return -1;
    }

    strcat(path_for_save, "\\system.dump");

    if (reg_save_key("SYSTEM", path_for_save))
    {
        puts("Unable to save a hive");
        return -1;
    }

    FILE* system_hive = fopen(path_for_save, "rb");
    if (system_hive == NULL)
    {
        printf("Unable to open system hive: %s\n", strerror(errno));
        return -1;
    }

    wchar_t* boot_key_hex = malloc(32 * sizeof(wchar_t));
    if (boot_key_hex == NULL)
    {
        puts("Unable to allocate bootkey");
        fclose(system_hive);
        return -1;
    }

    if (dump_bootkey(system_hive, boot_key_hex) != 0)
    {
        puts("Unable to read bootkey");
        fclose(system_hive);
        free(boot_key_hex);
        return -1;
    }

    printf("%ls\n", boot_key_hex);

    fclose(system_hive);
    free(boot_key_hex);

    if (remove(path_for_save) != 0)
    {
        printf("Error removing file %s:\n\t%s\n", path_for_save, strerror(errno));
        return -1;
    }
    
    return 0;
}

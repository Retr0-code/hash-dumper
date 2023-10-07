#ifndef DUMP_BOOTKEY_H
#define DUMP_BOOTKEY_H

#include <wchar.h>
#include <stdlib.h>
#include <stdint.h>

#include "hive.h"

int dump_bootkey(FILE* sys_hive, wchar_t* out_bootkey);

#endif

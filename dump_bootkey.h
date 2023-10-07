/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.


----

	References used:
	 - Registry hive basics and structure / https://binaryforay.blogspot.com/2015/01/registry-hive-basics.html?m=1
	 - Windows registry foremat specs / https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
	 - Syskey and SAM / https://moyix.blogspot.com/2008/02/syskey-and-sam.html

----

	This header describes a functionality to dump bootkey and hashed bootkey
*/

#ifndef DUMP_BOOTKEY_H
#define DUMP_BOOTKEY_H

#include <wchar.h>
#include <stdlib.h>
#include <stdint.h>

#include "hive.h"

int dump_bootkey(FILE* sys_hive, wchar_t* out_bootkey);

#endif

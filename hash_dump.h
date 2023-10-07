/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

	This header describes functions for dumping NTLM hashes from SAM and SYSTEM
*/

#ifndef HASH_DUMP_H
#define HASH_DUMP_H

#include <stdlib.h>
#include <stdint.h>
#if defined(WIN32) || defined(WIN64)
#include <Windows.h>
#else
typedef int BOOL;
typedef void* HANDLE;
typedef wchar_t* LPCTSTR;
#endif

// Saves registry hive
int reg_save_key(const char* key_name, const char* save_to);

// Sets windows privilege to process
static int enable_privilege(HANDLE token_handle, LPCTSTR privilege, BOOL enable);

#endif

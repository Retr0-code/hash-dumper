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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
typedef int BOOL;
typedef void* HANDLE;
typedef wchar_t* LPCTSTR;
#endif

#include "functional.h"

#define HIVE_NAME_LENGTH 12

// Sets paths to hives
void set_paths(const char* sys_hive_path, const char* sam_hive_path);

// Resolves %temp% paths and sets static variables
int resolve_temp_paths();

// Opens files and writes pointers to specified parameters
int open_hives(FILE** system_hive, FILE** sam_hive);

// Deletes files and closes handles
void close_hives(FILE** system_hive, FILE** sam_hive, int delete_hives);

// Saves registry hive
static int reg_save_key(const char* key_name, const char* save_to);

// Sets windows privilege to process
static int enable_privilege(HANDLE token_handle, LPCTSTR privilege, BOOL enable);

#endif

/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

	This header describes functions for working with low-level hives in windows registry
*/

/*! \file dump_hives.h
 *	\brief This header describes functions for working with low-level hives in windows registry
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

/*! \fn void set_paths(const char* sys_hive_path, const char* sam_hive_path)
 *	\brief Sets \a system_hive_filepath and \a sam_hive_filepath static variables to specified values.
 *	\param[in] sys_hive_path	ASCII string of path to saved SYSTEM hive file.
 *	\param[in] sam_hive_path	ASCII string of path to saved SAM hive file.
 */
void set_paths(const char* sys_hive_path, const char* sam_hive_path);

/*! \fn int resolve_temp_paths()
 *	\brief Resolves %temp% paths and sets system_hive_filepath and sam_hive_filepath static variables to specified values.
 */
int resolve_temp_paths();

/*! \fn int resolve_temp_paths()
 *	\brief Opens files and writes file descriptor pointers to specified parameters.
 *	\param[out] system_hive		constructs file descriptor to SYSTEM hive file using path from \a system_hive_filepath.
 *	\param[out] sam_hive		constructs file descriptor to SAM hive file using path from \a sam_hive_filepath.
 *	\return 0 on success or negative numbers correlated to steps of function.
 */
int open_hives(FILE** system_hive, FILE** sam_hive);

/*! \fn void close_hives(FILE** system_hive, FILE** sam_hive, int delete_hives)
 *	\brief Closes handles and deletes.
 *	\param[in] system_hive		constructs file descriptor to SYSTEM hive file using path from \a system_hive_filepath.
 *	\param[in] sam_hive			constructs file descriptor to SAM hive file using path from \a sam_hive_filepath.
 *	\param[in] delete_hives		if value not 0 deletes hives files.
 */
void close_hives(FILE** system_hive, FILE** sam_hive, int delete_hives);

/*! \fn static int reg_save_key(const char* key_name, const char* save_to)
 *	\brief Wrapper for WinAPI RegSaveKey function.
 *	\param[in] key_name		registry path to node.
 *	\param[in] save_to		path to saving directory.
 *	\return 0 on success or negative numbers correlated to steps of function.
 */
static int reg_save_key(const char* key_name, const char* save_to);

/*! \fn static int enable_privilege(HANDLE token_handle, LPCTSTR privilege, BOOL enable)
 *	\brief Sets windows privilege to process
 *	\param[in] token_handle		handle to a process privilege token.
 *	\param[in] privilege		name of a privilege.
 *	\param[in] enable			indicates if enable or disable the privilege.
 *	\return 0 on success or negative numbers correlated to steps of function.
 */
static int enable_privilege(HANDLE token_handle, LPCTSTR privilege, BOOL enable);

#endif

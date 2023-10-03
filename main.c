#include "hive.h"
#include <stdio.h>

int main(int argc, char const** argv)
{
	FILE* hive_handle = fopen("./TestingDumper.save", "rb");

	if (hive_handle == NULL)
	{
		printf("Error opening file: %s\n", strerror(errno));
		return -1;
	}

	puts("Hive file successfully opened\n");

	hive_header_t* hive_header_ptr = malloc(sizeof(hive_header_t));
	read_hive_header(hive_handle, hive_header_ptr);

	named_key_t* base_nk_ptr = malloc(sizeof(named_key_t));
	if (read_named_key(hive_header_ptr->root_offset, hive_handle, base_nk_ptr) != 0)
	{
		puts("Failed to read a key");
		printf("%s\n", strerror(errno));
		return -1;
	}
	
	const char* internal_reg[1] = {"InternalDirectory"};
	reg_path_t* reg_path_ptr = reg_make_path(1, internal_reg);

	if (reg_path_ptr == NULL)
	{
		puts("Failed to initialize a registry path");
		printf("%s\n", strerror(errno));
		return -1;
	}

	named_key_t* final_nk_ptr = malloc(sizeof(named_key_t));
	if (enum_subkey(base_nk_ptr, reg_path_ptr, hive_handle, final_nk_ptr))
	{
		puts("Failed to enumerate a key");
		printf("%s\n", strerror(errno));
		return -1;
	}

	puts(final_nk_ptr->name);

	fclose(hive_handle);
	free(hive_header_ptr);
	free(base_nk_ptr);
	free(reg_path_ptr);
	free(final_nk_ptr);

	return 0;
}

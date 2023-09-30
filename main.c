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

	abstract_key_t* some_key = malloc(sizeof(abstract_key_t));
	if (read_key(0x1000, hive_header_ptr->root_offset, hive_handle, some_key))
	{
		puts("Failed to read the key");
		printf("%s\n", strerror(errno));
		return -1;
	}

	if (convert_to_nk(some_key) == NULL)
	{
		puts("Failed to convert the key");
		return -1;
	}

	fclose(hive_handle);
	free(hive_header_ptr);
	free(some_key);

	return 0;
}

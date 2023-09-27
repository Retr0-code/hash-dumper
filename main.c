#include "hive.h"
#include <stdio.h>


int main(int argc, char const** argv)
{
	FILE* hive_handle = NULL;
	errno_t fopen_error = fopen_s(&hive_handle, "./TestingDumper.save", "rb");

	if (hive_handle == NULL)
	{
		char error_buffer[94];
		strerror_s(error_buffer, 94, fopen_error);
		printf("Error opening file: %s\n", error_buffer);
		return -1;
	}

	puts("Hive file successfully opened\n");

	hive_header_t* hive_header_ptr = malloc(sizeof(hive_header_t));
	read_hive_header(hive_handle, hive_header_ptr);

	abstract_key_t* some_key = malloc(sizeof(abstract_key_t));
	read_key(0x1000, hive_header_ptr->root_offset, hive_handle, some_key);

	convert_to_nk(some_key);

	fclose(hive_handle);
	free(hive_header_ptr);
	free(some_key);

	return 0;
}

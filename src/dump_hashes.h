#ifndef DUMP_HASHES_H
#define DUMP_HASHES_H

#include <stdlib.h>
#include <stdint.h>

#include "hive.h"
#include "crypto.h"


// Reads users named keys from SAM hive. Writes array to users_keys and size of the array to users_amount
int dump_users_keys(FILE* sam_hive, named_key_t** users_keys_array, size_t* users_amount);


#endif

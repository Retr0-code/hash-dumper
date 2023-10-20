/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

	This header describes functions and structs for argument parsing
*/

#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <stdlib.h>

#include "functional.h"
#include "string-hashtable/hash_table.h"

enum arg_errors
{
    arg_success,
    arg_invalid_arg,
    arg_init_error,
    arg_alloc_error,
    arg_no_entity,
    arg_unknown
};

typedef enum
{
    arg_flag,
    arg_parameter,
} arg_type;

typedef struct
{
    arg_type type;
    const char* key;
    const char* description;
    const char* value;
} argument_t;

typedef struct
{
    size_t amount;
    hashtable_t* arguments;
    const char* prog_info;
} arg_parser_t;

// Constructs an argument parser with total amount of arguments
int arg_parser_init(size_t args_amount, arg_parser_t* parser_ptr);

// Deletes the arguments parser
int arg_parser_delete(arg_parser_t* parser_ptr);

// Constructs an argument_t pointer with specified parameters 
const argument_t* arg_init_arg(arg_type type, const char* key, const char* description, void* value);

// Adds specified arguments pointer to parser
int arg_add(const argument_t* arg, arg_parser_t* parser_ptr);

// Adds specified amount of arguments to parser
int arg_add_amount(size_t args_amount, arg_parser_t* parser_ptr, ...);

// Retrieves argument or NULL if does not exist
argument_t* arg_get(const char* key, arg_parser_t* parser_ptr);

// Parses arguments given to main function
int arg_parse(int argc, const char** argv, arg_parser_t* parser_ptr);

// Deletes argument pointer
int arg_delete(argument_t* arg);

#endif

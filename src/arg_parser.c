/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

	hash_dumper is free software: you can redistribute, modify it
	under the terms of the GNU Affero General Public License version 3.

	You should have received a copy of GNU Affero General Public License
	version 3 along with hash_dumper.
	If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

----

	This file defines functions and structs for argument parsing
*/

#include "arg_parser.h"

int arg_parser_init(size_t args_amount, const char* prog_info, arg_parser_t* parser_ptr)
{
    // Validating parameters
    if (args_amount == 0 || parser_ptr == NULL)
    {
        errno = EINVAL;
        return arg_invalid_arg;
    }

    // Allocating hashtable for arguments
    parser_ptr->arguments = malloc_check(parser_ptr->arguments, sizeof(hashtable_t), arg_alloc_error);

    // Initializing the hashtable
    if (ht_init(args_amount, &fnv_1a, parser_ptr->arguments) != 0)
    {
        errno = EBADF;
        return arg_init_error;
    }

    parser_ptr->prog_info = prog_info;
    parser_ptr->amount = args_amount;
    return arg_success;
}

int arg_parser_delete(arg_parser_t* parser_ptr)
{
    if (parser_ptr == NULL)
        return arg_no_entity;
    
    for (size_t i = 0; i < parser_ptr->arguments->size; i++)
        if (parser_ptr->arguments->data[i] != NULL && parser_ptr->arguments->data[i]->value != NULL)
            arg_delete(parser_ptr->arguments->data[i]->value);
    
    ht_destroy(parser_ptr->arguments);

    free(parser_ptr);
    return arg_success;
}

const argument_t* arg_init_arg(arg_type type, const char* key, const char* description, void* value)
{
    // Validating parameters
    if (key == NULL || description == NULL)
    {
        errno = EINVAL;
        return arg_invalid_arg;
    }

    argument_t* arg_ptr = malloc_check(arg_ptr, sizeof(argument_t), NULL);
    arg_ptr->type = type;
    arg_ptr->key = key;
    arg_ptr->description = description;
    arg_ptr->value = value;
    return arg_ptr;
}

int arg_add(const argument_t* arg, arg_parser_t* parser_ptr)
{
    // Validating parameters
    if (arg == NULL || parser_ptr == NULL)
    {
        errno = EINVAL;
        return arg_invalid_arg;
    }

    // Adding new record to hashtable
    if (!ht_emplace(arg->key, arg, parser_ptr->arguments))
        return arg_success;

    return arg_no_entity;
}

int arg_add_amount(size_t args_amount, arg_parser_t* parser_ptr, ...)
{
    if (args_amount == 0 || parser_ptr == NULL)
    {
        errno = EINVAL;
        return arg_invalid_arg;
    }

    va_list arguments;
    va_start(arguments, parser_ptr);

    for (; args_amount > 0; --args_amount)
    {
        int res = arg_add(va_arg(arguments, argument_t*), parser_ptr);
        if (res != arg_success)
        {
            va_end(arguments);
            return res;
        }
    }

    va_end(arguments);
    return arg_success;
}

argument_t *arg_get(const char *key, arg_parser_t *parser_ptr)
{
    // Validating parameters
    if (key == NULL || parser_ptr == NULL)
    {
        errno = EINVAL;
        return arg_invalid_arg;
    }

    return ht_get_elem(key, parser_ptr->arguments);
}

int arg_parse(int argc, const char **argv, arg_parser_t *parser_ptr)
{
    // Validating parameters
    if (argc == 0 || argc == NULL || parser_ptr == NULL)
    {
        errno = EINVAL;
        return arg_invalid_arg;
    }

    // Iterating through argv
    for (int i = 1; i < argc; i++)
    {
        // Parsing argument from hash table
        argument_t* arg = arg_get(argv[i], parser_ptr);

        // If argument was not found
        if (arg == NULL)
            return arg_unknown;

        // If argument is parameter then next argument is a value
        if (arg->type == arg_parameter)
            arg->value = argv[++i];

        // If argument is flag type then it increments
        if (arg->type == arg_flag)
            ++arg->value;
    }

    return arg_success;
}

// TODO(Fix tabulation issue)
void arg_show_help(arg_parser_t* parser_ptr)
{
    printf("%s\n\n", parser_ptr->prog_info);

    for (size_t i = 0; i < parser_ptr->arguments->size; i++)
    {
        if (parser_ptr->arguments->data[i] == NULL)
            continue;

        argument_t* arg_temp = parser_ptr->arguments->data[i]->value;
        const char* type_val = arg_temp->type == arg_flag ? "FLAG" : "PARM";
        printf("%s\t%10s\t%s\n", arg_temp->key, type_val, arg_temp->description);

        ht_node_t* temp_node = parser_ptr->arguments->data[i];
        while (temp_node->next != NULL)
        {
            temp_node = temp_node->next;
            arg_temp = temp_node->value;
            type_val = arg_temp->type == arg_flag ? "FLAG" : "PARM";
            printf("%s\t%10s\t%s\n", arg_temp->key, type_val, arg_temp->description);
        }
    }
}

int arg_delete(argument_t *arg)
{
    if (arg == NULL)
        return arg_no_entity;

    free(arg);
    return arg_success;
}

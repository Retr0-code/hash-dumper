#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <stdlib.h>
#include "hashtable.h"

typedef enum arg_type
{
    flag,
    parameter,
    help
};

typedef enum arg_mode
{
    required,
    optional
};

typedef struct
{
    const char* key;
    arg_type type;
    arg_mode mode;

} argument;

typedef struct
{
    size_t amount;
    argument* submitted_args;
} arg_parser;

#endif

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

/*! \file arg_parser.h
 *  \brief This header describes functions and structs for argument parsing
 */

#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <stdio.h>
#include <stdlib.h>

#include "functional.h"
#include "string-hashtable/hash_table.h"

/*! \enum arg_errors
 *  \brief 
 */
enum arg_errors
{
    arg_success,        //!< Function completed successfully.
    arg_invalid_arg,    //!< Function got an invalid argument (e.g. NULL pointer).
    arg_init_error,     //!< Parser or argument cannot be initialized.
    arg_alloc_error,    //!< Failed allocation inside a function.
    arg_no_entity,      //!< Key does not exist.
    arg_unknown         //!< Unknown argument.
};

/*! \enum arg_type
 *  \brief Defines types of arguments
 */
typedef enum
{
    arg_flag,       //!< Stores as value count of arguments.
    arg_parameter,  //!< Stores next argument as a value.
} arg_type;

/*! \struct argument_t
 *  \brief Defines structure for argument.
 */
typedef struct
{
    arg_type type;              //!< Argument type flag/parameter.
    const char* key;            //!< Key associated with arguemt.
    const char* description;    //!< Description of given argument.
    const char* value;          //!< Container for specified value if type is parameter and count if flag.
} argument_t;

/*! \struct arg_parser_t
 *  \brief Describes argument parser.
 */
typedef struct
{
    size_t amount;              //!< Stores amount of specified arguments.
    hashtable_t* arguments;     //!< Hashtable for arguments.
    const char* prog_info;      //!< Info of program.
} arg_parser_t;

/*! \fn int arg_parser_init(size_t args_amount, const char* prog_info, arg_parser_t* parser_ptr)
 *  \brief Constructs an argument parser with total amount of arguments.
 *  \param[in] args_amount      Total amount of arguments that were given.
 *  \param[in] prog_info        Description of the app.
 *  \param[out] parser_ptr      Pointer to argument parser uninitialized structure.
 *	\return	value of \a arg_errors enumeration (0 or \a arg_success on success).
 */
int arg_parser_init(size_t args_amount, const char* prog_info, arg_parser_t* parser_ptr);

/*! \fn int arg_parser_delete(arg_parser_t* parser_ptr)
 *  \brief Deletes the arguments parser.
 *  \param[in] parser_ptr       Total amount of arguments that were given.
 *	\return	value of \a arg_errors enumeration (0 or \a arg_success on success).
 */
int arg_parser_delete(arg_parser_t* parser_ptr);

/*! \fn const argument_t* arg_init_arg(arg_type type, const char* key, const char* description, void* value)
 *  \brief Constructs an argument_t pointer with specified parameters.
 *  \param[in] type         Argument type flag/parameter.
 *  \param[in] key          Key associated with arguemt.
 *  \param[in] description  Description of given argument.
 *  \param[in] value        Default argument's value.
 *	\return	initialized argument structure or NULL on error.
 */
const argument_t* arg_init_arg(arg_type type, const char* key, const char* description, void* value);

/*! \fn int arg_add(const argument_t* arg, arg_parser_t* parser_ptr)
 *  \brief Adds single specified arguments pointer to parser.
 *  \param[in] arg          pointer to argument structure.
 *  \param[in] parser_ptr   pointer to parser structure.
 *	\return	value of \a arg_errors enumeration (0 or \a arg_success on success).
 */
int arg_add(const argument_t* arg, arg_parser_t* parser_ptr);

/*! \fn int arg_add(const argument_t* arg, arg_parser_t* parser_ptr)
 *  \brief Adds multiple specified arguments pointer to parser.
 *  \param[in] args_amount  amount of specified arguments.
 *  \param[in] parser_ptr   pointer to parser structure.
 *  \param[in] ...          variadic list of arguments.
 *	\return	value of \a arg_errors enumeration (0 or \a arg_success on success).
 */
int arg_add_amount(size_t args_amount, arg_parser_t* parser_ptr, ...);

/*! \fn argument_t* arg_get(const char* key, arg_parser_t* parser_ptr)
 *  \brief Returns pointer argument struct or NULL if does not exist.
 *  \param[in] key          Key associated with arguemt.
 *  \param[in] parser_ptr   pointer to parser structure.
 *	\return	pointer to argument struct or NULL if does not exists.
 */
argument_t* arg_get(const char* key, arg_parser_t* parser_ptr);

/*! \fn int arg_parse(int argc, const char** argv, arg_parser_t* parser_ptr)
 *  \brief Parses arguments given to main function.
 *  \param[in] argc         arguments amount including first arguments.
 *  \param[in] argv         arguments strings array.
 *  \param[in] parser_ptr   pointer to parser structure.
 *	\return	value of \a arg_errors enumeration (0 or \a arg_success on success).
 */
int arg_parse(int argc, const char** argv, arg_parser_t* parser_ptr);

/*! \fn void arg_show_help(arg_parser_t* parser_ptr)
 *  \brief Shows help message/manual.
 *  \param[in] parser_ptr   pointer to parser structure.
 */
void arg_show_help(arg_parser_t* parser_ptr);

/*! \fn int arg_delete(argument_t* arg)
 *  \brief Deletes argument pointer
 *  \param[in] parser_ptr   pointer to argument structure.
 *	\return	value of \a arg_errors enumeration (0 or \a arg_success on success).
 */
int arg_delete(argument_t* arg);

#endif

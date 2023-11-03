/*
	Copyright (C) 2023 Nikita Retr0-code Korneev

    hash_dumper is free software: you can redistribute, modify it
    under the terms of the GNU Affero General Public License version 3.

    You should have received a copy of GNU Affero General Public License
    version 3 along with hash_dumper.
    If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.


----

	References used:
	 - Registry hive basics and structure / https://binaryforay.blogspot.com/2015/01/registry-hive-basics.html?m=1
	 - Windows registry foremat specs / https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

----

	This header describes an API for interaction with registry hive file
*/

/*! \file hive.h
 *	\brief This header describes an API for interaction with registry hive file
 */

#ifndef HIVE_H
#define HIVE_H

#include <stdio.h>
#include <errno.h>
#include <uchar.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include "functional.h"

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#endif

#define HV_LITTLE_ENDIAN 1
#define HV_BIG_ENDIAN 2

// By default endianness type is little endian, but you can change it to BIG_ENDIAN if this is your case
#define HV_ENDIANNESS HV_LITTLE_ENDIAN


#ifdef _MSC_VER
 #define PACK(__decl__) __pragma(pack(push, 1)) __decl__ __pragma(pack(pop))

#elif defined(__GNUC__)
#define PACK(__decl__) __decl__ __attribute__((__packed__))

#endif


/*
NKF_KEY_VOLATILE		- is volatile (not used, a key node on a disk isn't expected to have this flag set)
NKF_HIVE_EXIT			- is the mount point of another hive (a key node on a disk isn't expected to have this flag set)
NKF_HIVE_ENTRY_ROOT	- determines the root node of the Registry hive
NKF_NO_DELETE			- this key can't be deleted
NKF_KEY_SYM_LINK		- this key is a symlink (in UTF-16LE)
NKF_COMPRESSED_NAME	- uses ASCII instead of 16bit
NKF_KEY_PREDEF_HANDLE	- is a predefined handle (a handle is stored in the Number of key values field)
*/
#define NKF_KEY_VOLATILE		(uint16_t)0b00000001
#define NKF_HIVE_EXIT			(uint16_t)0b00000010
#define NKF_HIVE_ENTRY_ROOT	(uint16_t)0b00000100
#define NKF_NO_DELETE			(uint16_t)0b00001000
#define NKF_KEY_SYM_LINK		(uint16_t)0b00010000
#define NKF_COMPRESSED_NAME	(uint16_t)0b00100000
#define NKF_KEY_PREDEF_HANDLE	(uint16_t)0b01000000

/*
VKF_VALUE_COMP_NAME		- Value name is an ASCII string, possibly an extended ASCII string (otherwise it is a UTF-16LE string)
VKF_IS_TOMBSTONE		- a tombstone value has the Data type field set to REG_NONE, the Data size field set to 0, and the Data offset field set to (uint32_t)-1
*/
#define VKF_VALUE_COMP_NAME		(uint16_t)0b00000001
#define VKF_IS_TOMBSTONE		(uint16_t)0b00000010


#if (HV_ENDIANNESS == HV_LITTLE_ENDIAN)

#define HIVE_SIGN	BYTE_SWAP32((uint32_t)0x72656766)
#define HBIN_SIGN	BYTE_SWAP32((uint32_t)0x6862696E)
#define NK_SIGN		BYTE_SWAP16((uint16_t)0x6E6B)
#define VK_SIGN		BYTE_SWAP16((uint16_t)0x766B)
#define SK_SIGN		BYTE_SWAP16((uint16_t)0x736B)
#define LF_SIGN		BYTE_SWAP16((uint16_t)0x6C66)
#define LH_SIGN		BYTE_SWAP16((uint16_t)0x6C68)

#elif (HV_ENDIANNESS == HV_BIG_ENDIAN)

#define HIVE_SIGN	(uint32_t)0x72656766
#define HBIN_SIGN	(uint32_t)0x6862696E
#define NK_SIGN		(uint16_t)0x6E6B
#define VK_SIGN		(uint16_t)0x766B
#define SK_SIGN		(uint16_t)0x736B
#define LF_SIGN		(uint16_t)0x6C66
#define LH_SIGN		(uint16_t)0x6C68

#else

#error "Unsupported ENDIANNESS type"

#endif

/*! \struct hive_header_t
 *	\brief Contains header of hive.
 */
typedef PACK(struct hive_header_t
{
	uint32_t signature;			//!< Signature 0x72656766 == "regf
	uint64_t padding1;			//!< Random padding
	uint64_t last_write_time;	//!< DOS format
	uint32_t major_ver;			//!< Regisry major version
	uint32_t minor_ver;			//!< Regisry minor version
	uint64_t padding2;			//!< Random padding
	uint32_t root_offset;		//!< Specifies an relative root's offset of containers
	uint32_t size;				//!< Amount of hbins in hive
	char16_t name[255];			//!< Hive name
}) hive_header_t;


/*! \struct named_key_t
 *	\brief A NK (named/node key) record contains the information necessary to define a key (and subkeys as well).
 */
typedef PACK(struct named_key_t
{
	int32_t size;				//!< Size of hbin, which is negative if container in use
	uint16_t signature;			//!< Signature 0x6E6B == "nk"
	uint16_t flags;				//!< Binary nk flags
	uint64_t last_write_time;	//!< DOS format
	uint32_t padding1;			//!< 0 padding
	uint32_t parent_offset;		//!< Offset to parent cell if HIVE_ENTRY_ROOT_REG_FLAG is set it points to 0xFFFFFFFF
	uint32_t subkey_amount;		//!< Stores amount of subkeys only one step deepper
	uint32_t padding2;			//!< 0 padding
	uint32_t subkey_offset;		//!< Offset to fast leaf
	uint32_t padding3;			//!< -1 padding
	uint32_t values_amount;		//!< Values in current subkey
	uint32_t value_offset;		//!< Offset to nearest value key
	uint32_t security_offset;	//!< Offset to security key record
	uint32_t class_name_offset;	//!< Offset of nodes class name
	uint32_t sub_max_namelen;	//!< The largest name of subkey
	uint32_t sub_max_classlen;	//!< The largest class name of subkey
	uint32_t val_max_namelen;	//!< The largest name of value key
	uint32_t val_max_datalen;	//!< The largest data of value key
	uint32_t padding4;			//!< Random padding
	int16_t name_length;		//!< Length of node name
	int16_t class_length;		//!< Length of node class name
	char* name;					//!< Name of a key
}) named_key_t;

/*! \struct value_key_t
 *	When the most significant bit is 1, data(4 bytes or less) is stored in
 *	the Data offset field directly(when data contains less than 4 bytes,
 *	it is being stored as is in the beginning of the Data offset field).
 *	The most significant bit(when set to 1) should be ignored when calculating the data size.
 */
typedef PACK(struct value_key_t
{
	int32_t size;				//!< Size of key, which is negative if container in use
	uint16_t signature;			//!< Signature 0x766B == "vk"
	uint16_t name_length;		//!< Value name length if 0 name not set (Default)
	uint32_t data_size;			//!< Amount of bytes of stored data (if higher bit is set then data is stored in data_offset)
	uint32_t data_offset_val;	//!< Stores offset to data or the data if size less then or equal to 4
	uint32_t data_type;			//!< Datatypes defined in Winnt.h (https://learn.microsoft.com/en-us/windows/win32/shell/hkey-type)
	uint16_t flags;				//!< Binary vk flags
	uint16_t padding;			//!< Random padding
	char* name;					//!< Value's name (optional if the length is 0)
}) value_key_t;

/*! \struct value_list_t
 *	Stores list of 32-bit offsets to value keys.
 */
typedef PACK(struct value_list_t
{
	int32_t size;				//!< Size of key, which is negative if container in use
	uint32_t* offsets;			//!< Offsets to value_key_t structures
}) value_list_t;

/*! \struct secure_key_t
 *	A SK (security key) record contains the information
 *	necessary to define access controls for the Registry.
 *	An example of an SK record as it exists on disk is shown below.
 */
typedef PACK(struct secure_key_t
{
	int32_t size;				//!< Size of key, which is negative if container in use
	uint16_t signature;			//!< Signature 0x736B == "sk"
	uint16_t padding;			//!< 0 padding
	uint32_t forward_link;		//!< the offset to the next SK record in the hive
	uint32_t back_link;			//!< the offset to the previous SK record in the hive
	uint32_t references;		//!< Amount of references to this node
	uint32_t descriptor_size;	//!< Size of descriptor in bytes
	char* descriptor;			//!< Descriptor data
}) secure_key_t;

/*! \struct fast_leaf_t
 *	\brief Describes an element stored in fast/hash leaf.
 */
typedef PACK(struct lf_element_t
{
	uint32_t node_offset;		//!< In bytes, relative from the start of the hive bins data
	uint32_t name_hint;			//!< The first 4 ASCII characters of a key name string (used to speed up lookups). If it is a hash leaf than it stores hashes
}) lf_element_t;

/*! \struct fast_leaf_t
 *	\brief A LF (fast leaf) record contains subkeys list with names, hints, hashes and offsets.
 */
typedef PACK(struct fast_leaf_t
{
	int32_t size;				//!< Size of key, which is negative if container in use
	uint16_t signature;			//!< Signature 0x6C66 == "lf"
	uint16_t elements_amount;	//!< Number of stored elements
	lf_element_t* elements;		//!< Array of elements
}) fast_leaf_t;

/*!	\struct reg_path_t
 *	\brief A helper structure that defines a path to embedded named key.
 */
typedef PACK(struct reg_path_t
{
	uint32_t size;			//!< Length of nodes array.
	const char** nodes;		//!< Array of nodes ASCII string names.
	uint32_t* nodes_hints;	//!< Array of 4 first bytes of givent name.
	uint32_t* nodes_hash;	//!< Array of 32-bit hashes for hash leaf traversal.
}) reg_path_t;

/*!	\enum hive_error
 *	\brief Defines errors statuses for hive API.
 */
enum hive_error
{
	hv_success,				//!< Function completed successfully.
	hv_invalid_arg,			//!< Function got an invalid argument (e.g. NULL pointer).
	hv_alloc_error,			//!< Failed allocation inside a function.
	hv_seek_error,			//!< Unable to set cursor to specified offset.
	hv_read_error,			//!< Bad read or unable to read given amount of bytes.
	hv_invalid_signature,	//!< Read signature does not fit specified structure.
	hv_inactive_cell,		//!< Size of cell is more then 0 means that key is inactive.
	hv_no_entity			//!< Key does not exist.
};


/*! \fn int read_hive_header(FILE* hive_ptr, hive_header_t* hive_header_ptr)
 *	\brief Reads hive header structure
 *	\param[in] hive_ptr			pointer to hive file descriptior.
 *	\param[out] hive_header_ptr	pointer to hive_header_t struct that contains output of read hive header.
 *	\return	value of \a hive_error enumeration (0 or \a hv_success on success).
 */
int read_hive_header(FILE* hive_ptr, hive_header_t* hive_header_ptr);

/*! \fn int read_named_key(const uint32_t root_offset, FILE* hive_ptr, named_key_t* nk_ptr)
 *	\brief Reads named key from hive
 *	\param[in] root_offset		32-bit unsigned integer that defines offset to named key structure.
 *	\param[in] hive_ptr			pointer to hive file descriptior.
 *	\param[out] nk_ptr			pointer to named_key_t struct that contains output of read named/node key.
 *	\return	value of \a hive_error enumeration (0 or \a hv_success on success).
 */
int read_named_key(const uint32_t root_offset, FILE* hive_ptr, named_key_t* nk_ptr);

/*! \fn int read_subkey_list(const uint32_t root_offset, FILE* hive_ptr, fast_leaf_t* lf_ptr)
 *	\brief Reads fast/hash leaf
 *	\param[in] root_offset		32-bit unsigned integer that defines offset to fast/hash leaf structure.
 *	\param[in] hive_ptr			pointer to hive file descriptior.
 *	\param[out] lf_ptr			pointer to fast_leaf_t struct that contains output of read fast/hash leaf key.
 *	\return	value of \a hive_error enumeration (0 or \a hv_success on success).
 */
int read_subkey_list(const uint32_t root_offset, FILE* hive_ptr, fast_leaf_t* lf_ptr);

/*! \fn int read_vk_list(const uint32_t root_offset, FILE* hive_ptr, value_list_t* vk_list_ptr)
 *	\brief Reads value key list from hive
 *	\param[in] root_offset		32-bit unsigned integer that defines offset to value list key structure.
 *	\param[in] hive_ptr			pointer to hive file descriptior.
 *	\param[out] vk_list_ptr		pointer to value_list_t struct that contains output of read values list key.
 *	\return	value of \a hive_error enumeration (0 or \a hv_success on success).
 */
int read_vk_list(const uint32_t root_offset, FILE* hive_ptr, value_list_t* vk_list_ptr);

/*! \fn int read_value_key(const uint32_t root_offset, FILE* hive_ptr, value_key_t* vk_ptr)
 *	\brief Reads value key from hive
 *	\param[in] root_offset		32-bit unsigned integer that defines offset to value key structure.
 *	\param[in] hive_ptr			pointer to hive file descriptior.
 *	\param[out] vk_ptr			pointer to value_key_t struct that contains output of read value key.
 *	\return	value of \a hive_error enumeration (0 or \a hv_success on success).
 */
int read_value_key(const uint32_t root_offset, FILE* hive_ptr, value_key_t* vk_ptr);

/*! \fn reg_path_t* reg_make_path(uint32_t depth, ...)
 *	\brief Initializes a path to named/node key using const char* variadic list
 *	\param[in] depth			32-bit unsigned integer that defines depth of specified path to node.
 *	\param[in] ...				variadic list of const char* to every sub-key in the path.
 *	\return	NULL on error or constructed \a reg_path_t* on success giving.
 */
reg_path_t* reg_make_path(uint32_t depth, ...);

/*! \fn int reg_enum_subkey(const named_key_t* base_nk_ptr, const reg_path_t* reg_path_ptr, FILE* hive_ptr, named_key_t* out_nk_ptr)
 *	\brief Enumerates subkey recursivly from given base key
 *	\param[in] base_nk_ptr		const pointer to path root named/node key.
 *	\param[in] reg_path_ptr		const pointer to constructed path by \a reg_make_path
 *	\param[in] hive_ptr			pointer to hive file descriptior.
 *	\param[out] out_nk_ptr		pointer to named_key_t struct that contains output of read enumerated named/node key.
 *	\return	value of \a hive_error enumeration (0 or \a hv_success on success).
 */
int reg_enum_subkey(const named_key_t* base_nk_ptr, const reg_path_t* reg_path_ptr, FILE* hive_ptr, named_key_t* out_nk_ptr);

/*! \fn int reg_enum_value(const named_key_t* base_nk_ptr, const char* value_name, FILE* hive_ptr, value_key_t* out_vk_ptr)
 *	\brief Enumerates specified value key from given named/node key
 *	\param[in] base_nk_ptr		const pointer to path root named/node key.
 *	\param[in] value_name		const pointer to ASCII string of value key name.
 *	\param[in] hive_ptr			pointer to hive file descriptior.
 *	\param[out] out_vk_ptr		pointer to value_key_t struct that contains output of read enumerated value key.
 *	\return	value of \a hive_error enumeration (0 or \a hv_success on success).
 */
int reg_enum_value(const named_key_t* base_nk_ptr, const char* value_name, FILE* hive_ptr, value_key_t* out_vk_ptr);

/*! \fn void* reg_get_value(const value_key_t* vk_ptr, FILE* hive_ptr)
 *	\brief Reads value of specified value key.
 *	\param[in] vk_ptr		const pointer to value key.
 *	\param[in] hive_ptr		pointer to hive file descriptior.
 *	\return	NULL on error or void pointer to read value.
 */
void* reg_get_value(const value_key_t* vk_ptr, FILE* hive_ptr);

/*! \fn char16_t* reg_get_class(named_key_t* nk_ptr, FILE* hive_ptr)
 *	\brief Reads UTF-16 class name of specified named/node key
 *	\param[in] nk_ptr		const pointer to named/node key.
 *	\param[in] hive_ptr		pointer to hive file descriptior.
 *	\return	NULL on error or char16_t pointer (UTF-16) string.
 */
char16_t* reg_get_class(named_key_t* nk_ptr, FILE* hive_ptr);

/*! \fn int hive_file_seek(FILE* hive_ptr, const uint32_t root_offset)
 *	\brief Sets file cursor from beggining to 0x1000 + root_offset
 *	\param[in] hive_ptr		pointer to hive file descriptior.
 *	\param[in] root_offset	32-bit unsigned integer that defines offset to named key structure.
 *	\return	result of fseek function.
 */
int hive_file_seek(FILE* hive_ptr, const uint32_t root_offset);

/*! \fn size_t hive_read_struct(FILE* hive_ptr, void* hive_struct, size_t read_size)
 *	\brief Reads any structure from given file.
 *	\param[in] hive_ptr		pointer to hive file descriptior.
 *	\param[out] hive_struct	void pointer to any hive structure except for header.
 *	\param[in] read_size	amounts of bytes meant to be read.
 *	\return	result of fread function (how many elements were read).
 */
size_t hive_read_struct(FILE* hive_ptr, void* hive_struct, size_t read_size);

/*! \fn int hive_get_root(FILE* hive_ptr, hive_header_t* hive_header_ptr, named_key_t* root_key_ptr)
 *	\brief Reads root named/node key and header of a specified hive file.
 *	\param[in] hive_ptr			pointer to hive file descriptior.
 *	\param[out] hive_header_ptr	pointer to hive_header_t struct that contains output of read hive header.
 *	\param[out] root_key_ptr	pointer to named_key_t struct for root key of specified hive.
 *	\return	value of \a hive_error enumeration (0 or \a hv_success on success).
 */
int hive_get_root(FILE* hive_ptr, hive_header_t* hive_header_ptr, named_key_t* root_key_ptr);

/*! \fn int uint32_t get_name_hash(const char* leaf_name)
 *	\brief Calculates 32-bit hash for hash_leaf structure.
 *	\param[in] leaf_name	ASCII string of named/node key.
 *	\return	hash value of given string or 0 on error.
 */
uint32_t get_name_hash(const char* leaf_name);

#endif

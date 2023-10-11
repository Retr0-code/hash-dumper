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

#ifndef HIVE_H
#define HIVE_H

#include <stdio.h>
#include <errno.h>
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

/*
By default endianness type is little endian, but you can change it to BIG_ENDIAN if this is your case
*/
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

#elif (HV_ENDIANNESS == HV_BIG_ENDIAN)

#define HIVE_SIGN	(uint32_t)0x72656766
#define HBIN_SIGN	(uint32_t)0x6862696E
#define NK_SIGN		(uint16_t)0x6E6B
#define VK_SIGN		(uint16_t)0x766B
#define SK_SIGN		(uint16_t)0x736B
#define LF_SIGN		(uint16_t)0x6C66

#else

#error "Unsupported ENDIANNESS type"

#endif

// By default everything in LE

typedef PACK(struct hive_header_t
{
	uint32_t signature;			// Signature 0x72656766 == "regf
	uint64_t padding1;			// Random padding
	uint64_t last_write_time;	// DOS format
	uint32_t major_ver;			// Regisry major version
	uint32_t minor_ver;			// Regisry minor version
	uint64_t padding2;			// Random padding
	uint32_t root_offset;		// Specifies an relative root's offset of containers
	uint32_t size;				// Amount of hbins in hive
	wchar_t name[255];			// Hive name
}) hive_header_t;


/*
A NK (named key) record contains the information necessary to define a key (and subkeys as well).
*/
typedef PACK(struct named_key_t
{
	int32_t size;				// Size of hbin, which is negative if container in use
	uint16_t signature;			// Signature 0x6E6B == "nk"
	uint16_t flags;				// Binary nk flags
	uint64_t last_write_time;	// DOS format
	uint32_t padding1;			// 0 padding
	uint32_t parent_offset;		// Offset to parent cell if HIVE_ENTRY_ROOT_REG_FLAG is set it points to 0xFFFFFFFF
	uint32_t subkey_amount;		// Stores amount of subkeys only one step deepper
	uint32_t padding2;			// 0 padding
	uint32_t subkey_offset;		// Offset to fast leaf
	uint32_t padding3;			// -1 padding
	uint32_t values_amount;		// Values in current subkey
	uint32_t value_offset;		// Offset to nearest value key
	uint32_t security_offset;	// Offset to security key record
	uint32_t class_name_offset;	// Offset of nodes class name
	uint64_t giant_padding[2];	// Unknown random padding
	int32_t class_length;		// Length of node class name
	int32_t name_length;		// Length of node name
	char* name;					// Name of a key
}) named_key_t;


/*
When the most significant bit is 1, data(4 bytes or less) is stored in
the Data offset field directly(when data contains less than 4 bytes,
it is being stored as is in the beginning of the Data offset field).
The most significant bit(when set to 1) should be ignored when calculating the data size.
*/
typedef PACK(struct value_key_t
{
	int32_t size;				// Size of key, which is negative if container in use
	uint16_t signature;			// Signature 0x766B == "vk"
	uint16_t name_length;		// Value name length if 0 name not set (Default)
	uint32_t data_size;			// Amount of bytes of stored data (if higher bit is set then data is stored in data_offset)
	uint32_t data_offset_val;	// Stores offset to data or the data if size less then or equal to 4
	uint32_t data_type;			// Datatypes defined in Winnt.h (https://learn.microsoft.com/en-us/windows/win32/shell/hkey-type)
	uint16_t flags;				// Binary vk flags
	uint16_t padding;			// Random padding
	char* name;					// Value's name (optional if the length is 0)
}) value_key_t;


typedef PACK(struct value_list_t
{
	int32_t size;				// Size of key, which is negative if container in use
	uint32_t* offsets;			// Offsets to value_key_t structures
}) value_list_t;

/*
A SK (security key) record contains the information
necessary to define access controls for the Registry.
An example of an SK record as it exists on disk is shown below.
*/
typedef PACK(struct secure_key_t
{
	int32_t size;				// Size of key, which is negative if container in use
	uint16_t signature;			// Signature 0x736B == "sk"
	uint16_t padding;			// 0 padding
	uint32_t forward_link;		// the offset to the next SK record in the hive
	uint32_t back_link;			// the offset to the previous SK record in the hive
	uint32_t references;		// Amount of references to this node
	uint32_t descriptor_size;	// Size of descriptor in bytes
	char* descriptor;			// Descriptor data
}) secure_key_t;


/*
Describes an element stored in fast leaf
*/
typedef PACK(struct lf_element_t
{
	uint32_t node_offset;		// In bytes, relative from the start of the hive bins data
	uint32_t name_hint;			// The first 4 ASCII characters of a key name string (used to speed up lookups)
}) lf_element_t;


/*
A LF (fast leaf) record contains subkeys list with name hints and offsets
*/
typedef PACK(struct fast_leaf_t
{
	int32_t size;				// Size of key, which is negative if container in use
	uint16_t signature;			// Signature 0x6C66 == "lf"
	uint16_t elements_amount;	// Number of stored elements
	lf_element_t* elements;		// Array of elements
}) fast_leaf_t;


/*
A helper structure that defines a path to embedded named key
*/
typedef PACK(struct reg_path_t
{
	uint32_t size;
	const char** nodes;
	uint32_t* nodes_hints;
}) reg_path_t;



typedef enum hive_error
{
	hv_success,
	hv_invalid_arg,
	hv_alloc_error,
	hv_seek_error,
	hv_read_error,
	hv_invalid_signature,
	hv_inactive_cell,
	hv_no_entity
};

// Reads hive header structure
int read_hive_header(FILE* hive_ptr, hive_header_t* hive_header_ptr);

// Read named key from hive
int read_named_key(const uint32_t root_offset, FILE* hive_ptr, named_key_t* nk_ptr);

// Read value key list from hive
int read_vk_list(const uint32_t root_offset, FILE* hive_ptr, value_list_t* vk_list_ptr);

// Read value key from hive
int read_value_key(const uint32_t root_offset, FILE* hive_ptr, value_key_t* vk_ptr);

// Initializes a path to named key
reg_path_t* reg_make_path(const uint32_t depth, const char** reg_path);

// Enumerates subkey recursivly from given base key
int reg_enum_subkey(const named_key_t* base_nk_ptr, const reg_path_t* reg_path_ptr, FILE* hive_ptr, named_key_t* out_nk_ptr);

// Enumerates specific value key from named key
int reg_enum_value(const named_key_t* base_nk_ptr, const char* value_name, FILE* hive_ptr, value_key_t* out_vk_ptr);

// Returns value of specified key
void* reg_get_value(const value_key_t* vk_ptr, FILE* hive_ptr);

// Returns class value of specified key
wchar_t* reg_get_class(named_key_t* nk_ptr, FILE* hive_ptr);

// Sets file cursor from beggining to 0x1000 + root_offset
static inline int hive_file_seek(FILE* hive_ptr, const uint32_t root_offset);

// Reads structure from given give
static inline int hive_read_struct(FILE* hive_ptr, void* hive_struct, size_t read_size);

#endif

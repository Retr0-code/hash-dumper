#ifndef HIVE_H
#define HIVE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>


/*
* COMPRESSED_NAME_REG_FLAG - uses ASCII instead of 16bit
* HIVE_ENTRY_ROOT_REG_FLAG - determines the root node of the Registry hive
*/

#define LITTLE_ENDIAN 1
#define BIG_ENDIAN 2


#ifndef ENDIANNESS
	#define ENDIANNESS LITTLE_ENDIAN
#endif

#define COMPRESSED_NAME_REG_FLAG	(uint16_t)0b100000
#define NO_DELETE_REG_FLAG			(uint16_t)0b001000
#define HIVE_ENTRY_ROOT_REG_FLAG	(uint16_t)0b000100
#define HIVE_EXIT_REG_FLAG			(uint16_t)0b000010

#define HIVE_SIGN	(uint32_t)0x72656766
#define NK_SIGN		(uint16_t)0x6E6B
#define VK_SIGN		(uint16_t)0x766B
#define SK_SIGN		(uint16_t)0x736B

// All in LE

typedef struct hive_header_t
{
	uint32_t signature;			// Signature 0x72656766 == "regf
	uint64_t padding1;			// Unknown random padding
	uint64_t last_write_time;	// DOS format
	uint32_t major_ver;
	uint32_t minor_ver;
	uint64_t padding2;			// Unknown random padding
	uint32_t root_offset;		// Specifies an relative root's offset of containers
	uint32_t size;				// Amount of hbins in hive
	wchar_t name[255];			// Hive name
} hive_header_t;

// Base key structure that could be cast down to nk, vk, sk via functions
typedef struct abstract_key_t
{
	int32_t size;				// Size of hbin
	uint16_t signature;			// Signature of key
	char* data;					// Data of this size
} abstract_key_t;

// Have to deal with padding in the end of a record
// ! TODO(Determine what is these paddings are) !
typedef struct named_key_t
{
	int32_t size;				// Size of hbin
	uint16_t signature;			// Signature 0x6E6B == "nk"
	uint16_t flags;				// Binary flags
	uint64_t last_write_time;	// DOS format
	uint32_t padding1;			// Unknown 0 padding
	uint32_t parent_offset;		// Offset to parent cell if HIVE_ENTRY_ROOT_REG_FLAG is set it points to 0xFFFFFFFF
	uint32_t subkey_amount;		// Stores amount of subkeys only one step deepper
	uint32_t padding2;			// Unknown 0 padding
	uint32_t subkey_offset;		// Offset to nearest subkey
	uint32_t padding3;			// Unknown -1 padding
	uint32_t values_amount;		// Values in current subkey
	uint32_t value_offset;		// Offset to nearest value key
	uint32_t security_offset;	// Offset to security key record
	uint32_t class_name_offset;	// Offset of nodes class name
	uint64_t giant_padding[2];	// Unknown random padding
	uint16_t class_length;		// Length of node class name
	uint16_t name_length;		// Length of node name
	char* name;					// Name of a key
} named_key_t;

typedef struct value_key_t
{
	int32_t size;				// Size of hbin
	uint16_t sign;				// Signature 0x766B == "vk"
} value_key_t;

typedef struct secure_key_t
{
	int32_t size;				// Size of hbin
	uint16_t signature;			// Signature 0x736B == "sk"
} secure_key_t;


int read_hive_header(FILE* hive_ptr, hive_header_t* hive_header_ptr);

int read_key(uint64_t offset, uint32_t root_offset, FILE* hive_ptr, abstract_key_t* key);

// Properly converts pointer from base struct to named key
named_key_t* convert_to_nk(abstract_key_t* reg_key);

// Properly converts pointer from base struct to value key
value_key_t* convert_to_vk(abstract_key_t* reg_key);

// Properly converts pointer from base struct to secure key
secure_key_t* convert_to_sk(abstract_key_t* reg_key);


#endif

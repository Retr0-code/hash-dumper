#ifndef HIVE_H
#define HIVE_H

#include <stdlib.h>
#include <stdint.h>


/*
* COMPRESSED_NAME_REG_FLAG - uses ASCII instead of 16bit
* HIVE_ENTRY_ROOT_REG_FLAG - determines the root node of the Registry hive
*/

#define LITTLE_ENDIANNESS 1
#define BIG_ENDIANNESS 2

#define DEFAULT_ENDIANNESS (LITTLE_ENDIANNESS)

#define COMPRESSED_NAME_REG_FLAG	0b100000
#define NO_DELETE_REG_FLAG			0b001000
#define HIVE_ENTRY_ROOT_REG_FLAG	0b000100
#define HIVE_EXIT_REG_FLAG			0b000010

// All in LE
// Have to deal with padding in the end of a record
// ! TODO(Determine what is these paddings are) !
typedef struct named_key_t
{
	int32_t size;				// Size of hbin
	uint16_t sign;				// Signature 0x6E6B == "nk"
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
	const char* name;
};


#endif

#ifndef FUNCTIONAL_H
#define FUNCTIONAL_H

#if defined(__linux__) || defined(__unix__)

#include <byteswap.h>

typedef unsigned long long errno_t;

#define _fseeki64(stream, offset, pos)  fseeko(stream, offset, pos)
#define fgetws(wstr, size, stream)      fgets((char*)wstr, size * 2, stream)

#endif

#endif

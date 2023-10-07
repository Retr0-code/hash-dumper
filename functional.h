#ifndef FUNCTIONAL_H
#define FUNCTIONAL_H

#if defined(__linux__) || defined(__unix__)

#include <wchar.h>
#include <byteswap.h>

typedef unsigned long long errno_t;

#define _fseeki64(stream, offset, pos)  fseeko(stream, offset, pos)
#define fgetws(wstr, size, stream)      fgets((char*)wstr, size * 2, stream)

#define GetLastError() errno

#endif

#endif

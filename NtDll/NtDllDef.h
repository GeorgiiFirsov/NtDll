#pragma once

#include <Windows.h>

// This file contains necessary structs, that are not defined
// in Windows.h and ntdef.h headers to allow definitions of 
// functions to be compiled correctly. Each struct definition 
// is surrounded with '__if_exists' block and compiles if and 
// only if there's no such structure exists

__if_not_exists(PCSZ)
{
    typedef _Null_terminated_ CONST char *PCSZ;
}

__if_not_exists(_UNICODE_STRING)
{
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
    } UNICODE_STRING;
}

__if_not_exists(PUNICODE_STRING)
{
    typedef UNICODE_STRING* PUNICODE_STRING;
}

__if_not_exists(PCUNICODE_STRING)
{
    typedef const UNICODE_STRING* PCUNICODE_STRING;
}

__if_not_exists(_STRING)
{
    typedef struct _STRING {
        USHORT Length;
        USHORT MaximumLength;
        _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
    } STRING;
}

__if_not_exists(PSTRING)
{
    typedef STRING* PSTRING;
}

__if_not_exists(ANSI_STRING)
{
    typedef STRING ANSI_STRING;
}

__if_not_exists(PANSI_STRING)
{
    typedef PSTRING PANSI_STRING;
}

__if_not_exists(OEM_STRING)
{
    typedef STRING OEM_STRING;
}

__if_not_exists(POEM_STRING)
{
    typedef PSTRING POEM_STRING;
}

__if_not_exists(PCOEM_STRING)
{
    typedef CONST STRING* PCOEM_STRING;
}

__if_not_exists(CANSI_STRING)
{
    typedef STRING CANSI_STRING;
}

__if_not_exists(PCANSI_STRING)
{
    typedef PSTRING PCANSI_STRING;
}

__if_not_exists(_RTL_BUFFER)
{
    typedef struct _RTL_BUFFER {
        PUCHAR    Buffer;
        PUCHAR    StaticBuffer;
        SIZE_T    Size;
        SIZE_T    StaticSize;
        SIZE_T    ReservedForAllocatedSize;
        PVOID     ReservedForIMalloc;
    } RTL_BUFFER, * PRTL_BUFFER;
}

__if_not_exists(_RTL_UNICODE_STRING_BUFFER)
{
    typedef struct _RTL_UNICODE_STRING_BUFFER {
        UNICODE_STRING String;
        RTL_BUFFER     ByteBuffer;
        UCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
    } RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;
}
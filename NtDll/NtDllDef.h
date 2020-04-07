#pragma once

#include <Windows.h>

// This file contains necessary structs, that are not defined
// in Windows.h and ntdef.h headers to allow definitions of 
// functions to be compiled correctly. Each struct definition 
// is surrounded with '__if_not_exists' block and compiles if and 
// only if there's no such structure exists

__if_not_exists(_RTL_HANDLE)
{
    typedef struct _RTL_HANDLE {
        struct _RTL_HANDLE* Next;
    } RTL_HANDLE, * PRTL_HANDLE;
};

__if_not_exists(_RTL_HANDLE_TABLE)
{
    typedef struct _RTL_HANDLE_TABLE {
        ULONG MaxHandleCount;
        ULONG HandleSize;
        ULONG Unused[2];
        PCHAR NextFree;
        PCHAR FirstHandle;
        PCHAR ReservedMemory;
        PCHAR MaxHandle;
    } RTL_HANDLE_TABLE, * PRTL_HANDLE_TABLE;
};

__if_not_exists(_RTL_BITMAP)
{
    typedef struct _RTL_BITMAP {
        ULONG SizeOfBitMap;
        ULONG* Buffer;
    } RTL_BITMAP, * PRTL_BITMAP;
}

__if_not_exists(_RTL_RXACT_LOG)
{
    typedef struct _RTL_RXACT_LOG {
        ULONG OperationCount;
        ULONG LogSize;
        ULONG LogSizeInUse;
#if defined(_WIN64)
        ULONG Alignment;
#endif
    } RTL_RXACT_LOG, * PRTL_RXACT_LOG;
};

__if_not_exists(_RTL_RXACT_CONTEXT)
{
    typedef struct _RTL_RXACT_CONTEXT {
        HANDLE         RootRegistryKey;
        HANDLE         RXactKey;
        BOOLEAN        HandlesValid;
        PRTL_RXACT_LOG RXactLog;
    } RTL_RXACT_CONTEXT, * PRTL_RXACT_CONTEXT;
};

__if_not_exists(_RTL_RXACT_OPERATION)
{
    typedef enum _RTL_RXACT_OPERATION {
        RtlRXactOperationDelete = 1,
        RtlRXactOperationSetValue,
        RtlRXactOperationDelAttribute,
        RtlRXactOperationSetAttribute
    } RTL_RXACT_OPERATION, * PRTL_RXACT_OPERATION;
};

__if_not_exists(_RTL_SRWLOCK)
{
    typedef struct _RTL_SRWLOCK {
        PVOID Ptr;
    } SRWLOCK_, * PSRWLOCK_;
};

__if_not_exists(_RTL_CRITICAL_SECTION)
{
    typedef struct _RTL_CRITICAL_SECTION {
        PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
        LONG                        LockCount;
        LONG                        RecursionCount;
        PVOID                       OwningThread;
        PVOID                       LockSemaphore;
        ULONG                       SpinCount;
    } RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;
};

__if_not_exists(_RTL_RESOURCE)
{
    typedef struct _RTL_RESOURCE {
        RTL_CRITICAL_SECTION Lock;
        HANDLE               SharedSemaphore;
        ULONG                SharedWaiters;
        HANDLE               ExclusiveSemaphore;
        ULONG                ExclusiveWaiters;
        LONG                 NumberActive;
        HANDLE               OwningThread;
        ULONG                TimeoutBoost;
        PVOID                DebugInfo;
    } RTL_RESOURCE, * PRTL_RESOURCE;
};

__if_not_exists(_LIST_ENTRY)
{
    typedef struct _LIST_ENTRY
    {
        PLIST_ENTRY Flink;
        PLIST_ENTRY Blink;
    } LIST_ENTRY, * PLIST_ENTRY;
};

__if_not_exists(_RTL_RANGE_LIST)
{
    typedef struct _RTL_RANGE_LIST
    {
        LIST_ENTRY ListHead;
        ULONG      Flags;
        ULONG      Count;
        ULONG      Stamp;
    } RTL_RANGE_LIST, * PRTL_RANGE_LIST;
}

__if_not_exists(PCSZ)
{
    typedef _Null_terminated_ CONST char *PCSZ;
};

__if_not_exists(_UNICODE_STRING)
{
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
#ifdef MIDL_PASS
        [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
        _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
    } UNICODE_STRING;
};

__if_not_exists(PUNICODE_STRING)
{
    typedef UNICODE_STRING* PUNICODE_STRING;
};

__if_not_exists(PCUNICODE_STRING)
{
    typedef const UNICODE_STRING* PCUNICODE_STRING;
};

__if_not_exists(_STRING)
{
    typedef struct _STRING {
        USHORT Length;
        USHORT MaximumLength;
#ifdef MIDL_PASS
        [size_is(MaximumLength), length_is(Length)]
#endif // MIDL_PASS
        _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
    } STRING;
};

__if_not_exists(PSTRING)
{
    typedef STRING* PSTRING;
};

__if_not_exists(ANSI_STRING)
{
    typedef STRING ANSI_STRING;
};

__if_not_exists(PANSI_STRING)
{
    typedef PSTRING PANSI_STRING;
};

__if_not_exists(OEM_STRING)
{
    typedef STRING OEM_STRING;
};

__if_not_exists(POEM_STRING)
{
    typedef PSTRING POEM_STRING;
};

__if_not_exists(PCOEM_STRING)
{
    typedef CONST STRING* PCOEM_STRING;
};

__if_not_exists(CANSI_STRING)
{
    typedef STRING CANSI_STRING;
};

__if_not_exists(PCANSI_STRING)
{
    typedef PSTRING PCANSI_STRING;
};

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
};

__if_not_exists(_RTL_UNICODE_STRING_BUFFER)
{
    typedef struct _RTL_UNICODE_STRING_BUFFER {
        UNICODE_STRING String;
        RTL_BUFFER     ByteBuffer;
        UCHAR          MinimumStaticBufferForTerminalNul[sizeof( WCHAR )];
    } RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;
};

__if_not_exists(_LARGE_INTEGER)
{
#if defined(MIDL_PASS)
    typedef struct _LARGE_INTEGER {
#else // MIDL_PASS
    typedef union _LARGE_INTEGER {
        struct {
            ULONG LowPart;
            LONG HighPart;
        } DUMMYSTRUCTNAME;

        struct {
            ULONG LowPart;
            LONG HighPart;
        } u;
#endif //MIDL_PASS
        LONGLONG QuadPart;
    } LARGE_INTEGER;
};

__if_not_exists(PHYSICAL_ADDRESS)
{
    typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;
}

__if_not_exists(KAFFINITY)
{
    typedef ULONG_PTR KAFFINITY;
};

__if_not_exists(_CM_PARTIAL_RESOURCE_DESCRIPTOR)
{
    typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
        UCHAR  Type;
        UCHAR  ShareDisposition;
        USHORT Flags;

        union {
            struct {
                PHYSICAL_ADDRESS Start;
                ULONG            Length;
            } Generic;

            struct {
                PHYSICAL_ADDRESS Start;
                ULONG            Length;
            } Port;

            struct {
                ULONG     Level;
                ULONG     Vector;
                KAFFINITY Affinity;
            } Interrupt;

            struct {
                union {
                    struct {
                        USHORT    Group;
                        USHORT    Reserved;
                        USHORT    MessageCount;
                        ULONG     Vector;
                        KAFFINITY Affinity;
                    } Raw;

                    struct {
                        ULONG     Level;
                        ULONG     Vector;
                        KAFFINITY Affinity;
                    } Translated;
                } DUMMYUNIONNAME;
            } MessageInterrupt;

            struct {
                PHYSICAL_ADDRESS Start;
                ULONG            Length;
            } Memory;

            struct {
                ULONG Channel;
                ULONG Port;
                ULONG Reserved1;
            } Dma;

            struct {
                ULONG Channel;
                ULONG RequestLine;
                UCHAR TransferWidth;
                UCHAR Reserved1;
                UCHAR Reserved2;
                UCHAR Reserved3;
            } DmaV3;

            struct {
                ULONG Data[3];
            } DevicePrivate;

            struct {
                ULONG Start;
                ULONG Length;
                ULONG Reserved;
            } BusNumber;

            struct {
                ULONG DataSize;
                ULONG Reserved1;
                ULONG Reserved2;
            } DeviceSpecificData;

            struct {
                PHYSICAL_ADDRESS Start;
                ULONG            Length40;
            } Memory40;

            struct {
                PHYSICAL_ADDRESS Start;
                ULONG            Length48;
            } Memory48;

            struct {
                PHYSICAL_ADDRESS Start;
                ULONG            Length64;
            } Memory64;

            struct {
                UCHAR Class;
                UCHAR Type;
                UCHAR Reserved1;
                UCHAR Reserved2;
                ULONG IdLowPart;
                ULONG IdHighPart;
            } Connection;

        } u;
    } CM_PARTIAL_RESOURCE_DESCRIPTOR, * PCM_PARTIAL_RESOURCE_DESCRIPTOR;
};
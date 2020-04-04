#pragma once

// Windows header files
#include "Windows.h"

// Library includes
#include "NtDllError.h"
#include "Utils.h"

// Macro used to declare an NtDll member. It expands into a type alias declaration
// for function type with the name 'PFunctionName', where 'FunctionName' is a name
// of the function to be declared. Macro makes a static class function declaration
// without trailing ';' to allow instant definition.
#define NT_DLL_FUNCTION( Type, Call, Name, ... /* Args */ )                      \
    using CONCATENATE( P, Name ) = Type (Call *) ( __VA_ARGS__ );                \
    static Type Call Name( __VA_ARGS__ ) 

// Macro used to easily load dll-function from NtDll.dll. Ite receives a function name,
// but it must not be a string, it will be stringified as soon as needed by preprocessor!
// This marco expands into a definition of static handle of NtDll.dll and definition of
// static pointer to function, that is loaded from NtDll.dll. It also provides some
// error checks, that must throw an error on failure.
#define LOAD_FUNCTION( Name )                                                    \
    static HMODULE hNtDll = GetModuleHandle( TEXT( "ntdll.dll" ) );              \
    static DWORD dwError = GetLastError();                                       \
    if (!hNtDll) {                                                               \
        exception::ThrowError( dwError, CURRENT_LOCATION );                      \
    }                                                                            \
    static CONCATENATE( P, Name ) CONCATENATE( pfn, Name )                       \
        = reinterpret_cast< CONCATENATE( P, Name ) >(                            \
            GetProcAddress( hNtDll, #Name )                                      \
    );                                                                           \
    if (! CONCATENATE( pfn, Name )) {                                            \
        exception::ThrowError( ERROR_CALL_NOT_IMPLEMENTED, CURRENT_LOCATION );   \
    }

namespace nt_dll {

    // Main class of this library. It contains various functions, defined and
    // implemented in NtDll.dll from Windows. Each function is a static member
    // function and can be called without creating an object of this class.
    // A link to documentation is provided for each documented function.
    class NtDll
    {
    public:
        // ---------------------------------------------------------------------------------------------------------
        //                                           Public functions
        // ---------------------------------------------------------------------------------------------------------

        // None implemented yet

        // ---------------------------------------------------------------------------------------------------------
        //                                            Rtl functions
        // ---------------------------------------------------------------------------------------------------------

        // *********************************************************************************************************
        // RtlAbsoluteToSelfRelativeSD
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlabsolutetoselfrelativesd
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAbsoluteToSelfRelativeSD,
            _In_    PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
            _In_    PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
            _Inout_ PULONG               BufferLength
        )
        {
            LOAD_FUNCTION( RtlAbsoluteToSelfRelativeSD );
            return pfnRtlAbsoluteToSelfRelativeSD( AbsoluteSecurityDescriptor, SelfRelativeSecurityDescriptor, BufferLength );
        }

        // *********************************************************************************************************
        // RtlAcquirePrivilege
        // Undocumented
        // 

        NT_DLL_FUNCTION( 
            NTSTATUS, NTAPI, RtlAcquirePrivilege,
            _In_  PULONG Privilege,
            _In_  ULONG  NumPriv,
            _In_  ULONG  Flags,
            _Out_ PVOID* ReturnedState
        )
        {
            LOAD_FUNCTION( RtlAcquirePrivilege );
            return pfnRtlAcquirePrivilege( Privilege, NumPriv, Flags, ReturnedState );
        }

        // *********************************************************************************************************
        // RtlAddAccessAllowedAce
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedace
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAccessAllowedAce,
            _Inout_ PACL        Acl,
            _In_    ULONG       AceRevision,
            _In_    ACCESS_MASK AccessMask,
            _In_    PSID        Sid
        )
        {
            LOAD_FUNCTION( RtlAddAccessAllowedAce );
            return pfnRtlAddAccessAllowedAce( Acl, AceRevision, AccessMask, Sid );
        }

        // *********************************************************************************************************
        // RtlAddAccessAllowedAceEx
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedaceex
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAccessAllowedAceEx,
            _Inout_ PACL        Acl,
            _In_    ULONG       AceRevision,
            _In_    ULONG       AceFlags,
            _In_    ACCESS_MASK AccessMask,
            _In_    PSID        Sid
        )
        {
            LOAD_FUNCTION( RtlAddAccessAllowedAceEx );
            return pfnRtlAddAccessAllowedAceEx( Acl, AceRevision, AceFlags, AccessMask, Sid );
        }

        // *********************************************************************************************************
        // RtlAddAccessAllowedObjectAce
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAccessAllowedObjectAce,
            _Inout_  PACL        Acl,
            _In_     ULONG       AceRevision,
            _In_     ULONG       AceFlags,
            _In_     ACCESS_MASK AccessMask,
            _In_opt_ GUID*       ObjectTypeGuid,
            _In_opt_ GUID*       InheritedObjectTypeGuid,
            _In_     PSID        Sid
        )
        {
            LOAD_FUNCTION( RtlAddAccessAllowedObjectAce );
            return pfnRtlAddAccessAllowedObjectAce( Acl, AceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, Sid );
        }

        // *********************************************************************************************************
        // RtlAddAccessDeniedAce
        // Undocumented (!)
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAccessDeniedAce,
            _Inout_ PACL        Acl,
            _In_    ULONG       AceRevision,
            _In_    ACCESS_MASK AccessMask,
            _In_    PSID        Sid
        )
        {
            LOAD_FUNCTION( RtlAddAccessDeniedAce );
            return pfnRtlAddAccessDeniedAce( Acl, AceRevision, AccessMask, Sid );
        }

        // *********************************************************************************************************
        // RtlAddAccessDeniedAceEx
        // Undocumented (!)
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAccessDeniedAceEx,
            _Inout_ PACL        Acl,
            _In_    ULONG       AceRevision,
            _In_    ULONG       AceFlags,
            _In_    ACCESS_MASK AccessMask,
            _In_    PSID        Sid
        )
        {
            LOAD_FUNCTION( RtlAddAccessDeniedAceEx );
            return pfnRtlAddAccessDeniedAceEx( Acl, AceRevision, AceFlags, AccessMask, Sid );
        }

        // *********************************************************************************************************
        // RtlAddAccessDeniedObjectAce 
        // Undocumented
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAccessDeniedObjectAce,
            _Inout_  PACL        Acl,
            _In_     ULONG       AceRevision,
            _In_     ULONG       AceFlags,
            _In_     ACCESS_MASK AccessMask,
            _In_opt_ GUID*       ObjectTypeGuid,
            _In_opt_ GUID*       InheritedObjectTypeGuid,
            _In_     PSID        Sid
        )
        {
            LOAD_FUNCTION( RtlAddAccessDeniedObjectAce );
            return pfnRtlAddAccessDeniedObjectAce( Acl, AceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, Sid );
        }

        // *********************************************************************************************************
        // RtlAddAce
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdace
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAce,
            _Inout_ PACL  Acl,
            _In_    ULONG AceRevision,
            _In_    ULONG StartingAceIndex,
            _In_    PVOID AceList,
            _In_    ULONG AceListLength
        )
        {
            LOAD_FUNCTION( RtlAddAce );
            return pfnRtlAddAce( Acl, AceRevision, StartingAceIndex, AceList, AceListLength );
        }

        // *********************************************************************************************************
        // RtlAddAuditAccessAce
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAuditAccessAce,
            _Inout_ PACL        Acl,
            _In_    ULONG       AceRevision,
            _In_    ACCESS_MASK AccessMask,
            _In_    PSID        Sid,
            _In_    BOOLEAN     AuditSuccess,
            _In_    BOOLEAN     AuditFailure
        )
        {
            LOAD_FUNCTION( RtlAddAuditAccessAce );
            return pfnRtlAddAuditAccessAce( Acl, AceRevision, AccessMask, Sid, AuditSuccess, AuditFailure );
        }

        // *********************************************************************************************************
        // RtlAddAuditAccessAceEx
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAuditAccessAceEx,
            _Inout_ PACL        Acl,
            _In_    ULONG       AceRevision,
            _In_    ULONG       AceFlags,
            _In_    ACCESS_MASK AccessMask,
            _In_    PSID        Sid,
            _In_    BOOLEAN     AuditSuccess,
            _In_    BOOLEAN     AuditFailure
        )
        {
            LOAD_FUNCTION( RtlAddAuditAccessAceEx );
            return pfnRtlAddAuditAccessAceEx( Acl, AceRevision, AceFlags, AccessMask, Sid, AuditSuccess, AuditFailure );
        }

        // *********************************************************************************************************
        // RtlAddAuditAccessObjectAce
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAuditAccessObjectAce,
            _Inout_  PACL        Acl,
            _In_     ULONG       AceRevision,
            _In_     ULONG       AceFlags,
            _In_     ACCESS_MASK AccessMask,
            _In_opt_ GUID*       ObjectTypeGuid,
            _In_opt_ GUID*       InheritedObjectTypeGuid,
            _In_     PSID        Sid,
            _In_     BOOLEAN     AuditSuccess,
            _In_     BOOLEAN     AuditFailure
        )
        {
            LOAD_FUNCTION( RtlAddAuditAccessObjectAce );
            return pfnRtlAddAuditAccessObjectAce( 
                Acl, AceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, Sid, AuditSuccess, AuditFailure 
            );
        }

        // *********************************************************************************************************
        // RtlAddCompoundAce
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddCompoundAce,
            _In_ PACL        Acl,
            _In_ ULONG       AceRevision,
            _In_ UCHAR       CompoundAceType,
            _In_ ACCESS_MASK AccessMask,
            _In_ PSID        ServerSid,
            _In_ PSID        ClientSid
        )
        {
            LOAD_FUNCTION( RtlAddCompoundAce );
            return pfnRtlAddCompoundAce( Acl, AceRevision, CompoundAceType, AccessMask, ServerSid, ClientSid );
        }

        // *********************************************************************************************************
        // RtlAddFunctionTable
        // https://docs.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable
        // 

        NT_DLL_FUNCTION(
            BOOLEAN, NTAPI, RtlAddFunctionTable,
            _In_ PRUNTIME_FUNCTION FunctionTable,
            _In_ DWORD             EntryCount,
            _In_ DWORD64           BaseAddress
        )
        {
            LOAD_FUNCTION( RtlAddFunctionTable );
            return pfnRtlAddFunctionTable( FunctionTable, EntryCount, BaseAddress );
        }

        // *********************************************************************************************************
        // RtlAddGrowableFunctionTable
        // https://docs.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdgrowablefunctiontable
        // 

        NT_DLL_FUNCTION(
            DWORD, NTAPI, RtlAddGrowableFunctionTable,
            _Out_ PVOID*            DynamicTable,
            _In_  PRUNTIME_FUNCTION FunctionTable,
            _In_  DWORD             EntryCount,
            _In_  DWORD             MaximumEntryCount,
            _In_  ULONG_PTR         RangeBase,
            _In_  ULONG_PTR         RangeEnd
        )
        {
            LOAD_FUNCTION( RtlAddGrowableFunctionTable );
            return pfnRtlAddGrowableFunctionTable( DynamicTable, FunctionTable, EntryCount, MaximumEntryCount, RangeBase, RangeEnd );
        }

        // *********************************************************************************************************
        // RtlComputeCrc32
        // Undocumented
        //

        NT_DLL_FUNCTION(
            DWORD, WINAPI, RtlComputeCrc32,
            _In_ DWORD       dwInitial, 
            _In_ CONST BYTE* pbData, 
            _In_ INT         iLen 
        )
        {
            LOAD_FUNCTION( RtlComputeCrc32 );
            return pfnRtlComputeCrc32( dwInitial, pbData, iLen );
        }

        // ---------------------------------------------------------------------------------------------------------
        //                                            Nt functions
        // ---------------------------------------------------------------------------------------------------------

        // None implemented yet

        // ---------------------------------------------------------------------------------------------------------
        //                                            Zw functions
        // ---------------------------------------------------------------------------------------------------------
        
        // None implemented yet
    };
} // namespace nt_dll
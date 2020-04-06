#pragma once

// Windows header files
#include <Windows.h>

// STL headers
#include <string>
#include <type_traits>

// Library includes
#include "NtDllDef.h"
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

        // This function template can be used in case if you need to call
        // a function that is not implemented in this library yet. To use it
        // you need to specify the type of function you want to call explicitly
        // as an template parameter and pass the name of a function as the first
        // argument. Other arguments will be forwarded to callable via perfect
        // forwarding. Return type will be deduced automatically.
        template<typename FuncPtr, typename... Args> 
        static typename utils::result_type_of<FuncPtr, Args...>::type 
        CallSpecific( const std::string& sFunctionName, Args&&... args )
        {
            //
            // Fistly we need to check if passed type is a pointer and
            // in case of failure we'll print readable message.
            // 

            static_assert( 
                std::is_pointer<FuncPtr>::value, 
                "FuncPtr in " __FUNCTION__ " must be pointer-to-function type" 
            );

            //
            // Maybe this function will be called more than one time, so
            // I'll load dynamic library once.
            // 

            static HMODULE hNtDll = GetModuleHandle( TEXT( "ntdll.dll" ) );
            static DWORD dwError = GetLastError();
            
            if (!hNtDll) {
                exception::ThrowError( dwError, CURRENT_LOCATION );
            }

            //
            // Searching for function in library. If none exists I'll
            // throw an exception, otherwise call will be performed.
            // 

            auto pfnCallable = reinterpret_cast<FuncPtr>(
                GetProcAddress( hNtDll, sFunctionName.c_str() )    
            );

            if (!pfnCallable) {
                exception::ThrowError( ERROR_NOT_FOUND, CURRENT_LOCATION );
            }

            return pfnCallable( std::forward<Args>( args )... );
        }

        // ---------------------------------------------------------------------------------------------------------
        //                                           Public functions
        // ---------------------------------------------------------------------------------------------------------

#pragma region Public functions

        // None implemented yet

#pragma endregion

        // ---------------------------------------------------------------------------------------------------------
        //                                            Rtl functions
        // ---------------------------------------------------------------------------------------------------------

#pragma region Rtl functions

        // *********************************************************************************************************
        // RtlAbortRXact
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAbortRXact,
            _In_ PRTL_RXACT_CONTEXT RXactContext
        )
        {
            LOAD_FUNCTION( RtlAbortRXact );
            return pfnRtlAbortRXact( RXactContext );
        }

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
        // RtlAcquirePebLock
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            VOID, NTAPI, RtlAcquirePebLock
        )
        {
            LOAD_FUNCTION( RtlAcquirePebLock );
            return pfnRtlAcquirePebLock();
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
        // RtlAcquireReleaseSRWLockExclusive
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            VOID, NTAPI, RtlAcquireReleaseSRWLockExclusive,
            _In_ PRTL_SRWLOCK SRWLock
        )
        {
            LOAD_FUNCTION( RtlAcquireReleaseSRWLockExclusive );
            return pfnRtlAcquireReleaseSRWLockExclusive( SRWLock );
        }

        // *********************************************************************************************************
        // RtlAcquireResourceExclusive
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            BOOLEAN, NTAPI, RtlAcquireResourceExclusive,
            _In_ PRTL_RESOURCE Resource,
            _In_ BOOLEAN       Wait
        )
        {
            LOAD_FUNCTION( RtlAcquireResourceExclusive );
            return pfnRtlAcquireResourceExclusive( Resource, Wait );
        }

        // *********************************************************************************************************
        // RtlAcquireResourceShared
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            BOOLEAN, NTAPI, RtlAcquireResourceShared,
            _In_ PRTL_RESOURCE Resource,
            _In_ BOOLEAN       Wait
        )
        {
            LOAD_FUNCTION( RtlAcquireResourceShared );
            return pfnRtlAcquireResourceShared( Resource, Wait );
        }

        // *********************************************************************************************************
        // RtlAcquireSRWLockExclusive
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            VOID, NTAPI, RtlAcquireSRWLockExclusive,
            _In_ PRTL_SRWLOCK SRWLock
        )
        {
            LOAD_FUNCTION( RtlAcquireSRWLockExclusive );
            return pfnRtlAcquireSRWLockExclusive( SRWLock );
        }

        // *********************************************************************************************************
        // RtlAcquireSRWLockShared
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            VOID, NTAPI, RtlAcquireSRWLockShared,
            _In_ PRTL_SRWLOCK SRWLock
        )
        {
            LOAD_FUNCTION( RtlAcquireSRWLockShared );
            return pfnRtlAcquireSRWLockShared( SRWLock );
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
        // RtlAddActionToRXact
        // Undocumented
        // 
        
        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddActionToRXact,
            _In_     PRTL_RXACT_CONTEXT  RXactContext,
            _In_     RTL_RXACT_OPERATION Operation,
            _In_     PUNICODE_STRING     SubKeyName,
            _In_     ULONG               NewKeyValueType,
            _In_opt_ PVOID               NewKeyValue,
            _In_     ULONG               NewKeyValueLength
        )
        {
            LOAD_FUNCTION( RtlAddActionToRXact );
            return pfnRtlAddActionToRXact( RXactContext, Operation, SubKeyName, NewKeyValueType, NewKeyValue, NewKeyValueLength );
        }

        // *********************************************************************************************************
        // RtlAddAttributeActionToRXact
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddAttributeActionToRXact,
            _In_ PRTL_RXACT_CONTEXT  RXactContext,
            _In_ RTL_RXACT_OPERATION Operation,
            _In_ PUNICODE_STRING     SubKeyName,
            _In_ HANDLE              KeyHandle,
            _In_ PUNICODE_STRING     AttributeName,
            _In_ ULONG               NewValueType,
            _In_ PVOID               NewValue,
            _In_ ULONG               NewValueLength
        )
        {
            LOAD_FUNCTION( RtlAddAttributeActionToRXact );
            return pfnRtlAddAttributeActionToRXact( 
                RXactContext, Operation, SubKeyName, KeyHandle, AttributeName, NewValueType, NewValue, NewValueLength 
            );
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
        // RtlAddIntegrityLabelToBoundaryDescriptor
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddIntegrityLabelToBoundaryDescriptor,
            _Inout_ PVOID* BoundaryDescriptor,
            _In_    PSID   IntegrityLabel
        )
        {
            LOAD_FUNCTION( RtlAddIntegrityLabelToBoundaryDescriptor );
            return pfnRtlAddIntegrityLabelToBoundaryDescriptor( BoundaryDescriptor, IntegrityLabel );
        }

        // *********************************************************************************************************
        // RtlAddMandatoryAce
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, WINAPI, RtlAddMandatoryAce,
            _Inout_ PACL  pAcl,
            _In_    DWORD dwAceRevision,
            _In_    DWORD dwAceFlags,
            _In_    DWORD dwMandatoryFlags,
            _In_    DWORD dwAceType,
            _In_    PSID  pSid
        )
        {
            LOAD_FUNCTION( RtlAddMandatoryAce );
            return pfnRtlAddMandatoryAce( pAcl, dwAceRevision, dwAceFlags, dwMandatoryFlags, dwAceType, pSid );
        }

        // *********************************************************************************************************
        // RtlAddRange
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddRange, 
            _Inout_  PRTL_RANGE_LIST RangeList,
            _In_     ULONGLONG       Start,
            _In_     ULONGLONG       End,
            _In_     UCHAR           Attributes,
            _In_     ULONG           Flags,
            _In_opt_ PVOID           UserData,
            _In_opt_ PVOID           Owner
        )
        {
            LOAD_FUNCTION( RtlAddRange );
            return pfnRtlAddRange( RangeList, Start, End, Attributes, Flags, UserData, Owner );
        }

        // *********************************************************************************************************
        // RtlAddRefMemoryStream
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            ULONG, NTAPI, RtlAddRefMemoryStream,
            _In_ IStream* Stream
        )
        {
            LOAD_FUNCTION( RtlAddRefMemoryStream );
            return pfnRtlAddRefMemoryStream( Stream );
        }

        // *********************************************************************************************************
        // RtlAddSIDToBoundaryDescriptor
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAddSIDToBoundaryDescriptor,
            _Inout_ PVOID* BoundaryDescriptor,
            _In_    PSID   RequiredSid
        )
        {
            LOAD_FUNCTION( RtlAddSIDToBoundaryDescriptor );
            return pfnRtlAddSIDToBoundaryDescriptor( BoundaryDescriptor, RequiredSid );
        }

        // *********************************************************************************************************
        // RtlAddVectoredContinueHandler
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            PVOID, NTAPI, RtlAddVectoredContinueHandler,
            _In_ ULONG                       FirstHandler,
            _In_ PVECTORED_EXCEPTION_HANDLER VectoredHandler
        )
        {
            LOAD_FUNCTION( RtlAddVectoredContinueHandler );
            return pfnRtlAddVectoredContinueHandler( FirstHandler, VectoredHandler );
        }

        // *********************************************************************************************************
        // RtlAddVectoredExceptionHandler
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            PVOID, NTAPI, RtlAddVectoredExceptionHandler,
            _In_ ULONG                       FirstHandler,
            _In_ PVECTORED_EXCEPTION_HANDLER VectoredHandler
        )
        {
            LOAD_FUNCTION( RtlAddVectoredExceptionHandler );
            return pfnRtlAddVectoredExceptionHandler( FirstHandler, VectoredHandler );
        }

        // *********************************************************************************************************
        // RtlAddressInSectionTable 
        // Undocumented
        // 

        NT_DLL_FUNCTION(
            PVOID, NTAPI, RtlAddressInSectionTable,
            _In_ PIMAGE_NT_HEADERS NtHeaders,
            _In_ PVOID             Base,
            _In_ ULONG             Address
        )
        {
            LOAD_FUNCTION( RtlAddressInSectionTable );
            return pfnRtlAddressInSectionTable( NtHeaders, Base, Address );
        }

        // *********************************************************************************************************
        // RtlAdjustPrivilege 
        // Undocumented
        // 
        
        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAdjustPrivilege,
            _In_  ULONG    Privilege,
            _In_  BOOLEAN  Enable,
            _In_  BOOLEAN  CurrentThread,
            _Out_ PBOOLEAN Enabled
        )
        {
            LOAD_FUNCTION( RtlAdjustPrivilege );
            return pfnRtlAdjustPrivilege( Privilege, Enable, CurrentThread, Enabled );
        }

        // *********************************************************************************************************
        // RtlAllocateAndInitializeSid 
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateandinitializesid
        // 
        
        NT_DLL_FUNCTION(
            _Must_inspect_result_ 
            NTSTATUS, NTAPI, RtlAllocateAndInitializeSid,
            _In_     PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
            _In_     UCHAR                     SubAuthorityCount,
            _In_     ULONG                     SubAuthority0,
            _In_     ULONG                     SubAuthority1,
            _In_     ULONG                     SubAuthority2,
            _In_     ULONG                     SubAuthority3,
            _In_     ULONG                     SubAuthority4,
            _In_     ULONG                     SubAuthority5,
            _In_     ULONG                     SubAuthority6,
            _In_     ULONG                     SubAuthority7,
            _Outptr_ PSID*                     Sid
        )
        {
            LOAD_FUNCTION( RtlAllocateAndInitializeSid );
            return pfnRtlAllocateAndInitializeSid( 
                IdentifierAuthority, SubAuthorityCount, 
                SubAuthority0, SubAuthority1, SubAuthority2, 
                SubAuthority3, SubAuthority4, SubAuthority5, 
                SubAuthority6, SubAuthority7, Sid 
            );
        }

        // *********************************************************************************************************
        // RtlAllocateAndInitializeSidEx 
        // Undocumented
        // 
        
        NT_DLL_FUNCTION(
            _Must_inspect_result_
            NTSTATUS, NTAPI, RtlAllocateAndInitializeSidEx,
            _In_                          PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
            _In_                          UCHAR                     SubAuthorityCount,
            _In_reads_(SubAuthorityCount) PULONG                    SubAuthorities,
            _Outptr_                      PSID*                     Sid
        )
        {
            LOAD_FUNCTION( RtlAllocateAndInitializeSidEx );
            return pfnRtlAllocateAndInitializeSidEx( IdentifierAuthority, SubAuthorityCount, SubAuthorities, Sid );
        }

        // *********************************************************************************************************
        // RtlAllocateHeap 
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateheap
        // 

        NT_DLL_FUNCTION(
            PVOID, NTAPI, RtlAllocateHeap,
            _In_ PVOID  HeapHandle,
            _In_ ULONG  Flags,
            _In_ SIZE_T Size
        )
        {
            LOAD_FUNCTION( RtlAllocateHeap );
            return pfnRtlAllocateHeap( HeapHandle, Flags, Size );
        }

        // *********************************************************************************************************
        // RtlAllocateMemoryBlockLookaside
        // Undocumented
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAllocateMemoryBlockLookaside,
            _In_     PVOID  MemoryBlockLookaside,
            _In_     ULONG  BlockSize,
            _Outptr_ PVOID* Block
        )
        {
            LOAD_FUNCTION( RtlAllocateMemoryBlockLookaside );
            return pfnRtlAllocateMemoryBlockLookaside( MemoryBlockLookaside, BlockSize, Block );
        }

        // *********************************************************************************************************
        // RtlAllocateMemoryZone
        // Undocumented
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAllocateMemoryZone,
            _In_     PVOID  MemoryZone,
            _In_     SIZE_T BlockSize,
            _Outptr_ PVOID* Block
        )
        {
            LOAD_FUNCTION( RtlAllocateMemoryZone );
            return pfnRtlAllocateMemoryZone( MemoryZone, BlockSize, Block );
        }

        // *********************************************************************************************************
        // RtlAnsiCharToUnicodeChar
        // https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff561132(v%3Dvs.85)
        //

        NT_DLL_FUNCTION(
            WCHAR, NTAPI, RtlAnsiCharToUnicodeChar,
            _Inout_ PUCHAR* SourceCharacter
        )
        {
            LOAD_FUNCTION( RtlAnsiCharToUnicodeChar );
            return pfnRtlAnsiCharToUnicodeChar( SourceCharacter );
        }

        // *********************************************************************************************************
        // RtlAnsiStringToUnicodeString
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodestring
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAnsiStringToUnicodeString,
            _Out_ PUNICODE_STRING DestinationString,
            _In_  PCANSI_STRING   SourceString,
            _In_  BOOLEAN         AllocateDestinationString
        )
        {
            LOAD_FUNCTION( RtlAnsiStringToUnicodeString );
            return pfnRtlAnsiStringToUnicodeString( DestinationString, SourceString, AllocateDestinationString );
        }

        // *********************************************************************************************************
        // RtlAppendAsciizToString
        // Undocumented
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAppendAsciizToString,
            _Inout_  PSTRING Destination,
            _In_opt_ PCSZ    Source
        )
        {
            LOAD_FUNCTION( RtlAppendAsciizToString );
            return pfnRtlAppendAsciizToString( Destination, Source );
        }

        // *********************************************************************************************************
        // RtlAppendPathElementGo 
        // Undocumented
        //

        NT_DLL_FUNCTION(
            NTSTATUS, WINAPI, RtlAppendPathElementGo,
            _In_    ULONG                      Flags,
            _Inout_ PRTL_UNICODE_STRING_BUFFER pStrBuffer,
            _In_    PCUNICODE_STRING           pAddend

        )
        {
            LOAD_FUNCTION( RtlAppendPathElementGo );
            return pfnRtlAppendPathElementGo( Flags, pStrBuffer, pAddend );
        }

        // *********************************************************************************************************
        // RtlAppendStringToString 
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlappendstringtostring
        //
        
        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAppendStringToString,
            _Inout_ PSTRING       Destination,
            _In_    CONST STRING* Source
        )
        {
            LOAD_FUNCTION( RtlAppendStringToString );
            return pfnRtlAppendStringToString( Destination, Source );
        }

        // *********************************************************************************************************
        // RtlAppendUnicodeStringToString 
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodestringtostring
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAppendUnicodeStringToString,
            _Inout_ PUNICODE_STRING  Destination,
            _In_    PCUNICODE_STRING Source
        )
        {
            LOAD_FUNCTION( RtlAppendUnicodeStringToString );
            return pfnRtlAppendUnicodeStringToString( Destination, Source );
        }

        // *********************************************************************************************************
        // RtlAppendUnicodeToString 
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodetostring
        //

        NT_DLL_FUNCTION(
            NTSTATUS, NTAPI, RtlAppendUnicodeToString,
            _Inout_ PUNICODE_STRING Destination,
            _In_    PCWSTR          Source
        )
        {
            LOAD_FUNCTION( RtlAppendUnicodeToString );
            return pfnRtlAppendUnicodeToString( Destination, Source );
        }

        // *********************************************************************************************************
        // RtlApplicationVerifierStop
        // Undocumented
        //

        NT_DLL_FUNCTION(
            VOID, NTAPI, RtlApplicationVerifierStop,
            _In_ ULONG_PTR Code,
            _In_ PCSTR     Message,
            _In_ PVOID     Value1,
            _In_ PCSTR     Description1,
            _In_ PVOID     Value2,
            _In_ PCSTR     Description2,
            _In_ PVOID     Value3,
            _In_ PCSTR     Description3,
            _In_ PVOID     Value4,
            _In_ PCSTR     Description4
        )
        {
            LOAD_FUNCTION( RtlApplicationVerifierStop );
            return pfnRtlApplicationVerifierStop(
                Code, Message, Value1, Description1, Value2, Description2, Value3, Description3, Value4, Description4
            );
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

#pragma endregion

        // ---------------------------------------------------------------------------------------------------------
        //                                            Nt functions
        // ---------------------------------------------------------------------------------------------------------

#pragma region Nt functions

        // None implemented yet

#pragma endregion

        // ---------------------------------------------------------------------------------------------------------
        //                                            Zw functions
        // ---------------------------------------------------------------------------------------------------------
        
#pragma region Zw functions

        // None implemented yet

#pragma endregion
    };
} // namespace nt_dll
#include "pch.h"

// I disable this annoying warning, because MSVC 19.22 (my compiler)
// assumes that Win32 API error codes have 'int' type, which is signed
// type, but in 'EXPECT_EQ' I compare it with a value of 'DWORD' type,
// which is unsigned.
#pragma warning( disable: 4389 ) // signed/unsigned mismatch

using namespace nt_dll;

static HMODULE g_hNtDll = GetModuleHandle( TEXT( "ntdll.dll") );

[[noreturn]] void TestThrow1()
{
    exception::ThrowError( ERROR_CALL_NOT_IMPLEMENTED );
}

[[noreturn]] void TestThrow2()
{
    exception::ThrowError( ERROR_CALL_NOT_IMPLEMENTED, CURRENT_LOCATION );
}

[[noreturn]] void TestThrow3()
{
    exception::ThrowErrorFormatMessage( L"Message: %s", ERROR_CALL_NOT_IMPLEMENTED, CURRENT_LOCATION, L"invalid call" );
}

TEST(Exception, Throwers)
{
    using namespace exception;

    EXPECT_THROW(
        ThrowError( ERROR_CALL_NOT_IMPLEMENTED ),
        CNtDllError
    );

    EXPECT_THROW(
        ThrowError( ERROR_CALL_NOT_IMPLEMENTED, CURRENT_LOCATION ),
        CNtDllError
    );

    EXPECT_THROW(
        ThrowErrorFormatMessage( L"%s", ERROR_CALL_NOT_IMPLEMENTED, CURRENT_LOCATION, L"Message" ),
        CNtDllError
    );
}

TEST(Exception, Code)
{
    using namespace exception;

    try
    {
        TestThrow1();
    }
    catch (const CNtDllError & err)
    {
        EXPECT_EQ( err.Code(), ERROR_CALL_NOT_IMPLEMENTED );
    }

    try
    {
        TestThrow2();
    }
    catch (const CNtDllError & err)
    {
        EXPECT_EQ( err.Code(), ERROR_CALL_NOT_IMPLEMENTED );
    }

    try
    {
        TestThrow3();
    }
    catch (const CNtDllError & err)
    {
        EXPECT_EQ( err.Code(), ERROR_CALL_NOT_IMPLEMENTED );
    }
}

TEST(Exception, DumpVisual)
{
    using namespace exception;
    setlocale( LC_ALL, "russian" );

    try
    {
        TestThrow1();
    }
    catch(const CNtDllError& err)
    {
        std::wcout << err.Dump() << std::endl;
    }

    try
    {
        TestThrow2();
    }
    catch (const CNtDllError & err)
    {
        std::wcout << err.Dump() << std::endl;
    }

    try
    {
        TestThrow3();
    }
    catch (const CNtDllError & err)
    {
        std::wcout << err.Dump() << std::endl;
    }
}

TEST(NtDll, RtlComputeCrc32)
{
    constexpr BYTE data[] = { 0x00, 0x00, 0x00, 0x00 };

    auto pfnRtlComputeCrc32 = reinterpret_cast<NtDll::PRtlComputeCrc32>(
        GetProcAddress( g_hNtDll, "RtlComputeCrc32" )
    );

    DWORD dwExpected = pfnRtlComputeCrc32( 0, data, _countof( data ) );

    DWORD dwCrc  = NtDll::RtlComputeCrc32( 0, data, _countof( data ) );

    EXPECT_EQ( dwCrc, dwExpected );
}

TEST(NtDll, CallSpecific)
{
    constexpr BYTE data[] = { 0x00, 0x00, 0x00, 0x00 };

    DWORD dwExpected = NtDll::RtlComputeCrc32( 0, data, _countof( data ) );

    DWORD dwCrc = NtDll::CallSpecific<NtDll::PRtlComputeCrc32>( 
        "RtlComputeCrc32", 0, data, static_cast<INT>( _countof( data ) )
    );

    EXPECT_EQ( dwCrc, dwExpected );
}

TEST(NtDll, CallSpecificWrong)
{
    using PFN = void (__stdcall*) ();

    EXPECT_THROW(
        NtDll::CallSpecific<PFN>( "NotExists" ),
        exception::CNtDllError
    );

    try 
    {
        NtDll::CallSpecific<PFN>( "NotExists" );
    }
    catch( const exception::CNtDllError& err )
    {
        EXPECT_EQ( err.Code(), ERROR_NOT_FOUND );
    }
}
#pragma once

// Windows header files
#include <Windows.h>

// STL header files
#include <string>
#include <chrono>
#include <ctime>

//
// Necessary defines for different project settings
// 

#if defined( _UNICODE ) || defined( UNICODE )
#   define tstring wstring
#   define tstringstream wstringstream
#   define tsprintf_s swprintf_s
#   define tsprintf_failed( iWritten ) ( (iWritten) == -1 )
#else
#   define tstring string
#   define tstringstream stringstream
#   define tsprintf_s sprintf_s
#   define tsprintf_failed( iWritten ) ( (iWritten) == -1 )
#endif

// Macro used to annotate friend template functions instead of [[noreturn]] attribute,
// because the last one is forbidden to use in such case
#define _No_return_

#define CONCATENATE_IMPL( token_1, token_2 ) token_1 ## token_2
#define CONCATENATE( token_1, token_2 ) CONCATENATE_IMPL( token_1, token_2 )

namespace nt_dll {
namespace utils {

    // *********************************************************************************************************
    // Constants
    // 
    // Begin
    // 

    // Maximum available error message length
    constexpr size_t ullMaxMessageLength = 3 * MAX_PATH;

    // Defaul error description. Used if no system description available
    constexpr TCHAR szDefaultErrorMessage[] = TEXT( "Unknown error" );

    // 
    // Constants
    // 
    // End
    // *********************************************************************************************************

    // *********************************************************************************************************
    // Classes and structs
    // 
    // Begin
    // 

    // Structure used to specify source loaction by line number,
    // file name and function name. To specify current location
    // use marco defined below the struct.
    struct CCodeLocation
    {
        // Line number
        ULONGLONG ullLine;

        // File name
        std::tstring sFile;

        // Function name
        std::tstring sFunction;
    };

    // Macro used to determine current code location easily
#   define CURRENT_LOCATION nt_dll::utils::CCodeLocation{ __LINE__, TEXT( __FILE__ ), TEXT( __FUNCTION__ ) }


    // std::result_of is deprecated in C++17 and not available in C++20
    // That's the reason to define own trait.
#if defined(_HAS_CXX17) && _HAS_CXX17
    template<typename Func, typename... Args>
    struct result_type_of : std::invoke_result<Func, Args...> { };
#else
    template<typename Func, typename... Args>
    struct result_type_of : std::result_of<Func(Args...)> { };
#endif

    // 
    // Classes and structs
    // 
    // End
    // *********************************************************************************************************

    // *********************************************************************************************************
    // Functions
    // 
    // Begin
    // 

    // Function used to print specified message to debugger stream.
    // It formats by following pattern:
    // 
    //             [Time] Function: message
    //             
    // where 'Time' is current time in ctime format,
    // 'Function' is a name of function, that invokes DbgOut and
    // 'message' is a user-defined message to be printed
    inline void DbgOut( 
        _In_ const std::tstring& sMessage, 
        _In_ const CCodeLocation& location 
    )
    {
        //
        // Capture current time
        // 

        const auto now = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now()
        );

        //
        // Format a message
        // 

        std::tstringstream strmError;

        #pragma warning( suppress: 4996 ) // 'ctime': This function or variable may be unsafe.
        strmError << TEXT( "[" ) << std::ctime( &now ) << TEXT( "] " )
            << location.sFunction << TEXT( ": " ) << sMessage;

        //
        // Output into debugger stream
        // 

        ::OutputDebugString( strmError.str().c_str() );
    }


    // This function is a wrapper over 'sprintf_s' or 'wsprintf_s' function.
    // It returns a formatted string in case of success and an empty string otherwise.
    template<typename... ArgsT>
    _Must_inspect_result_
    std::tstring Format( 
        _Printf_format_string_ _Literal_ LPCTSTR pszFormat, 
        _In_ ArgsT&&... args 
    )
    {
        //
        // Attempt to format message via 'tsprintf_s'
        // 

        std::vector<TCHAR> buffer( utils::ullMaxMessageLength, 0 );
        int iWritten = tsprintf_s(
            buffer.data(),
            buffer.size(),
            pszFormat,
            std::forward<ArgsT>( args )...
        );

        //
        // In case of an error this function prints a message
        // into debugger stream.
        // 

        if (tsprintf_failed( iWritten )) 
        {
            utils::DbgOut( TEXT( "tsprintf failed" ), CURRENT_LOCATION );
            return std::tstring();
        }
        else 
        {
            return std::tstring( buffer.data() );
        }
    }

    // 
    // Functions
    // 
    // End
    // *********************************************************************************************************

} // namespace utils
} // namespace nt_dll
#pragma once

// Windows header files
#include <Windows.h>

// STL header files
#include <iomanip>
#include <sstream>

// Library includes
#include "Utils.h"

namespace nt_dll {
namespace exception {

    // *********************************************************************************************************
    // Class CNtDllError
    // 
    // Describes an error that can be thrown in NtDll library.
    // It can be constructed from Win32 error code and provide
    // description of the error. Actually it is a wrapper over
    // Win32 error, but can handle another user-defined errors.
    // 
    // Begin
    // 

    class CNtDllError
    {
    public:
        // ---------------------------------------------------------------------------------------------------------
        //                                           Public API
        // ---------------------------------------------------------------------------------------------------------
        
        // Trivial copy and move constructors
        CNtDllError( const CNtDllError& ) = default;
        CNtDllError( CNtDllError&& ) = default;


        // Trivial copy and move assignment operators
        CNtDllError& operator=( const CNtDllError& ) = default;
        CNtDllError& operator=( CNtDllError&& ) = default;


        // Returns error description
        std::tstring Message() const { return m_sMessage; }


        // Returns error code
        DWORD Code() const { return m_dwCode; }


        // Returns extended error description
        std::tstring Dump() const 
        { 
            std::tstringstream strmDump;

            strmDump \
                << TEXT( "Error code: 0x" ) << std::setw( 8 ) << std::setfill( TEXT( '0' ) ) << std::hex << m_dwCode << std::endl
                << TEXT( "Description: " ) << m_sMessage << std::endl;

            if (m_bIsLocationSet) 
            {
                strmDump \
                << TEXT( "Location: " ) << m_sFile << TEXT( " at line " ) << m_ullLine << std::endl
                << TEXT( "Function: " ) << m_sFunction << std::endl;
            }

            std::tstring sDump = std::move( strmDump.str() );

            return sDump;
        }

    public:
        // ---------------------------------------------------------------------------------------------------------
        //                                        Friend functions
        // ---------------------------------------------------------------------------------------------------------

        // Contructs an error object by error code only and throws it
        friend void ThrowError( 
            _In_ DWORD dwError 
        );


        // Constructs an error object by error code and location, given by CCodeLocation object, and throws it
        friend void ThrowError( 
            _In_ DWORD dwError,
            _In_ const utils::CCodeLocation& location 
        );


        // Constructs an error object by error code and location, given by CCodeLocation object, and custom message and throws it
        template<typename... ArgsT>
        friend void ThrowErrorFormatMessage( 
            _Printf_format_string_ _Literal_ LPCTSTR pszFormat, 
            _In_ DWORD dwError, 
            _In_ const utils::CCodeLocation& location, 
            _In_ ArgsT&&... args 
        );

    private:
        // ---------------------------------------------------------------------------------------------------------
        //                                        Hidden functions
        // ---------------------------------------------------------------------------------------------------------
        
        // Costructor with error code only
        CNtDllError( _In_ DWORD dwError )
            : m_bIsLocationSet( false )
            , m_dwCode( dwError )
            , m_ullLine( 0 )
            , m_sFile( {} )
            , m_sMessage( {} )
        {
            FormatMessage( dwError );
        }


        // Constructor with error code and custom message
        CNtDllError( _In_ DWORD dwError, _In_ const std::tstring& sMessage )
            : m_bIsLocationSet( false )
            , m_dwCode( dwError )
            , m_ullLine( 0 )
            , m_sFile( {} )
            , m_sMessage( sMessage )
        {
            // Nothing to do
        }


        // Constructor with error code and source location
        CNtDllError( _In_ DWORD dwError, _In_ const utils::CCodeLocation& location )
            : m_bIsLocationSet( true )
            , m_dwCode( dwError )
            , m_ullLine( location.ullLine )
            , m_sFile( location.sFile )
            , m_sFunction( location.sFunction )
            , m_sMessage( {} )
        {
            FormatMessage( dwError );
        }


        // Constructor with error code, source location and custom message
        CNtDllError( _In_ DWORD dwError, _In_ const utils::CCodeLocation& location, _In_ const std::tstring& sMessage )
            : m_bIsLocationSet( true )
            , m_dwCode( dwError )
            , m_ullLine( location.ullLine )
            , m_sFile( location.sFile )
            , m_sFunction( location.sFunction )
            , m_sMessage( sMessage )
        {
            // Nothing to do
        }


        // Function puts error description to m_sMessage
        void FormatMessage( _In_ DWORD dwError )
        {
            LPTSTR pszBuffer = nullptr;

            DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

            //
            // Attempting to retreive error message from system
            // 

            DWORD dwWritten = ::FormatMessage(
                dwFlags,
                nullptr,
                dwError,
                MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                reinterpret_cast<LPTSTR>( &pszBuffer ),
                0,
                nullptr
            );

            if (!dwWritten) 
            {
                //
                // If none available, dump message to debugger and assingn default
                // 

                std::tstringstream strmMessage;
                strmMessage << TEXT( "no message found for code: " ) << dwError;

                utils::DbgOut( strmMessage.str(), CURRENT_LOCATION );

                m_sMessage.assign( utils::szDefaultErrorMessage, _countof( utils::szDefaultErrorMessage ) );
            }
            else 
            {
                //
                // Otherwise assign extracted message and free the buffer
                // 

                m_sMessage.assign( pszBuffer, dwWritten );
                LocalFree( pszBuffer );
            }
        }

    private:
        // ---------------------------------------------------------------------------------------------------------
        //                                             Data
        // ---------------------------------------------------------------------------------------------------------
        
        // Utility flag
        // If set to 'true', fields 'm_ullLine', 'm_sFile'
        // and 'm_sFunction' contain valid information.
        bool m_bIsLocationSet;

        // Error code
        DWORD m_dwCode;

        // Code line number
        ULONGLONG m_ullLine;
        
        // Name of source file
        std::tstring m_sFile;
        
        // Name of fucntion
        std::tstring m_sFunction;

        // Error description (may be set to custom one)
        std::tstring m_sMessage;
    };

    // 
    // Class CNtDllError
    // 
    // End
    // *********************************************************************************************************


    [[noreturn]] inline void ThrowError(
        _In_ DWORD dwError 
    )
    {
        CNtDllError error( dwError );
        throw error;
    }


    [[noreturn]] inline void ThrowError( 
        _In_ DWORD dwError,
        _In_ const utils::CCodeLocation& location 
    )
    {
        CNtDllError error( dwError, location );
        throw error;
    }


    template<typename... ArgsT>
    _No_return_ void ThrowErrorFormatMessage(
        _Printf_format_string_ _Literal_ LPCTSTR pszFormat,
        _In_ DWORD dwError, 
        _In_ const utils::CCodeLocation& location, 
        _In_ ArgsT&&... args 
    )
    {
        const auto sMessage = utils::Format( pszFormat, std::forward<ArgsT>( args )... );

        if (sMessage.empty())
        {
            CNtDllError error( dwError, location );
            throw error;
        }
        else
        {
            CNtDllError error( dwError, location, sMessage );
            throw error;
        }
    }

} // namespace exception
} // namespace nt_dll
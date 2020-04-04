# NtDll library

This ***header-only*** library provides an easy acces to NtDll.dll functions. NtDll.dll is a key component of Windows system, it is a kind of a "bridge"
between Win32 API (e.g. `CreateFile`, `PostMessage`, etc.) and Native NT API (`NtCreateFile`, `RtlAddAccessAllowedAce`, etc.).

It is quite beautiful to use it like the library allows:

```cpp
constexpr BYTE data[] = { 0x00, 0x00, 0x00, 0x00 };

DWORD dwCrc = NtDll::RtlComputeCrc32( 0, data, _countof( data ) );
```

Instead of the way that has been used for a years:

```cpp
constexpr BYTE data[] = { 0x00, 0x00, 0x00, 0x00 };

HMODULE hNtDll = GetModuleHandle( L"ntdll.dll" );

if (!hNtDll) {
    // Handle error
}

using PRtlComputeCrc32 = DWORD (WINAPI*) ( _In_ DWORD, _In_ CONST BYTE*, _In_ INT );

auto pfnRtlComputeCrc32 = reinterpret_cast<PRtlComputeCrc32>(
    GetProcAddress( hNtDll, "RtlComputeCrc32" )
);

if (!pfnRtlComputeCrc32) {
    // Handle error
}

DWORD dwCrc = pfnRtlComputeCrc32( 0, data, _countof( data ) );
```
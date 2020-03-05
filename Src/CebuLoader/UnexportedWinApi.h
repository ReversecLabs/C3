#pragma once

namespace FSecure::Loader::UnexportedWinApi
{
	/// Wrapper around private ntdll!LdrpHandleTlsData
	/// Initializes static data from .tls section
	/// @param baseAddress of PE file image
	/// @returns value returned from ntdll!LdrpHandleTlsData
	DWORD LdrpHandleTlsData(void* baseAddress);

#ifdef _M_IX86
	///	Wrapper around private ntdll!RtlInsertInvertedFunctionTable
	/// Adds inverted function table required for Exception Handling
	/// @param baseAddress of PE file image
	/// @param sizeOfImage size of PE file image
	void RtlInsertInvertedFunctionTable(void* baseAddress, DWORD sizeOfImage);
#endif // _M_IX86
}

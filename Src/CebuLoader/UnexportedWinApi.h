#pragma once

namespace MWR::Loader::UnexportedWinApi
{
	/// Get size of image from NT headers
	/// @param baseAddress - base address of PE file image
	/// @returns size of image specified image
	inline DWORD GetSizeOfImage(UINT_PTR baseAddress)
	{
		auto ntHeader = baseAddress + ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew;
		return reinterpret_cast<PIMAGE_NT_HEADERS>(ntHeader)->OptionalHeader.SizeOfImage;
	}

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

#pragma once

namespace MWR::Loader::UnexportedWinApi
{
	inline DWORD GetSizeOfImage(UINT_PTR baseAddress)
	{
		auto ntHeader = baseAddress + ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew;
		return reinterpret_cast<PIMAGE_NT_HEADERS>(ntHeader)->OptionalHeader.SizeOfImage;
	}

	DWORD LdrpHandleTlsData(void* baseAddress);

#ifdef _M_IX86
	void RtlInsertInvertedFunctionTable(void* baseAddress, DWORD sizeOfImage);
#endif // _M_IX86
}

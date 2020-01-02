#pragma once

namespace MWR::Loader::UnexportedWinApi
{
	struct UNICODE_STR
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR pBuffer;
	};

	struct LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STR FullDllName;
		UNICODE_STR BaseDllName;
		ULONG Flags;
		SHORT LoadCount;
		SHORT TlsIndex;
		LIST_ENTRY HashTableEntry;
		ULONG TimeDateStamp;
	};

	typedef DWORD(NTAPI* LdprHandleTlsData)(LDR_DATA_TABLE_ENTRY*);

	inline DWORD GetSizeOfImage(UINT_PTR baseAddress)
	{
		auto ntHeader = baseAddress + ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew;
		return reinterpret_cast<PIMAGE_NT_HEADERS>(ntHeader)->OptionalHeader.SizeOfImage;
	}

	LdprHandleTlsData GetLdrpHandleTlsData();
}

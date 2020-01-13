#include "stdafx.h"
#include "UnexportedWinApi.h"

#include <algorithm>
#include <string>
using namespace std::string_literals;

// Based on Blackbone https://github.com/DarthTon/Blackbone

namespace MWR::Loader::UnexportedWinApi
{
	namespace
	{
		std::pair<std::string, size_t> GetLdrpHandleTlsOffsetData()
		{
#if defined _M_X64
			if (IsWindows10RS3OrGreater())
			{
				auto offset = 0x43;
				if (IsWindows10RS6OrGreater())
					offset = 0x46;
				else if (IsWindows10RS4OrGreater())
					offset = 0x44;

				return { "\x74\x33\x44\x8d\x43\x09"s, offset };
			}
			else if (IsWindows10RS2OrGreater())
				return { "\x74\x33\x44\x8d\x43\x09"s, 0x43 };
			else if (IsWindows8Point1OrGreater())
				return { "\x44\x8d\x43\x09\x4c\x8d\x4c\x24\x38"s, 0x43 };
			else if (IsWindows8OrGreater())
				return { "\x48\x8b\x79\x30\x45\x8d\x66\x01"s, 0x49 };
			else if (IsWindows7OrGreater())
			{
				//const bool update1 = WinVer().revision > 24059;
				const bool update1 = true; // FIXME handle Win7 revisions
				return { "\x41\xb8\x09\x00\x00\x00\x48\x8d\x44\x24\x38"s, update1 ? 0x23 : 0x27 };
			}
			else
				abort(); // TODO
#elif defined _M_IX86
			if (IsWindows10RS3OrGreater())
			{
				auto pattern = "\x8b\xc1\x8d\x4d\xbc\x51";
				if (IsWindows10RS5OrGreater())
					pattern = "\x33\xf6\x85\xc0\x79\x03";
				else if (IsWindows10RS4OrGreater())
					pattern = "\x8b\xc1\x8d\x4d\xac\x51";

				auto offset = 0x18;
				if (IsWindows10RS6OrGreater())
					offset = 0x2E;
				else if (IsWindows10RS5OrGreater())
					offset = 0x2C;

				return { pattern, offset };
			}
			else if (IsWindows10RS2OrGreater())
				return { "\x8b\xc1\x8d\x4d\xbc\x51"s, 0x18 };
			else if (IsWindows8Point1OrGreater())
				return { "\x50\x6a\x09\x6a\x01\x8b\xc1"s, 0x1B };
			else if (IsWindows8OrGreater())
				return { "\x8b\x45\x08\x89\x45\xa0"s, 0xC };
			else if (IsWindows7OrGreater())
				return { "\x74\x20\x8d\x45\xd4\x50\x6a\x09"s, 0x14 };
			else
				abort(); // TODO
#else
# error Unsupported architecture
#endif
		}

#if defined _M_IX86
		std::pair<std::string, size_t> GetRtlInsertInvertedFunctionTableOffset()
		{
			if (IsWindows10RS3OrGreater())
				return { "\x53\x56\x57\x8d\x45\xf8\x8b\xfa"s, 0x8 };
			else if (IsWindows10RS2OrGreater())
				return { "\x8d\x45\xf0\x89\x55\xf8\x50\x8d\x55\xf4"s, 0xB };
			else if (IsWindows8Point1OrGreater())
				return { "\x53\x56\x57\x8b\xda\x8b\xf9\x50"s, 0xB };
			else if (IsWindows8OrGreater())
				return { "\x8b\xff\x55\x8b\xec\x51\x51\x53\x57\x8b\x7d\x08\x8d"s, 0 };
			else if (IsWindows7OrGreater())
				return { "\x8b\xff\x55\x8b\xec\x56\x68"s, 0 };
			else
				abort(); // TODO
		}
#endif

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

#if defined _M_X64
		typedef DWORD(NTAPI* LdprHandleTlsData_t)(LDR_DATA_TABLE_ENTRY*);
#elif defined _M_IX86
		typedef DWORD(__thiscall* LdprHandleTlsData_t)(LDR_DATA_TABLE_ENTRY*);
		typedef void(__fastcall* RtlInsertInvertedFunctionTableWin8Point1OrGreater)(void* baseAddr, DWORD sizeOfImage);
		typedef void(_stdcall* RtlInsertInvertedFunctionTableWin8OrGreater)(void* baseAddr, DWORD sizeOfImage);
		typedef void(_stdcall* RtlInsertInvertedFunctionTableWin7OrGreater)(void* ldrpInvertedFunctionTable, void* baseAddr, DWORD sizeOfImage);
#else
#error Unsupported architecture
#endif

		void* FindSymbol(const wchar_t* dll, std::pair<std::string, size_t> const& offsetData)
		{
			auto dllBase = GetModuleHandleW(dll);
			auto dllSize = GetSizeOfImage((UINT_PTR)dllBase);

			auto match = std::search((char*)dllBase, (char*)dllBase + dllSize, offsetData.first.begin(), offsetData.first.end());
			if (match == (char*)dllBase + dllSize)
				abort();
			return match - offsetData.second;
		}

		void* FindNtDllSymbol(std::pair<std::string, size_t> const& offsetData)
		{
			return FindSymbol(L"ntdll.dll", offsetData);
		}

#if defined _M_IX86
		void* g_RtlInsertInvertedFunctionTable = nullptr;
		void* GetRtlInsertInvertedFunctionTable()
		{
			if (!g_RtlInsertInvertedFunctionTable)
				g_RtlInsertInvertedFunctionTable = FindNtDllSymbol(GetRtlInsertInvertedFunctionTableOffset());
			return g_RtlInsertInvertedFunctionTable;
		}
#endif // defined _M_IX86

		LdprHandleTlsData_t g_LdrpHandleTlsData = nullptr;
		LdprHandleTlsData_t GetLdrpHandleTlsData()
		{
			if (!g_LdrpHandleTlsData)
				g_LdrpHandleTlsData = (LdprHandleTlsData_t)(FindNtDllSymbol(GetLdrpHandleTlsOffsetData()));
			return g_LdrpHandleTlsData;
		}
	} // namespace

	DWORD LdrpHandleTlsData(void* baseAddress)
	{
		auto ldrpHandleTlsData = GetLdrpHandleTlsData();
		LDR_DATA_TABLE_ENTRY ldrDataTableEntry{};
		ldrDataTableEntry.DllBase = baseAddress;
		return ldrpHandleTlsData(&ldrDataTableEntry);
	}

#if defined _M_IX86
	void RtlInsertInvertedFunctionTable(void* baseAddress, DWORD sizeOfImage)
	{
		auto rtlInsertInvertedFunctionTable = GetRtlInsertInvertedFunctionTable();
		if (IsWindows8Point1OrGreater())
			((RtlInsertInvertedFunctionTableWin8Point1OrGreater)rtlInsertInvertedFunctionTable)(baseAddress, sizeOfImage);
		else if (IsWindows8OrGreater())
			((RtlInsertInvertedFunctionTableWin8OrGreater)rtlInsertInvertedFunctionTable)(baseAddress, sizeOfImage);
		else
			abort(); // TODO
	}
#endif // defined _M_IX86

} // namespace MWR::Loader

#include "stdafx.h"
#include "UnexportedWinApi.h"
#include "PeUtils.h"
#include <algorithm>
#include <string>
using namespace std::string_literals;

// Based on Blackbone https://github.com/DarthTon/Blackbone

namespace FSecure::Loader::UnexportedWinApi
{
	namespace
	{
		std::pair<std::string, size_t> GetLdrpHandleTlsOffsetData()
		{
#if defined _M_X64
			if (IsWindows10RS3OrGreater())
			{
				auto offset = 0x43;
				if (IsWindows1019H1OrGreater())
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
				const bool update1 = WinVer().revision > 24059;
				return { "\x41\xb8\x09\x00\x00\x00\x48\x8d\x44\x24\x38"s, update1 ? 0x23 : 0x27 };
			}
			else
				QuietAbort();
#elif defined _M_IX86
			if (IsWindows10RS3OrGreater())
			{
				auto pattern = "\x8b\xc1\x8d\x4d\xbc\x51";
				if (IsWindows10RS5OrGreater())
					pattern = "\x33\xf6\x85\xc0\x79\x03";
				else if (IsWindows10RS4OrGreater())
					pattern = "\x8b\xc1\x8d\x4d\xac\x51";

				auto offset = 0x18;
				if (IsWindows1020H1OrGreater())
					offset = 0x2C;
				else if (IsWindows1019H1OrGreater())
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
				QuietAbort();
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
				QuietAbort();
		}

		std::pair<std::string, size_t> GetLdrpInvertedFunctionTableOffset()
		{
			// AFAIK only Win7 requires passing LdrpInvertedFunctionTable pointer to RtlInsertInvertedFunctionTable
			if (IsWindows8OrGreater())
				QuietAbort();
			else if (IsWindows7OrGreater())
				return { "\x89\x5D\xE0\x38", -0x1B };
			else
				QuietAbort();
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
		using LdrpHandleTlsData_t = DWORD(*)(LDR_DATA_TABLE_ENTRY*);
#elif defined _M_IX86
		using LdrpHandleTlsDataWin8Point1OrGreater = DWORD(__thiscall*)(LDR_DATA_TABLE_ENTRY*);
		using LdprHandleTlsDataWin7OrGreater = DWORD(__stdcall*)(LDR_DATA_TABLE_ENTRY*);
		using RtlInsertInvertedFunctionTableWin8Point1OrGreater = void(__fastcall*)(void* baseAddr, DWORD sizeOfImage);
		using RtlInsertInvertedFunctionTableWin8OrGreater = void(__stdcall*)(void* baseAddr, DWORD sizeOfImage);
		using RtlInsertInvertedFunctionTableWin7OrGreater = void(__stdcall*)(void* ldrpInvertedFunctionTable, void* baseAddr, DWORD sizeOfImage);
#else
#error Unsupported architecture
#endif
		void* Find(void* begin, void* end, std::pair<std::string, size_t> const& offsetData)
		{
			auto match = std::search((char*)begin, (char*)end, offsetData.first.begin(), offsetData.first.end());
			if (match == end)
				QuietAbort();
			return (void*)(match - offsetData.second);
		}

		void* FindInSection(std::wstring const& dll, std::string const& section, std::pair<std::string, size_t> const& offsetData)
		{
			auto dllBase = GetModuleHandleW(dll.c_str());
			auto [begin, end] = GetSectionRange(dllBase, section);
			return Find(begin, end, offsetData);
		}

		void* FindSymbol(std::wstring const& dll, std::pair<std::string, size_t> const& offsetData)
		{
			auto dllBase = GetModuleHandleW(dll.c_str());
			auto dllSize = GetSizeOfImage((UINT_PTR)dllBase);

			return Find(dllBase, dllBase + dllSize, offsetData);
		}

		void* FindNtDllSymbol(std::pair<std::string, size_t> const& offsetData)
		{
			return FindInSection(L"ntdll.dll", ".text", offsetData);
		}

#if defined _M_IX86
		void* g_RtlInsertInvertedFunctionTable = nullptr;
		void* GetRtlInsertInvertedFunctionTable()
		{
			if (!g_RtlInsertInvertedFunctionTable)
				g_RtlInsertInvertedFunctionTable = FindNtDllSymbol(GetRtlInsertInvertedFunctionTableOffset());
			return g_RtlInsertInvertedFunctionTable;
		}

		void* g_LdrpInvertedFunctionTable = nullptr;
		void* GetLdrpInvetedFunctionTable()
		{
			if (!g_LdrpInvertedFunctionTable)
				g_LdrpInvertedFunctionTable = *(void**)FindNtDllSymbol(GetLdrpInvertedFunctionTableOffset());
			return g_LdrpInvertedFunctionTable;
		}
#endif // defined _M_IX86
		void* g_LdrpHandleTlsData = nullptr;
		void* GetLdrpHandleTlsData()
		{
			if (!g_LdrpHandleTlsData)
				g_LdrpHandleTlsData = FindNtDllSymbol(GetLdrpHandleTlsOffsetData());
			return g_LdrpHandleTlsData;
		}
	} // namespace

	DWORD LdrpHandleTlsData(void* baseAddress)
	{
		auto ldrpHandleTlsData = GetLdrpHandleTlsData();
		LDR_DATA_TABLE_ENTRY ldrDataTableEntry{};
		ldrDataTableEntry.DllBase = baseAddress;
#if defined _M_X64
		return ((LdrpHandleTlsData_t)ldrpHandleTlsData)(&ldrDataTableEntry);
#elif defined _M_IX86
		if (IsWindows8Point1OrGreater())
			return ((LdrpHandleTlsDataWin8Point1OrGreater)ldrpHandleTlsData)(&ldrDataTableEntry);
		else
			return ((LdprHandleTlsDataWin7OrGreater)ldrpHandleTlsData)(&ldrDataTableEntry);
#else
#error Unsupported architecture
#endif
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
			((RtlInsertInvertedFunctionTableWin7OrGreater)rtlInsertInvertedFunctionTable)(GetLdrpInvetedFunctionTable(), baseAddress, sizeOfImage);
	}
#endif // defined _M_IX86

} // namespace FSecure::Loader

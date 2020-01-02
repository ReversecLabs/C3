#include "stdafx.h"
#include "UnexportedWinApi.h"

// Based on Blackbone https://github.com/DarthTon/Blackbone

namespace MWR::Loader::UnexportedWinApi
{
	namespace
	{
		std::pair<std::string, size_t> GetOsLdrpHandleTlsOffsetData()
		{
			if (IsWindows10RS3OrGreater())
			{
				// LdrpHandleTlsData
				// 74 33 44 8D 43 09
				auto offset = 0x43;
				if (IsWindows10RS6OrGreater())
					offset = 0x46;
				else if (IsWindows10RS4OrGreater())
					offset = 0x44;

				return { "\x74\x33\x44\x8d\x43\x09"s, offset };
			}
			else if (IsWindows10RS2OrGreater())
			{
				// LdrpHandleTlsData
				// 74 33 44 8D 43 09
				return { "\x74\x33\x44\x8d\x43\x09"s, 0x43 };
			}
			else if (IsWindows8Point1OrGreater())
			{
				// LdrpHandleTlsData
				// 44 8D 43 09 4C 8D 4C 24 38
				return { "\x44\x8d\x43\x09\x4c\x8d\x4c\x24\x38"s, 0x43 };
			}
			else if (IsWindows8OrGreater())
			{
				// LdrpHandleTlsData
				// 48 8B 79 30 45 8D 66 01
				return { "\x48\x8b\x79\x30\x45\x8d\x66\x01"s, 0x49 };
			}
			else if (IsWindows7OrGreater())
			{
				//const bool update1 = WinVer().revision > 24059;
				const bool update1 = true; // FIXME handle Win7 revisions

				// LdrpHandleTlsData
				// 41 B8 09 00 00 00 48 8D 44 24 38
				return { "\x41\xb8\x09\x00\x00\x00\x48\x8d\x44\x24\x38"s, update1 ? 0x23 : 0x27 };
			}
			else
				abort(); // TODO
		}
	}

	LdprHandleTlsData GetLdrpHandleTlsData()
	{
		auto offsetData = GetOsLdrpHandleTlsOffsetData();
		auto ntdllBase = GetModuleHandleW(L"ntdll.dll");
		auto ntdllSize = GetSizeOfImage((UINT_PTR)ntdllBase);


		auto match = std::search((char*)ntdllBase, (char*)ntdllBase + ntdllSize, offsetData.first.begin(), offsetData.first.end());
		if (match == (char*)ntdllBase + ntdllSize)
			abort();

		return (LdprHandleTlsData)(match - offsetData.second);
	}

}

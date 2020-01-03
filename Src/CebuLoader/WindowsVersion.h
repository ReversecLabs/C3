#pragma once

#include <windows.h>

namespace MWR::Loader
{
#define _WIN32_WINNT_NT4            0x0400
#define _WIN32_WINNT_WIN2K          0x0500
#define _WIN32_WINNT_WINXP          0x0501
#define _WIN32_WINNT_WS03           0x0502
#define _WIN32_WINNT_WIN6           0x0600
#define _WIN32_WINNT_VISTA          0x0600
#define _WIN32_WINNT_WS08           0x0600
#define _WIN32_WINNT_LONGHORN       0x0600
#define _WIN32_WINNT_WIN7           0x0601
#define _WIN32_WINNT_WIN8           0x0602
#define _WIN32_WINNT_WINBLUE        0x0603
#define _WIN32_WINNT_WIN10          0x0A00

	enum eBuildThreshold
	{
		Build_RS0 = 10586,
		Build_RS1 = 14393,
		Build_RS2 = 15063,
		Build_RS3 = 16299,
		Build_RS4 = 17134,
		Build_RS5 = 17763,
		Build_RS6 = 18362,
		Build_RS_MAX = 99999,
	};

	enum eVerShort
	{
		WinUnsupported, // Unsupported OS
		WinXP,          // Windows XP
		Win7,           // Windows 7
		Win8,           // Windows 8
		Win8Point1,     // Windows 8.1
		Win10,          // Windows 10
		Win10_RS1,      // Windows 10 Anniversary update
		Win10_RS2,      // Windows 10 Creators update
		Win10_RS3,      // Windows 10 Fall Creators update
		Win10_RS4,      // Windows 10 Spring Creators update
		Win10_RS5,      // Windows 10 October 2018 update
		Win10_RS6,      // Windows 10 May 2019 update
	};

	struct WinVersion
	{
		eVerShort ver = WinUnsupported;
		uint32_t revision = 0;
		RTL_OSVERSIONINFOEXW native = { };
	};

	WinVersion& WinVer();

	inline uint32_t GetRevision()
	{
		HKEY hKey = NULL;

		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey) == 0)
		{
			wchar_t data[MAX_PATH] = {};
			DWORD dataSize = sizeof(data);
			DWORD type = REG_SZ;

			if (RegQueryValueExW(hKey, L"BuildLabEx", nullptr, &type, reinterpret_cast<LPBYTE>(data), &dataSize) == 0)
			{
				std::wstring buildStr = data;
				size_t first = buildStr.find(L'.');
				size_t second = buildStr.find(L'.', first + 1);

				if (second > first&& first != buildStr.npos)
				{
					RegCloseKey(hKey);
					return std::wcstol(buildStr.substr(first + 1, second - first - 1).c_str(), nullptr, 10);
				}
			}

			RegCloseKey(hKey);
		}

		return 0;
	}

	bool IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor, DWORD dwBuild);

	inline bool IsWindowsXPOrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0, 0);
	}

	inline bool IsWindowsXPSP1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 1, 0);
	}

	inline bool IsWindowsXPSP2OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 2, 0);
	}

	inline bool IsWindowsXPSP3OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3, 0);
	}

	inline bool IsWindowsVistaOrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 0, 0);
	}

	inline bool IsWindowsVistaSP1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 1, 0);
	}

	inline bool IsWindowsVistaSP2OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 2, 0);
	}

	inline bool IsWindows7OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 0, 0);
	}

	inline bool IsWindows7SP1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 1, 0);
	}

	inline bool IsWindows8OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN8), LOBYTE(_WIN32_WINNT_WIN8), 0, 0);
	}

	inline bool IsWindows8Point1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINBLUE), LOBYTE(_WIN32_WINNT_WINBLUE), 0, 0);
	}

	inline bool IsWindows10OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, 0);
	}

	inline bool IsWindows10RS1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS1);
	}

	inline bool IsWindows10RS2OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS2);
	}

	inline bool IsWindows10RS3OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS3);
	}

	inline bool IsWindows10RS4OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS4);
	}

	inline bool IsWindows10RS5OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS5);
	}

	inline bool IsWindows10RS6OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS6);
	}

	inline bool IsWindowsServer()
	{
		OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, { 0 }, 0, 0, 0, VER_NT_WORKSTATION };
		DWORDLONG        const dwlConditionMask = VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);

		return !VerifyVersionInfoW(&osvi, VER_PRODUCT_TYPE, dwlConditionMask);
	}

}

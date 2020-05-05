// Replacement for #include <VersionHelpers.h> that doesn't require exe manifest
// Taken from https://github.com/DarthTon/Blackbone and modified
// License: MIT

#pragma once

#ifndef _WIN32_WINNT
#	define _WIN32_WINNT _WIN32_WINNT_WIN7
#endif
#ifndef NOMINMAX
#	define NOMINMAX
#endif

#ifndef OBF
#	define OBF(x) x
#endif

#include <windows.h>
#include <winternl.h>

#include <string_view>

namespace FSecure
{
	namespace Detail
	{
		BOOL GetVersionExW(LPOSVERSIONINFOEXW lpVersionInformation)
		{
			using fnRtlGetVersion = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOEXW lpVersionInformation);
			auto RtlGetVersion = (fnRtlGetVersion)GetProcAddress(GetModuleHandleW(OBF(L"ntdll.dll")), OBF("RtlGetVersion"));
			if (!RtlGetVersion)
				return FALSE;

			return RtlGetVersion(lpVersionInformation) != 0 /* STATUS_SUCCESS */;
		}

		inline uint32_t GetRevision()
		{
			HKEY hKey = NULL;

			if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBF(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), 0, KEY_QUERY_VALUE, &hKey) == 0)
			{
				wchar_t data[MAX_PATH] = {};
				DWORD dataSize = sizeof(data);
				DWORD type = REG_SZ;

				if (RegQueryValueExW(hKey, OBF(L"BuildLabEx"), nullptr, &type, reinterpret_cast<LPBYTE>(data), &dataSize) == 0)
				{
					std::wstring_view buildStr{ data, dataSize / sizeof(wchar_t) };
					size_t first = buildStr.find(L'.');
					size_t second = buildStr.find(L'.', first + 1);

					if (second > first && first != buildStr.npos)
					{
						RegCloseKey(hKey);
						return std::wcstol(buildStr.substr(first + 1, second - first - 1).data(), nullptr, 10);
					}
				}

				RegCloseKey(hKey);
			}
			return 0;
		}
	}

	struct OsVersionInfoExW : RTL_OSVERSIONINFOEXW
	{
		OsVersionInfoExW() = default;

		static const OsVersionInfoExW& CurrentHost()
		{
#if !defined FSECURE_WINVER_NO_USE_THREADSAFE_STATIC
			static OsVersionInfoExW hostVersion(0);
			return hostVersion;
#else
			s_hostVersion = new OsVersionInfoExW(0);
			return *s_hostVersion;
#endif
		}

	private:
		OsVersionInfoExW(int tag)
		{
			this->dwOSVersionInfoSize = sizeof(*this);
			Detail::GetVersionExW(this);
		}

#if defined FSECURE_WINVER_NO_USE_THREADSAFE_STATIC
		inline static OsVersionInfoExW* s_hostVersion = nullptr;
#endif

	};

	static_assert(sizeof(OsVersionInfoExW) == sizeof(RTL_OSVERSIONINFOEXW));

	struct WindowsVersion
	{
		OsVersionInfoExW native;
		uint32_t revision = 0;

		static WindowsVersion const& CurrentHost()
		{
#if !defined FSECURE_WINVER_NO_USE_THREADSAFE_STATIC
			static WindowsVersion hostVersion(0);
			return hostVersion;
#else
			s_hostVersion = new WindowsVersion(0);
			return *s_hostVersion;
#endif
		}

		WindowsVersion() = default;

	private:
		WindowsVersion(int tag)
			: native{ OsVersionInfoExW::CurrentHost()}
			, revision{Detail::GetRevision()}
		{
		}

#if defined FSECURE_WINVER_NO_USE_THREADSAFE_STATIC
		inline static WindowsVersion* s_hostVersion = nullptr;
#endif
	};

	enum Win32WinNt
	{
		Win32WinNtNT4 = 0x0400,
		Win32WinNtWIN2K = 0x0500,
		Win32WinNtWINXP = 0x0501,
		Win32WinNtWS03 = 0x0502,
		Win32WinNtWIN6 = 0x0600,
		Win32WinNtVISTA = 0x0600,
		Win32WinNtWS08 = 0x0600,
		Win32WinNtLONGHORN = 0x0600,
		Win32WinNtWIN7 = 0x0601,
		Win32WinNtWIN8 = 0x0602,
		Win32WinNtWINBLUE = 0x0603,
		Win32WinNtWIN10 = 0x0A00,
	};

	enum BuildThreshold
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

	inline bool IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor, DWORD dwBuild)
	{
		auto& g_WinVer = OsVersionInfoExW::CurrentHost();
		if (g_WinVer.dwMajorVersion != 0)
		{
			if (g_WinVer.dwMajorVersion > wMajorVersion)
				return true;
			else if (g_WinVer.dwMajorVersion < wMajorVersion)
				return false;

			if (g_WinVer.dwMinorVersion > wMinorVersion)
				return true;
			else if (g_WinVer.dwMinorVersion < wMinorVersion)
				return false;

			if (g_WinVer.wServicePackMajor > wServicePackMajor)
				return true;
			else if (g_WinVer.wServicePackMajor < wServicePackMajor)
				return false;

			if (g_WinVer.dwBuildNumber >= dwBuild)
				return true;
		}

		return false;
	}

	inline bool IsWindowsXPOrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWINXP), LOBYTE(Win32WinNtWINXP), 0, 0);
	}

	inline bool IsWindowsXPSP1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWINXP), LOBYTE(Win32WinNtWINXP), 1, 0);
	}

	inline bool IsWindowsXPSP2OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWINXP), LOBYTE(Win32WinNtWINXP), 2, 0);
	}

	inline bool IsWindowsXPSP3OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWINXP), LOBYTE(Win32WinNtWINXP), 3, 0);
	}

	inline bool IsWindowsVistaOrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtVISTA), LOBYTE(Win32WinNtVISTA), 0, 0);
	}

	inline bool IsWindowsVistaSP1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtVISTA), LOBYTE(Win32WinNtVISTA), 1, 0);
	}

	inline bool IsWindowsVistaSP2OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtVISTA), LOBYTE(Win32WinNtVISTA), 2, 0);
	}

	inline bool IsWindows7OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN7), LOBYTE(Win32WinNtWIN7), 0, 0);
	}

	inline bool IsWindows7SP1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN7), LOBYTE(Win32WinNtWIN7), 1, 0);
	}

	inline bool IsWindows8OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN8), LOBYTE(Win32WinNtWIN8), 0, 0);
	}

	inline bool IsWindows8Point1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWINBLUE), LOBYTE(Win32WinNtWINBLUE), 0, 0);
	}

	inline bool IsWindows10OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN10), LOBYTE(Win32WinNtWIN10), 0, 0);
	}

	inline bool IsWindows10RS1OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN10), LOBYTE(Win32WinNtWIN10), 0, Build_RS1);
	}

	inline bool IsWindows10RS2OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN10), LOBYTE(Win32WinNtWIN10), 0, Build_RS2);
	}

	inline bool IsWindows10RS3OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN10), LOBYTE(Win32WinNtWIN10), 0, Build_RS3);
	}

	inline bool IsWindows10RS4OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN10), LOBYTE(Win32WinNtWIN10), 0, Build_RS4);
	}

	inline bool IsWindows10RS5OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN10), LOBYTE(Win32WinNtWIN10), 0, Build_RS5);
	}

	inline bool IsWindows10RS6OrGreater()
	{
		return IsWindowsVersionOrGreater(HIBYTE(Win32WinNtWIN10), LOBYTE(Win32WinNtWIN10), 0, Build_RS6);
	}
}

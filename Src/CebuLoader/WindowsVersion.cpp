#include "stdafx.h"
#include "WindowsVersion.h"

namespace FSecure::Loader
{
	WinVersion g_WinVer;

	namespace
	{
		static bool versionInitialized = false;

		void InitVersion()
		{
			if (versionInitialized)
				return;

			g_WinVer.native.dwOSVersionInfoSize = sizeof(g_WinVer.native);

			using fnRtlGetVersion = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOEXW lpVersionInformation);
			auto RtlGetVersion = (fnRtlGetVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
			if (RtlGetVersion)
			{
				RtlGetVersion(&g_WinVer.native);
			}

			if (g_WinVer.native.dwMajorVersion != 0)
			{
				auto fullver = (g_WinVer.native.dwMajorVersion << 8) | g_WinVer.native.dwMinorVersion;
				switch (fullver)
				{
				case Win32WinNtWIN10:
					if (g_WinVer.native.dwBuildNumber >= Build_RS6)
						g_WinVer.ver = Win10_RS6;
					else if (g_WinVer.native.dwBuildNumber >= Build_RS5)
						g_WinVer.ver = Win10_RS5;
					else if (g_WinVer.native.dwBuildNumber >= Build_RS4)
						g_WinVer.ver = Win10_RS4;
					else if (g_WinVer.native.dwBuildNumber >= Build_RS3)
						g_WinVer.ver = Win10_RS3;
					else if (g_WinVer.native.dwBuildNumber >= Build_RS2)
						g_WinVer.ver = Win10_RS2;
					else if (g_WinVer.native.dwBuildNumber >= Build_RS1)
						g_WinVer.ver = Win10_RS1;
					else if (g_WinVer.native.dwBuildNumber >= Build_RS0)
						g_WinVer.ver = Win10;
					break;

				case Win32WinNtWINBLUE:
					g_WinVer.ver = Win8Point1;
					break;

				case Win32WinNtWIN8:
					g_WinVer.ver = Win8;
					break;

				case Win32WinNtWIN7:
					g_WinVer.ver = Win7;
					break;

				case Win32WinNtWINXP:
					g_WinVer.ver = WinXP;
					break;

				default:
					g_WinVer.ver = WinUnsupported;
				}
			}

			g_WinVer.revision = GetRevision();
			versionInitialized = true;
		}
	}

	WinVersion& WinVer()
	{
		InitVersion();
		return g_WinVer;
	}

	bool IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor, DWORD dwBuild)
	{
		auto& g_WinVer = WinVer();
		if (g_WinVer.native.dwMajorVersion != 0)
		{
			if (g_WinVer.native.dwMajorVersion > wMajorVersion)
				return true;
			else if (g_WinVer.native.dwMajorVersion < wMajorVersion)
				return false;

			if (g_WinVer.native.dwMinorVersion > wMinorVersion)
				return true;
			else if (g_WinVer.native.dwMinorVersion < wMinorVersion)
				return false;

			if (g_WinVer.native.wServicePackMajor > wServicePackMajor)
				return true;
			else if (g_WinVer.native.wServicePackMajor < wServicePackMajor)
				return false;

			if (g_WinVer.native.dwBuildNumber >= dwBuild)
				return true;
		}

		return false;
	}

}

#pragma once

#include "../Config.h"
#include "../../WinTools/WindowsVersion.h"
#include <windows.h>
#include <winhttp.h>

namespace FSecure::WinHttp::Detail
{

	// from cpprestsdk
	// Small RAII helper to ensure that the fields of this struct are always
	// properly freed.
	struct ProxyInfo : WINHTTP_PROXY_INFO
	{
		ProxyInfo() { memset(this, 0, sizeof(WINHTTP_PROXY_INFO)); }

		~ProxyInfo()
		{
			if (lpszProxy) ::GlobalFree(lpszProxy);
			if (lpszProxyBypass) ::GlobalFree(lpszProxyBypass);
		}
	};

	// from cpprestsdk
	// Small RAII helper to ensure that the fields of this struct are always
	// properly freed.
	struct IeProxyConfig : WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
	{
		IeProxyConfig() { memset(this, 0, sizeof(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG)); }

		~IeProxyConfig()
		{
			if (lpszAutoConfigUrl) ::GlobalFree(lpszAutoConfigUrl);
			if (lpszProxy) ::GlobalFree(lpszProxy);
			if (lpszProxyBypass) ::GlobalFree(lpszProxyBypass);
		}
	};

	// from cpprestsdk
	/// @returns default proxy constant depending on windows version
	static DWORD WinHttpDefaultProxyConstant() noexcept
	{
#if _WIN32_WINNT >= _WIN32_WINNT_VISTA
#if _WIN32_WINNT < _WIN32_WINNT_WINBLUE
		if (!FSecure::IsWindows8Point1OrGreater())
		{
			// Not Windows 8.1 or later, use the default proxy setting
			return WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
		}
#endif // _WIN32_WINNT < _WIN32_WINNT_WINBLUE

		// Windows 8.1 or later, use the automatic proxy setting
		return WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
#else  // ^^^ _WIN32_WINNT >= _WIN32_WINNT_VISTA ^^^ // vvv _WIN32_WINNT < _WIN32_WINNT_VISTA vvv
		return WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
#endif // _WIN32_WINNT >= _WIN32_WINNT_VISTA
	}
}

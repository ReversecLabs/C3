#pragma once

#include "../Config.h"
#include <windows.h>
#include <winhttp.h>

#include <memory>
#include <string>
#include <stdexcept>

#ifndef OBF
#	define OBF(x) x
#endif

namespace FSecure::WinHttp::Detail
{
	struct InternetHandleDeleter
	{
		void operator()(HINTERNET hinet)
		{
			WinHttpCloseHandle(hinet);
		}
	};

	[[noreturn]] inline void ThrowLastError(std::string const& msg)
	{
		throw std::runtime_error{ msg + " Error code: " + std::to_string(GetLastError()) };
	}
}

namespace FSecure::WinHttp
{
	using HttpHandle = std::unique_ptr<std::remove_pointer_t<HINTERNET>, Detail::InternetHandleDeleter>;

	inline HttpHandle MakeHttpHandle(HINTERNET hinternet, std::string const& err)
	{
		if (!hinternet)
			Detail::ThrowLastError("Failed to open " + err + " handle");

		return HttpHandle{ hinternet };
	}

}

#pragma once

#include "../Config.h"
#include <windows.h>
#include <winhttp.h>

#include <memory>
#include <string>
#include <stdexcept>

namespace FSecure::WinHttp::Detail
{
	/// Deleter for handler acquired from WinHttp
	struct InternetHandleDeleter
	{
		/// Invoke WinHttpCloseHandle
		/// @param handle to close
		void operator()(HINTERNET handle)
		{
			WinHttpCloseHandle(handle);
		}
	};

	/// Throws a runtime error with error code from GetLastError
	/// @param msg - error message
	[[noreturn]] inline void ThrowLastError(std::string const& msg)
	{
		throw std::runtime_error{ msg + " Error code: " + std::to_string(GetLastError()) };
	}
}

namespace FSecure::WinHttp
{
	/// RAII wrapper for HINTERNET handles
	using HttpHandle = std::unique_ptr<std::remove_pointer_t<HINTERNET>, Detail::InternetHandleDeleter>;

	/// Wrap existing HINTERNET handle into owning HttpHandle
	/// @param hinternet handle to wrap
	/// @param handleType - type of handle to wrap, used for error message
	/// @returns HttpHandle that takes ownership of hinternet handle
	inline HttpHandle MakeHttpHandle(HINTERNET hinternet, std::string const& handleType)
	{
		if (!hinternet)
			Detail::ThrowLastError("Failed to open " + handleType + " handle.");

		return HttpHandle{ hinternet };
	}

}

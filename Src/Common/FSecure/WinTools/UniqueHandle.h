#pragma once

namespace FSecure::WinTools
{
	/// Custom std::unique_ptr deleter for WinAPI HANDLEs.
	struct HandleDeleter
	{
		void operator()(void* handle)
		{
			if (!handle)
				return;

			CloseHandle(handle);
			handle = nullptr;
		}
	};
	typedef std::unique_ptr<void, HandleDeleter> UniqueHandle;															///< Useful typedef for WinAPI HANDLE std::unique_ptr.
}

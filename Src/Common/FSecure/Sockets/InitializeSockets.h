#pragma once

namespace FSecure {

	/// wrapper to WSAStartup and WSACleanup
	class InitializeSockets
	{
		// TODO reference counting to avoid unecessary WAS* calls
	public:
		/// Initialize sockets
		/// @throws WinSocketsException
		InitializeSockets() { Initialize(); }

		/// Initialize sockets. Allow copy ctor.
		/// @throws WinSocketsException
		InitializeSockets(InitializeSockets const&) { Initialize(); }

		/// Initialize sockets. Allow copy assignment.
		/// @throws WinSocketsException
		InitializeSockets& operator=(InitializeSockets const&) { Initialize(); return *this; }

		/// Initialize sockets. Allow move ctor.
		/// @throws WinSocketsException
		InitializeSockets(InitializeSockets&&) { Initialize(); }

		/// Initialize sockets. Allow move assignment.
		/// @throws WinSocketsException
		InitializeSockets& operator=(InitializeSockets&&) { Initialize(); return *this; }

		/// Dtor. Deinitialize sockets.
		~InitializeSockets() noexcept { Deinitialize(); }

	private:
		/// Initialize sockets. Effectively calls WSAStartup
		/// @throws WinSocketsException
		static void Initialize();

		/// Initialize sockets. Effectively calls WSACleanup
		/// @note ignores errors, because called in destructor.
		static void Deinitialize() noexcept;
	};
}

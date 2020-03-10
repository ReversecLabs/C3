#pragma once

#include "AddrInfo.h"
#include "Common/FSecure/CppTools/ByteVector.h"

namespace FSecure
{
	/// Socket wrapper
	/// @note user has to call WSAStartup;
	struct Socket
	{
		/// Create an invalid socket
		Socket() noexcept = default;

		/// Create a socket with addrinfo
		/// @throws WinSocketsException
		Socket(const AddrInfo& addrinfo);

		/// Close socket
		~Socket() noexcept;

		/// Disallow copying
		Socket(const Socket&) = delete;

		/// Disallow copying
		Socket& operator=(const Socket&) = delete;

		/// Allow move
		Socket(Socket&& other) noexcept;

		/// Allow move
		Socket& operator=(Socket&& other) noexcept;

		/// Check if socket is in valid state
		/// @return false if underlying SOCKET is in INVALID_SOCKET state
		operator bool() const noexcept;

		/// Send data through socket. Prefixes the data with its length (4 bytes, network order)
		/// @param data to send
		/// @throws SocketsException
		void Send(ByteVector const& data);

		/// Receive data from socket. Data must be prefixed with its length (4 bytes, network order)
		/// @returns ByteVector - received data. Empty if connection has been closed gracefully.
		/// @throws SocketsException
		ByteVector Receive();

		/// bind wrapper
		/// @param addrinfo to bind socket to
		/// @throws SocketsException
		void Bind(const AddrInfo& addrinfo);

		/// connect wrapper for TCP/IPv4
		/// @param addr - remote IPv4 address (TODO support for IPv6)
		/// @param port - remote port
		/// @throws SocketsException
		void Connect(std::string_view addr, uint16_t port);

		/// listen wrapper
		/// @param maxconn - maximum number of connections in queue to accept
		/// @throws SocketsException
		void Listen(int maxconn = 1);

		/// accept wrapper
		/// @return Socket bound to accepted connection
		/// @throws SocketsException
		Socket Accept();

		/// Has socket received data
		/// @throws SocketsException
		bool HasReceivedData();

	private:
		/// Wrap and take ownership of given socket
		/// @param socket - socket to wrap
		Socket(SOCKET socket) : m_Socket(socket) {}

		/// Underlying handle
		SOCKET m_Socket = INVALID_SOCKET;
	};


	/// Wrapper for TCP client socket
	class ClientSocket
	{
	public:
		/// Create a TCP client socket
		/// @param addr remote address to connect to
		/// @param port remote port
		/// @throws WinSocketsException
		ClientSocket(std::string_view addr, uint16_t port);

		/// Send data through socket. Prefixes the data with its length (4 bytes, network order)
		/// @param data to send
		/// @throws WinSocketsException
		void Send(ByteVector const& data) { m_Socket.Send(data); }

		/// Receive data from socket. Data must be prefixed with its length (4 bytes, network order)
		/// @returns ByteVector - received data. Empty if connection has been closed gracefully.
		/// @throws WinSocketsException
		ByteVector Receive() { return m_Socket.Receive(); }

		/// Has socket received data
		/// @throws SocketsException
		bool HasReceivedData() { return m_Socket.HasReceivedData(); }

	private:
		Socket m_Socket;
	};


	/// Wrapper for TCP server socket
	struct ServerSocket
	{
		/// Create a TCP server socket bound to specific host IP
		/// @param addr - listening IP address
		/// @param port - listening port
		/// @throws WinSocketsException
		ServerSocket(std::string_view addr, uint16_t port);

		/// Create a TCP server socket on
		/// @param port - listening port
		/// @throws WinSocketsException
		ServerSocket(uint16_t port);

		/// accept wrapper
		/// @return Socket bound to accepted connection
		/// @throws WinSocketsException
		Socket Accept() { return m_ListeningSocket.Accept(); }

	private:
		AddrInfo m_Addrinfo;
		Socket m_ListeningSocket;
	};
}

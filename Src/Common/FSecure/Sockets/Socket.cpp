#include "StdAfx.h"
#include "Socket.h"
#include "SocketsException.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Socket::Socket(const AddrInfo& addrinfo)
{
	if (m_Socket = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol); m_Socket == INVALID_SOCKET)
		throw SocketsException(OBF("Failed to create socket. Error: ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Socket::~Socket() noexcept
{
	if (m_Socket != INVALID_SOCKET)
		closesocket(m_Socket);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Socket::Socket(Socket&& other) noexcept
{
	m_Socket = other.m_Socket;
	other.m_Socket = INVALID_SOCKET;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Socket& FSecure::Socket::operator=(Socket&& other) noexcept
{
	m_Socket = other.m_Socket;
	other.m_Socket = INVALID_SOCKET;
	return *this;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Socket::operator bool() const noexcept
{
	return m_Socket != INVALID_SOCKET;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::Socket::Send(ByteVector const& data)
{
	// First send the 4-byte (network order) length of chunk.
	uint32_t size = htonl(static_cast<uint32_t>(data.size()));
	if (SOCKET_ERROR == send(m_Socket, reinterpret_cast<const char*>(&size), sizeof(size), 0))
		throw FSecure::SocketsException(OBF("Error sending to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());

	// Write the chunk to socket.
	if (SOCKET_ERROR == send(m_Socket, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0))
		throw FSecure::SocketsException(OBF("Error sending to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Socket::Receive()
{
	// First read the 4-byte (network order) length of chunk.
	uint32_t chunkLength = 0;
	int bytesRead;
	if (bytesRead = recv(m_Socket, reinterpret_cast<char*>(&chunkLength), 4, 0); bytesRead == SOCKET_ERROR)
		throw FSecure::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());

	uint32_t length = ntohl(chunkLength);
	if (!bytesRead or !length)
		return {};															//< The connection has been gracefully closed.

	// Read in the result.
	ByteVector buffer;
	buffer.resize(length);
	for (DWORD bytesReadTotal = 0; bytesReadTotal < length; bytesReadTotal += bytesRead)
		switch (bytesRead = recv(m_Socket, reinterpret_cast<char *>(&buffer[bytesReadTotal]), length - bytesReadTotal, 0))
		{
		case 0:
			return {};															//< The connection has been gracefully closed.

		case SOCKET_ERROR:
			throw FSecure::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
		}
	return buffer;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::Socket::Bind(const AddrInfo& addrinfo)
{
	// Setup the TCP listening socket
	if (bind(m_Socket, addrinfo->ai_addr, static_cast<int>(addrinfo->ai_addrlen)))
		throw SocketsException(OBF("bind failed with error: ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::Socket::Connect(std::string_view addr, uint16_t port)
{
	// TODO IPv6 support
	sockaddr_in tsClient;
	tsClient.sin_family = AF_INET;
	tsClient.sin_port = htons(port);

	switch (inet_pton(AF_INET, addr.data(), &tsClient.sin_addr.s_addr))
	{
	case 0:
		throw std::invalid_argument(OBF("Provided address in not a valid IPv4 dotted - decimal string"));
	case -1:
		throw FSecure::SocketsException(OBF("Couldn't convert standard text IPv4 address into its numeric binary form. Error code : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
	}

	// Attempt to connect.
	if (INVALID_SOCKET == (m_Socket = socket(AF_INET, SOCK_STREAM, 0)))
		throw FSecure::SocketsException(OBF("Couldn't create socket. Error code : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());

	if (SOCKET_ERROR == connect(m_Socket, reinterpret_cast<const sockaddr*>(&tsClient), sizeof(tsClient)))
		throw FSecure::SocketsException(OBF("Could not connect to ") + std::string{ addr } +OBF(":") + std::to_string(port) + OBF(". Error code : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::Socket::Listen(int maxconn)
{
	if (listen(m_Socket, 1) == SOCKET_ERROR)
		throw FSecure::SocketsException(OBF("listen failed. Error code: ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Socket FSecure::Socket::Accept()
{
	SOCKET clientSocket = accept(m_Socket, nullptr, nullptr);
	if (clientSocket == INVALID_SOCKET)
		throw FSecure::SocketsException(OBF("accept failed. Error code : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
	return clientSocket;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool FSecure::Socket::HasReceivedData()
{
	pollfd xx{ m_Socket, POLLRDNORM, 0};
	auto ret = WSAPoll(&xx, /* one socket on list */ 1, /* return immediately*/ 0);
	if (ret == SOCKET_ERROR)
	{
		auto errCode = WSAGetLastError();
		throw SocketsException(OBF("Failed to poll socket. Error code: ") + std::to_string(errCode) + OBF("."), errCode);
	}
	else if (ret)
	{
		auto revent = xx.revents;
		if (revent & POLLRDNORM)
			return true;
		if (revent & POLLHUP)
			throw SocketsException(OBF("Connection aborted"), 0);
		if (revent & POLLERR)
			throw SocketsException(OBF("Unknown error occurred"), 0);
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ClientSocket::ClientSocket(std::string_view addr, uint16_t port)
	: m_Socket{ AddrInfo{ addr, std::to_string(port).c_str() } }
{
	m_Socket.Connect(addr, port);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ServerSocket::ServerSocket(std::string_view addr, uint16_t port)
	: m_Addrinfo(addr, port)
	, m_ListeningSocket(m_Addrinfo)
{
	m_ListeningSocket.Bind(m_Addrinfo);
	m_ListeningSocket.Listen();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ServerSocket::ServerSocket(uint16_t port)
	: ServerSocket("", port)
{
}

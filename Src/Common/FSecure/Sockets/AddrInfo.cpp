#include "StdAfx.h"
#include "AddrInfo.h"
#include "SocketsException.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::AddrInfo::AddrInfo(std::string_view host, std::string_view service, int flags, int family, int socktype, int protocol)
{
	addrinfo hints{ flags, family, socktype, protocol };
	addrinfo* result{};
	// Resolve the local address and port to be used by the server
	if (auto err = getaddrinfo(host.data(), service.data(), &hints, &result))
		throw SocketsException(OBF("getaddrinfo failed"), err);
	m_Addrinfo = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>(result, &freeaddrinfo);
}

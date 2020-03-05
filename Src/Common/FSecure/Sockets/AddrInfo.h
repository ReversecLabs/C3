#pragma once

namespace FSecure
{
	/// Wrapper to struct addrinfo
	/// @note user has to call WSAStartup;
	class AddrInfo
	{
	public:
		/// getaddrinfo wrapper
		/// @throws WinSocketsException
		AddrInfo(std::string_view host, std::string_view service, int flags = AI_PASSIVE, int family = AF_INET, int socktype = SOCK_STREAM, int protocol = IPPROTO_TCP);

		/// getaddrinfo wrapper for IPv4/TCP
		/// @throws WinSocketsException
		AddrInfo(std::string_view host, uint16_t port) : AddrInfo(host, std::to_string(port)) {};

		/// Accesses the underlying addrinfo
		/// @return underlying addrinfo struct
		const addrinfo* operator->() const noexcept { return m_Addrinfo.get(); }

	private:
		std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> m_Addrinfo{ nullptr, &freeaddrinfo };
	};
}

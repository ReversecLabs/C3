#pragma once

#include "HttpHandle.h"
#include "HttpRequestHandle.h"

namespace FSecure::WinHttp
{
	/// RAII wrapper for connection handle
	class HttpConnection
	{
	public:
		/// Create empty handle
		HttpConnection() = default;

		/// Create a connection handle on default HTTPS/HTTP port
		/// Effectively calls WinHttpConnect
		/// @param session native handle
		/// @param hostName - hostname to create connection to
		/// @param useHttps - true if connection should use HTTPS, false for plain HTTP
		/// @throws std::runtime error if handle can't be aquired
		HttpConnection(HINTERNET session, std::wstring const& hostName, bool useHttps = true)
			: HttpConnection(session, hostName, useHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, useHttps)
		{
		}

		/// Create a connection handle on custom port
		/// Effectively calls WinHttpConnect
		/// @param session native handle
		/// @param hostName - hostname to create connection to
		/// @param port - port to connect to
		/// @param useHttps - true if connection should use HTTPS, false for plain HTTP
		/// @throws std::runtime error if handle can't be aquired
		HttpConnection(HINTERNET session, std::wstring const& hostName, uint16_t port, bool useHttps)
			: m_UseHttps(useHttps)
			, m_ConnectionHandle{ MakeHttpHandle(WinHttpConnect(session, hostName.c_str(), port, 0), OBF("Connection")) }
		{
		}

		/// Create a request handle
		/// Effectively calls WinHttpOpenRequest
		/// @param method - HTTP method
		/// @param path - path part of URL (optionally with query)
		/// @throws std::runtime error if handle can't be aquired
		HttpRequestHandle OpenRequest(std::wstring const& method, std::wstring const& path)
		{
			return HttpRequestHandle(m_ConnectionHandle.get(), method, path, m_UseHttps);
		}

	private:
		bool m_UseHttps = true;
		HttpHandle m_ConnectionHandle;
	};
}

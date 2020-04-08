#pragma once

#include "HttpHandle.h"
#include "HttpRequestHandle.h"

namespace FSecure::WinHttp
{
	class HttpConnection
	{
	public:
		HttpConnection() = default;

		HttpConnection(HINTERNET httpHandle, std::wstring const& hostName, bool useHttps = true)
			: HttpConnection(httpHandle, hostName, useHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, useHttps)
		{
		}

		HttpConnection(HINTERNET httpHandle, std::wstring const& hostName, uint16_t port, bool useHttps)
			: m_UseHttps(useHttps)
			, m_ConnectionHandle{ MakeHttpHandle(WinHttpConnect(httpHandle, hostName.c_str(), port, 0), OBF("Connection")) }
		{
		}

		HttpRequestHandle OpenRequest(std::wstring const& method, std::wstring const& endpoint)
		{
			return HttpRequestHandle(m_ConnectionHandle.get(), method, endpoint, m_UseHttps);
		}

	private:
		bool m_UseHttps = true;
		HttpHandle m_ConnectionHandle;
	};
}
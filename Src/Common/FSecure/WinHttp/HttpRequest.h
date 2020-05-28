#pragma once

#include "Constants.h"

#include <vector>
#include <map>
#include <chrono>
#include <optional>

namespace FSecure::WinHttp
{
	/// Helper to prepare HTTP requests with HttpClient
	class HttpRequest
	{
	public:
		/// Create a HttpRequest
		/// @param method - optional (defaults to GET) HTTP method
		/// @param path - path(optionally with query) to HTTP resource
		/// @param contentType - HTTP body content type
		/// @param data - HTTP request body
		/// @param resolveTimeout - timeout for name resolution
		/// @param connectTimeout - timeout for server connection requests
		/// @param sendTimeout - timeout for sending requests
		/// @param receiveTimeout - timeout to receive a response to a request
		/// @note Providing zero as timeout means no timeout (infinite)
		HttpRequest(
			Method method = Method::GET,
			std::wstring path = L"",
			std::wstring contentType = L"",
			std::vector<uint8_t> data = {},
			std::chrono::milliseconds resolveTimeout = 0s,
			std::chrono::milliseconds connectTimeout = 60s,
			std::chrono::milliseconds sendTimeout = 30s,
			std::chrono::milliseconds receiveTimeout = 30s
		) noexcept
			: m_Method(method)
			, m_Path(std::move(path))
			, m_ContentType(std::move(contentType))
			, m_Data(std::move(data))
			, m_ResolveTimeout(resolveTimeout)
			, m_ConnectTimeout(connectTimeout)
			, m_SendTimeout(sendTimeout)
			, m_ReceiveTimeout(receiveTimeout)
		{
		}

		/// Set content type and body
		/// @param content type
		/// @param request body data
		void SetData(ContentType contentType, std::vector<uint8_t> data) noexcept
		{
			SetData(GetContentType(contentType), data);
		}

		/// Set content type and body
		/// @param content type
		/// @param request body data
		void SetData(std::wstring contentType, std::vector<uint8_t> data) noexcept
		{
			m_ContentType = std::move(contentType);
			m_Data = std::move(data);
		}

		/// Set request header value
		/// @param header name
		/// @param header content
		void SetHeader(Header header, std::wstring headerContent) noexcept
		{
			SetHeader(GetHeaderName(header), headerContent);
		}

		/// Set request header value
		/// @param header name
		/// @param header content
		void SetHeader(std::wstring headerName, std::wstring headerContent) noexcept
		{
			m_Headers[headerName] = headerContent;
		}

		/// Sets timeouts involved with HTTP transactions.
		/// Providing zero as timeout means no timeout (infinite).
		/// Providing empty optional means no change for previously set timeout.
		/// @param resolveTimeout - timeout for name resolution
		/// @param connectTimeout - timeout for server connection requests
		/// @param sendTimeout - timeout for sending requests
		/// @param receiveTimeout - timeout to receive a response to a request
		void SetTimeout(
			std::optional<std::chrono::milliseconds> resolveTimeout,
			std::optional<std::chrono::milliseconds> connectTimeout = {},
			std::optional<std::chrono::milliseconds> sendTimeout = {},
			std::optional<std::chrono::milliseconds> receiveTimeout = {}
		) noexcept
		{
			if (resolveTimeout) m_ResolveTimeout = *resolveTimeout;
			if (connectTimeout) m_ConnectTimeout = *connectTimeout;
			if (sendTimeout) m_SendTimeout = *sendTimeout;
			if (receiveTimeout) m_ReceiveTimeout = *receiveTimeout;
		}

		Method m_Method;
		std::wstring m_Path;
		std::wstring m_ContentType;
		std::vector<uint8_t> m_Data;
		std::map<std::wstring, std::wstring> m_Headers;
		std::chrono::milliseconds m_ResolveTimeout, m_ConnectTimeout, m_SendTimeout, m_ReceiveTimeout;
	};
}

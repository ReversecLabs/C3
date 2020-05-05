#pragma once

#include "Constants.h"

#include <vector>
#include <map>

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
		HttpRequest(Method method = Method::GET, std::wstring path = L"", std::wstring contentType = L"", std::vector<uint8_t> data = {}) noexcept
			: m_Method(method)
			, m_Path(std::move(path))
			, m_ContentType(std::move(contentType))
			, m_Data(std::move(data))
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

		Method m_Method;
		std::wstring m_Path;
		std::wstring m_ContentType;
		std::vector<uint8_t> m_Data;
		std::map<std::wstring, std::wstring> m_Headers;
	};
}

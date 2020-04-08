#pragma once

#include "Constants.h"

#include <map>

namespace FSecure::WinHttp
{
	class HttpRequest
	{
	public:
		HttpRequest(Method method = Method::GET, std::wstring path = L"", std::wstring contentType = L"", std::vector<uint8_t> data = {})
			: m_Method(method)
			, m_Path(std::move(path))
			, m_ContentType(std::move(contentType))
			, m_Data(std::move(data))
		{
		}

		void SetData(ContentType contentType, std::vector<uint8_t> data)
		{
			SetData(GetContentType(contentType), data);
		}

		void SetData(std::wstring contentType, std::vector<uint8_t> data)
		{
			m_ContentType = std::move(contentType);
			m_Data = std::move(data);
		}

		void SetHeader(Header header, std::wstring headerContent)
		{
			SetHeader(GetHeaderName(header), headerContent);
		}

		void SetHeader(std::wstring headerName, std::wstring headerContent)
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

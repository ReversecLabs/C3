#pragma once

#include "../Config.h"

#include "HttpHandle.h"
#include "HttpResponse.h"
#include "../Constants.h"

#include <stdexcept>

namespace FSecure::WinHttp
{
	class HttpRequestHandle
	{
	public:
		HttpRequestHandle() = default;

		HttpRequestHandle(HINTERNET connection, std::wstring const& mehtod, std::wstring const& endpoint, bool useHttps = true)
		{
			m_RequestHandle = MakeHttpHandle(WinHttpOpenRequest(connection, mehtod.c_str(), endpoint.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, useHttps ? WINHTTP_FLAG_SECURE : 0), OBF("Request"));
		}

		void SetHeader(Header header, std::wstring const& headerData)
		{
			SetHeader(GetHeaderName(header), headerData);
		}

		void SetHeader(std::wstring const& headerName, std::wstring const& headerData)
		{
			auto fullHeader = headerName + L": " + headerData;
			// make sure header ends with CRLF
			auto twoLastChars = std::wstring_view{ fullHeader.data() + fullHeader.length() - 2, 2};
			if (twoLastChars != L"\r\n")
				fullHeader += L"\r\n";
			if (fullHeader.size() > std::numeric_limits<DWORD>::max())
				throw std::runtime_error{OBF("Header too long")};
			WinHttpAddRequestHeaders(m_RequestHandle.get(), fullHeader.data(), static_cast<DWORD>(fullHeader.length()), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
		}

		void SetProxy(WINHTTP_PROXY_INFO& info)
		{
			if (WinHttpSetOption(m_RequestHandle.get(), WINHTTP_OPTION_PROXY, &info, sizeof(WINHTTP_PROXY_INFO)))
				Detail::ThrowLastError(OBF("Set proxy option"));
		}

		void Send(ContentType contentType, std::vector<uint8_t> const& data)
		{
			Send(GetContentType(contentType), data);
		}

		void Send(std::wstring const& contentType = L"", std::vector<uint8_t> const& data = {})
		{
			if (data.size() > std::numeric_limits<DWORD>::max())
				throw std::runtime_error{ OBF("Failed to send over 4GB of data (not implemented)") };
			auto dataSize = static_cast<DWORD>(data.size());

			if (contentType.length())
				SetHeader(Header::ContentType, contentType);

			auto xdata = data.size() ? data.data() : nullptr;
			auto result = WinHttpSendRequest(m_RequestHandle.get(), nullptr, 0, const_cast<uint8_t*>(xdata), dataSize, dataSize, NULL);
			if (!result)
				Detail::ThrowLastError(OBF("SendRequest failed"));
		}

		HttpResponse ReceiveResponse()
		{
			auto result = WinHttpReceiveResponse(m_RequestHandle.get(), NULL);
			if (!result)
				Detail::ThrowLastError(OBF("ReceiveRespones failed"));

			return { std::move(m_RequestHandle) };
		}

	private:
		HttpHandle m_RequestHandle;
	};
}

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
		/// Create empty handle
		HttpRequestHandle() = default;

		/// Create a request handle
		/// Effectively calls WinHttpOpenRequest
		/// @param connection native handle
		/// @param method - HTTP method
		/// @param path - path part of URL (optionally with query)
		/// @param useHttps - true if request should use HTTPS, false for plain HTTP, must be consistent with options used to open connection handle
		/// @throws std::runtime error if handle can't be aquired
		HttpRequestHandle(HINTERNET connection, std::wstring const& mehtod, std::wstring const& path, bool useHttps = true)
		{
			m_RequestHandle = MakeHttpHandle(WinHttpOpenRequest(connection, mehtod.c_str(), path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, useHttps ? WINHTTP_FLAG_SECURE : 0), OBF("Request"));
		}

		/// Set request header
		/// @param header - one of knows header names
		/// @param headerData - header data
		/// @throws std::runtime_error if header lenght exceeds 4GB
		void SetHeader(Header header, std::wstring const& headerData)
		{
			SetHeader(GetHeaderName(header), headerData);
		}

		/// Set request header
		/// @param header - header name
		/// @param headerData - header data
		/// @throws std::runtime_error if header lenght exceeds 4GB
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

		/// Set proxy for request
		/// @param info - native proxy info
		/// @throws std::runtime_error if proxy setting fails
		void SetProxy(WINHTTP_PROXY_INFO& info)
		{
			if (WinHttpSetOption(m_RequestHandle.get(), WINHTTP_OPTION_PROXY, &info, sizeof(WINHTTP_PROXY_INFO)))
				Detail::ThrowLastError(OBF("Set proxy option"));
		}

		/// Send request
		/// Effectively calls WinHttpSendRequest
		/// @param contentType - one of knows content types
		/// @param data - data to send
		/// @throws std::runtime_error if data size exceeds 4GB (not supported), or sending fails
		void Send(ContentType contentType, std::vector<uint8_t> const& data)
		{
			Send(GetContentType(contentType), data);
		}

		/// Send request
		/// Effectively calls WinHttpSendRequest
		/// @param contentType - content type of data
		/// @param data - data to send
		/// @throws std::runtime_error if data size exceeds 4GB (not supported), or sending fails
		void Send(std::wstring const& contentType = L"", std::vector<uint8_t> const& data = {})
		{
			if (data.size() > std::numeric_limits<DWORD>::max())
				throw std::runtime_error{ OBF("Failed to send over 4GB of data (not implemented)") };
			auto dataSize = static_cast<DWORD>(data.size());

			if (contentType.length())
				SetHeader(Header::ContentType, contentType);

			auto xdata = data.size() ? data.data() : nullptr;
			if (!WinHttpSendRequest(m_RequestHandle.get(), nullptr, 0, const_cast<uint8_t*>(xdata), dataSize, dataSize, NULL))
				Detail::ThrowLastError(OBF("SendRequest failed"));
		}

		/// Receive request response
		/// Transfers ownership of handle to returned HttpResponse
		/// Effectively calls WinHttpReceiveResponse
		/// @returns HttpResponse owning handle
		/// @throws std::runtime_error if receiving fails
		HttpResponse ReceiveResponse()
		{
			if (!WinHttpReceiveResponse(m_RequestHandle.get(), NULL))
				Detail::ThrowLastError(OBF("ReceiveRespones failed"));

			return { std::move(m_RequestHandle) };
		}

	private:
		HttpHandle m_RequestHandle;
	};
}

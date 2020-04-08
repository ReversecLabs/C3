#pragma once

#include "../Config.h"
#include "HttpHandle.h"
#include "../../CppTools/ByteConverter/ByteVector.h"

namespace FSecure::WinHttp
{
	class HttpResponse
	{
	public:
		HttpResponse(HttpHandle requestHandle)
			: m_RequestHandle{ std::move(requestHandle) }
		{
		}

		uint32_t GetStatusCode() const
		{
			if (!m_StatusCode)
				ReadStatusCode();

			return m_StatusCode;
		}

		std::wstring GetHeader(std::wstring const& headerName) const
		{
			DWORD dwSize = 0;
			WinHttpQueryHeaders(m_RequestHandle.get(), WINHTTP_QUERY_CUSTOM, headerName.c_str(), WINHTTP_NO_OUTPUT_BUFFER, &dwSize, WINHTTP_NO_HEADER_INDEX);
			if (dwSize == 0)
				return {};

			// Allocate memory for the buffer.
			std::wstring header = std::wstring(dwSize, '\0');

			// Now, use WinHttpQueryHeaders to retrieve the header.
			if (!WinHttpQueryHeaders(m_RequestHandle.get(), WINHTTP_QUERY_CUSTOM, headerName.c_str(), header.data(), &dwSize, WINHTTP_NO_HEADER_INDEX))
				Detail::ThrowLastError(OBF("Retrieve headers"));

			return header;
		}

		std::wstring GetHeaders() const
		{
			if (!m_Headers.length())
				ReceiveHeaders();

			return m_Headers;
		}

		ByteVector GetData() const
		{
			if (!m_Data.size())
				ReceiveData();

			return m_Data;
		}

	private:
		void ReadStatusCode() const
		{
			DWORD dwSize = sizeof(m_StatusCode);
			if (!WinHttpQueryHeaders(m_RequestHandle.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &m_StatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX))
				Detail::ThrowLastError(OBF("Read Status"));
		}

		void ReceiveHeaders() const
		{
			// Retrieve size of headers
			DWORD dwSize = 0;
			WinHttpQueryHeaders(m_RequestHandle.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &dwSize, WINHTTP_NO_HEADER_INDEX);

			// Allocate memory for the buffer.
			m_Headers.resize(dwSize / sizeof(WCHAR));
			// Now, use WinHttpQueryHeaders to retrieve the header.
			if (!WinHttpQueryHeaders(m_RequestHandle.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, m_Headers.data(), &dwSize, WINHTTP_NO_HEADER_INDEX))
				Detail::ThrowLastError(OBF("Retrieve headers"));
		}

		void ReceiveData() const
		{
			DWORD dwSize;
			do
			{
				// Check for available data.
				dwSize = 0;
				if (!WinHttpQueryDataAvailable(m_RequestHandle.get(), &dwSize))
					Detail::ThrowLastError(OBF("WinHttpQueryDataAvailable"));

				// No more available data.
				if (!dwSize)
					break;

				// Allocate space for the buffer.
				ByteVector tmp;
				tmp.resize(dwSize);

				DWORD dwDownloaded;
				if (!WinHttpReadData(m_RequestHandle.get(), tmp.data(), dwSize, &dwDownloaded))
					Detail::ThrowLastError(OBF("Error in WinHttpReadData"));

				// This condition should never be reached since WinHttpQueryDataAvailable
				// reported that there are bits to read.
				if (!dwDownloaded)
					break;

				m_Data.Concat(tmp);

			} while (dwSize > 0);
		}

		HttpHandle m_RequestHandle;
		mutable uint32_t m_StatusCode = 0;
		mutable std::wstring m_Headers;
		mutable ByteVector m_Data;
	};
}
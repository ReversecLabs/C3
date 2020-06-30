#pragma once

#include "../Config.h"
#include "HttpHandle.h"
#include "../Constants.h"
#include "../../CppTools/ByteConverter/ByteVector.h"

namespace FSecure::WinHttp
{
	class HttpResponse
	{
	public:
		/// Create response handle
		/// @param requestHadle - a request corresponding to this response
		HttpResponse(HttpHandle requestHandle)
			: m_RequestHandle{ std::move(requestHandle) }
		{
		}

		/// Get HTTP status code
		/// @returns response HTTP status code
		/// @throws std::runtime_error if status code cannot be retreived
		uint32_t GetStatusCode() const
		{
			if (!m_StatusCode)
				ReadStatusCode();

			return m_StatusCode;
		}

		/// Get HTTP header value
		/// @param header - one of known HTTP headers to retrieve
		/// @returns HTTP header value
		/// @throws std::runtime_error if header value cannot be retreived
		std::wstring GetHeader(Header header) const
		{
			return GetHeader(GetHeaderName(header));
		}

		/// Get HTTP header value
		/// @param headerName - name of HTTP header to retrieve
		/// @returns HTTP header value
		/// @throws std::runtime_error if header value cannot be retreived
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

		/// Get all HTTP headers
		/// @returns All HTTP headers
		/// @throws std::runtime_error if headers cannot be retreived
		std::wstring GetHeaders() const
		{
			if (!m_Headers.length())
				ReceiveHeaders();

			return m_Headers;
		}

		/// Get HTTP response body
		/// @returns HTTP response body
		/// @throws std::runtime_error if response body cannot be retreived
		template <typename T = ByteView>
		std::enable_if_t<!std::is_reference_v<T>, T> GetData() const&
		{
			return GetDataInternal();
		}

		/// Get HTTP response body
		/// @returns HTTP response body
		/// @throws std::runtime_error if response body cannot be retreived
		template <typename T = ByteVector>
		std::enable_if_t<!std::is_reference_v<T>, T> GetData() const&&
		{
			return  GetDataInternal();
		}

		/// Get HTTP response body
		/// @param c callable object used to obtain data.
		/// @returns HTTP response body
		/// @throws std::runtime_error if response body cannot be retreived
		template <typename Callable>
		auto GetData(Callable c) const
		{
			return c(GetDataInternal());
		}

	private:
		/// Get HTTP response body.
		/// @returns HTTP response body
		/// @throws std::runtime_error if response body cannot be retreived
		ByteView GetDataInternal() const
		{
			if (!m_Data.size())
				ReceiveData();

			return m_Data;
		}
		/// Read status code from HTTP response
		/// @throws std::runtime_error if status code cannot be retreived
		void ReadStatusCode() const
		{
			DWORD dwSize = sizeof(m_StatusCode);
			if (!WinHttpQueryHeaders(m_RequestHandle.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &m_StatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX))
				Detail::ThrowLastError(OBF("Read Status"));
		}

		/// Receive repoonse HTTP headers
		/// @throws std::runtime_error if headers cannot be retreived
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

		/// Receive response HTTP body
		/// @throws std::runtime_error if response body cannot be retreived
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

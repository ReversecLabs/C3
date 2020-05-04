#pragma once

#include "Config.h"
#include "Handles/HttpHandle.h"
#include "../CppTools/ByteConverter/ByteView.h"
#include <windows.h>
#include <winhttp.h>
#include <shlwapi.h>

namespace FSecure::WinHttp::Detail
{
	// copy from cpprestsdk
	inline static  bool is_unreserved(int c)
	{
		return ::isalnum((char)c) || c == '-' || c == '.' || c == '_' || c == '~';
	}

	// copy from cpprestsdk with modified template params
	template<class T, class F>
	static std::string encode_impl(T const& raw, F should_encode)
	{
		const char* const hex = "0123456789ABCDEF";
		std::string encoded;
		for (auto iter = raw.begin(); iter != raw.end(); ++iter)
		{
			// for utf8 encoded string, char ASCII can be greater than 127.
			int ch = static_cast<unsigned char>(*iter);
			// ch should be same under both utf8 and utf16.
			if (should_encode(ch))
			{
				encoded.push_back('%');
				encoded.push_back(hex[(ch >> 4) & 0xF]);
				encoded.push_back(hex[ch & 0xF]);
			}
			else
			{
				// ASCII don't need to be encoded, which should be same on both utf8 and utf16.
				encoded.push_back((char)ch);
			}
		}
		return encoded;
	}
}

namespace FSecure::WinHttp
{
	/// URI utilities
	class Uri
	{
	public:
		/// create a empty URI
		Uri() = default;

		/// Parse URI from string
		/// @param uri - URI string
		/// @throws std::runtime_error if URI cannot be parsed from stirng
		Uri(const wchar_t* uri)
		{
			if (!Uri::IsValid(uri))
				throw std::runtime_error("Invalid URI:");

			m_FullUri = uri;
			URL_COMPONENTS urlComp{ sizeof(urlComp) };

			// Set required component lengths to non-zero
			// so that they are cracked.
			urlComp.dwSchemeLength = (DWORD)-1;
			urlComp.dwHostNameLength = (DWORD)-1;
			urlComp.dwUrlPathLength = (DWORD)-1;
			urlComp.dwUserNameLength = (DWORD)-1;
			urlComp.dwPasswordLength = (DWORD)-1;
			urlComp..dwExtraInfoLength = (DWORD)-1;

			if (!WinHttpCrackUrl(uri, 0, 0, &urlComp))
				Detail::ThrowLastError(OBF("Error in WinHttpCrackUrl."));

			m_UseHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
			m_Port = urlComp.nPort;
			m_HostName = std::wstring{ std::wstring_view{urlComp.lpszHostName, urlComp.dwHostNameLength} };
			std::wstring pathAndQuery = urlComp.lpszUrlPath;
			m_PathWithQuery = std::wstring{ std::wstring_view{ pathAndQuery.c_str(), pathAndQuery.length()} };
		}

		/// Parse URI from string
		/// @param uri - URI string
		/// @throws std::runtime_error if URI cannot be parsed from stirng
		Uri(std::wstring const& uri) : Uri(uri.c_str())
		{
		}

		/// Check if string is a valid URI
		/// @return true if string is a valid URI
		static bool IsValid(const wchar_t* uri)
		{
			return PathIsURLW(uri);
		}

		/// Encode binary data to URI format
		/// @param raw data to encode
		/// @returns encoded data
		static std::string EncodeData(ByteView raw)
		{
			return Detail::encode_impl(raw, [](int ch) -> bool { return !Detail::is_unreserved(ch); });
		}

		/// @returns true if URI specifies https
		bool UseHttps() const { return m_UseHttps; }

		/// @returns full URI string
		std::wstring const& GetFullUri() const noexcept { return m_FullUri; }

		/// @returns host name specified in URI
		std::wstring const& GetHostName() const noexcept { return m_HostName; }

		/// @returns port number specified in URI
		uint16_t GetPort() const noexcept { return m_Port; }

		/// @returns true if port number is default to respective protocol
		bool IsPortDefault() const noexcept { return (m_UseHttps && m_Port == INTERNET_DEFAULT_HTTPS_PORT) || (!m_UseHttps && m_Port == INTERNET_DEFAULT_HTTP_PORT); }

		/// @returns path with query specified in URI
		std::wstring const& GetPathWithQuery() const { return m_PathWithQuery; }

	private:
		bool m_UseHttps = false;
		uint16_t m_Port = 0;
		std::wstring m_FullUri;
		std::wstring m_HostName;
		std::wstring m_PathWithQuery;
	};
}

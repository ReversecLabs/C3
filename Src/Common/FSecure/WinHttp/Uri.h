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
	class Uri
	{
	public:
		Uri() = default;

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

			if (!WinHttpCrackUrl(uri, 0, 0, &urlComp))
				Detail::ThrowLastError(OBF("Error in WinHttpCrackUrl."));

			m_UseHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
			m_Port = urlComp.nPort;
			m_HostName = std::wstring{ std::wstring_view{urlComp.lpszHostName, urlComp.dwHostNameLength} };
			m_PathWithQuery = std::wstring{ std::wstring_view{urlComp.lpszUrlPath, urlComp.dwUrlPathLength} };
		}

		Uri(std::wstring const& uri) : Uri(uri.c_str())
		{
		}

		static bool IsValid(const wchar_t* uri)
		{
			return PathIsURLW(uri);
		}

		static std::string EncodeData(ByteView raw)
		{
			return Detail::encode_impl(raw, [](int ch) -> bool { return !Detail::is_unreserved(ch); });
		}

		bool UseHttps() const { return m_UseHttps; }

		std::wstring const& GetFullUri() const { return m_FullUri; }
		std::wstring const& GetHostName() const { return m_HostName; }
		uint16_t GetPort() const { return m_Port; }
		bool IsPortDefault() const { return (m_UseHttps && m_Port == INTERNET_DEFAULT_HTTPS_PORT) || (!m_UseHttps && m_Port == INTERNET_DEFAULT_HTTP_PORT); }
		std::wstring const& GetPathWithQuery() const { return m_PathWithQuery; }

	private:
		Uri(bool useHttps, std::wstring hostName, uint16_t port, std::wstring pathWithQuery)
			: m_UseHttps{useHttps}
			, m_Port{port}
			, m_HostName{std::move(hostName)}
			, m_PathWithQuery{std::move(pathWithQuery)}
		{
		}

		bool m_UseHttps = false;
		uint16_t m_Port = 0;
		std::wstring m_FullUri;
		std::wstring m_HostName;
		std::wstring m_PathWithQuery;
	};
}

#pragma once

#include "HttpRequest.h"
#include "Handles/HttpSession.h"
#include "Handles/HttpConnection.h"
#include "Uri.h"

namespace FSecure::WinHttp
{
	/// HTTP client class with API simmilar to cpprestsdk's http_client
	class HttpClient
	{
	public:
		/// Create HTTP clinet
		/// @param uri - base or full uri
		/// @param proxy - proxy settings
		/// @throws std::runtime_error if underlying HTTP session fails
		HttpClient(Uri uri, WebProxy proxy = {})
			: m_ProxyConfig{std::move(proxy)}
			, m_Session{ m_ProxyConfig }
			, m_Uri(std::move(uri))
		{
			m_Connection = m_Session.Connect(m_Uri.GetHostName(), m_Uri.GetPort(), m_Uri.UseHttps());
		}

		/// Send HTTP request
		/// @param request - request to send
		/// @param content type - optional content type (override content type from `request`)
		/// @param data - optional request body (override request body from `request`)
		/// @returns HttpResponse
		/// @throws std::runtime_error
		HttpResponse Request(HttpRequest const& request, std::wstring const& contentType = {}, std::vector<uint8_t> const& data = {})
		{
			auto coalesce = [](auto&& opt1, auto&& defaultValue) { return !opt1.empty() ? opt1 : defaultValue; };
			auto const& path = coalesce(request.m_Path, m_Uri.GetPathWithQuery());
			auto req = m_Connection.OpenRequest(GetMethodString(request.m_Method), path);

			for (auto& [name, content] : request.m_Headers)
				req.SetHeader(name, content);

			if (auto proxy = m_Session.GetProxyForUrl(m_Uri))
				req.SetProxy(*proxy);

			auto const& xContentType = coalesce(request.m_ContentType, contentType);
			auto const& xData = coalesce(request.m_Data, data);
			req.Send(xContentType, xData);
			return req.ReceiveResponse();
		}

	private:
		WebProxy m_ProxyConfig;
		HttpSession m_Session;
		Uri m_Uri;
		HttpConnection m_Connection;
	};
}

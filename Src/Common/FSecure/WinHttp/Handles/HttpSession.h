#pragma once

#include "HttpHandle.h"
#include "HttpConnection.h"
#include "../WebProxy.h"
#include "ProxyHelpers.h"

#include <optional>
#include <cassert>

namespace FSecure::WinHttp
{
	/// RAII wrapper for session handle
	class HttpSession
	{
	public:

		/// Create a session handle
		/// Effectively calls WinHttpOpen
		/// @param proxy settings
		/// @throws std::runtime error if handle can't be aquired
		HttpSession(WebProxy const& proxy = {})
		{
			// This object have lifetime greater than proxy_name and proxy_bypass
			// which may point to its elements.
			Detail::IeProxyConfig proxyIE;

			DWORD access_type;
			LPCTSTR proxy_name = WINHTTP_NO_PROXY_NAME;
			LPCTSTR proxy_bypass = WINHTTP_NO_PROXY_BYPASS;
			m_ProxyAutoConfig = false;
			std::wstring proxy_str;
			Uri uri;
			if (proxy.IsDefault())
			{
				access_type = Detail::WinHttpDefaultProxyConstant();
			}
			else if (proxy.IsDisabled())
			{
				access_type = WINHTTP_ACCESS_TYPE_NO_PROXY;
			}
			else if (proxy.IsAutoDiscovery())
			{
				access_type = Detail::WinHttpDefaultProxyConstant();
				if (access_type != WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY)
				{
					// Windows 8 or earlier, do proxy autodetection ourselves
					m_ProxyAutoConfig = true;

					Detail::ProxyInfo proxyDefault;
					if (!WinHttpGetDefaultProxyConfiguration(&proxyDefault) ||
						proxyDefault.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY)
					{
						// ... then try to fall back on the default WinINET proxy, as
						// recommended for the desktop applications (if we're not
						// running under a user account, the function below will just
						// fail, so there is no real need to check for this explicitly)
						if (WinHttpGetIEProxyConfigForCurrentUser(&proxyIE))
						{
							if (proxyIE.fAutoDetect)
							{
								m_ProxyAutoConfig = true;
							}
							else if (proxyIE.lpszAutoConfigUrl)
							{
								m_ProxyAutoConfig = true;
								m_ProxyAutoConfigUrl = proxyIE.lpszAutoConfigUrl;
							}
							else if (proxyIE.lpszProxy)
							{
								access_type = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
								proxy_name = proxyIE.lpszProxy;

								if (proxyIE.lpszProxyBypass)
								{
									proxy_bypass = proxyIE.lpszProxyBypass;
								}
							}
						}
					}
				}
			}
			else
			{
				assert(proxy.IsSpecified());
				access_type = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
				// WinHttpOpen cannot handle trailing slash in the name, so here is some string gymnastics to keep
				// WinHttpOpen happy proxy_str is intentionally declared at the function level to avoid pointing to the
				// string in the destructed object
				uri = proxy.Address();
				if (uri.IsPortDefault())
				{
					proxy_name = uri.GetHostName().c_str();
				}
				else
				{
					proxy_str = uri.GetHostName();
					if (uri.GetPort() > 0)
					{
						proxy_str.push_back(L':');
						proxy_str.append(std::to_wstring(uri.GetPort()));
					}

					proxy_name = proxy_str.c_str();
				}
			}

			m_SessionHandle = MakeHttpHandle(WinHttpOpen(nullptr, access_type, proxy_name, proxy_bypass, 0), OBF("Session"));
		}


		/// Create a connection handle on default HTTPS/HTTP port
		/// Effectively calls WinHttpConnect
		/// @param hostName - hostname to create connection to
		/// @param useHttps - true if connection should use HTTPS, false for plain HTTP
		/// @returns HttpConnection handle
		/// @throws std::runtime error if handle can't be aquired
		HttpConnection Connect(std::wstring const& hostName, bool useHttps = true)
		{
			return HttpConnection(m_SessionHandle.get(), hostName, useHttps);
		}

		/// Create a connection handle on custom port
		/// Effectively calls WinHttpConnect
		/// @param hostName - hostname to create connection to
		/// @param port - port to connect to
		/// @param useHttps - true if connection should use HTTPS, false for plain HTTP
		/// @returns HttpConnection handle
		/// @throws std::runtime error if handle can't be aquired
		HttpConnection Connect(std::wstring const& hostName, uint16_t port, bool useHttps)
		{
			return HttpConnection(m_SessionHandle.get(), hostName, port, useHttps);
		}

		/// Try to resolve proxy using Proxy Auto Config (PAC) for given URL
		/// @param uri - URL to get proxy for
		/// @returns ProxyInfo if PAC is used, empty otherwise
		std::optional<Detail::ProxyInfo> GetProxyForUrl(Uri const& uri) noexcept
		{
			if (!m_ProxyAutoConfig)
				return {};

			WINHTTP_AUTOPROXY_OPTIONS autoproxy_options{};
			if (m_ProxyAutoConfigUrl.empty())
			{
				autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
				autoproxy_options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
			}
			else
			{
				autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
				autoproxy_options.lpszAutoConfigUrl = m_ProxyAutoConfigUrl.c_str();
			}

			autoproxy_options.fAutoLogonIfChallenged = TRUE;

			Detail::ProxyInfo info;
			if (!WinHttpGetProxyForUrl(m_SessionHandle.get(), uri.GetFullUri().c_str(), &autoproxy_options, &info))
				// Failure to download the auto-configuration script is not fatal. Fall back to the default proxy.
				return {};

			return info;
		}

	private:
		HttpHandle m_SessionHandle;
		bool m_ProxyAutoConfig;
		std::wstring m_ProxyAutoConfigUrl;
	};
}

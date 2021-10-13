#include "stdafx.h"
#include "DiscordApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"
#include <random>
#include <cctype>
#include <algorithm>

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

namespace
{
	std::wstring ToWideString(std::string const& str)
	{
		return Convert<Utf16>(str);
	}
}

FSecure::Discord::Discord(std::string const& userAgent, std::string const& token, std::string const& channelName, std::string const& guildId)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_Token = token;
	this->m_UserAgent = userAgent;
	this->m_guildId = guildId;
	std::string lowerChannelName = channelName;
	std::transform(lowerChannelName.begin(), lowerChannelName.end(), lowerChannelName.begin(), [](unsigned char c) { return std::tolower(c); });

	SetChannel(CreateChannel(lowerChannelName));
}

void FSecure::Discord::SetChannel(std::string const& channelId)
{
	this->m_channelId = channelId;
}

void FSecure::Discord::SetToken(std::string const& token)
{
	this->m_Token = token;
}

std::string FSecure::Discord::WriteMessage(std::string const& text)
{
	json j;
	j[OBF("content")] = text;
	std::string url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages");

	json output = SendJsonRequest(url, j, Method::POST);

	return output[OBF("id")].get<std::string>(); //return the timestamp so a reply can be viewed
}

std::map<std::string, std::string> FSecure::Discord::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	std::string url = OBF("https://discord.com/api/v9/guilds/") + this->m_guildId + OBF("/channels");

	json response = GetJsonResponse(url);

	for (auto& channel : response)
	{
		std::string cName = channel[OBF("name")];
		std::string cId = channel[OBF("id")].get<std::string>();
		channelMap.insert({ cName, cId });
	}

	return channelMap;
}

std::string FSecure::Discord::CreateChannel(std::string const& channelName)
{
	std::map<std::string, std::string> channels = this->ListChannels();

	if (channels.find(channelName) == channels.end())
	{
		std::string url = OBF("https://discord.com/api/v9/guilds/") + this->m_guildId + OBF("/channels");
	
		json j;
		j[OBF("name")] = channelName;
		j[OBF("type")] = 0; //text channel

		json response = SendJsonRequest(url, j, Method::POST);

		if (!response.contains(OBF("name")))
			throw std::runtime_error(OBF("Throwing exception: unable to create channel\n"));
		return response[OBF("id")];
	}
	return channels[channelName];
}

json FSecure::Discord::GetAllMessages()
{
	std::string url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages?limit=100");
	int retrieve_count = 100;
	int message_count;
	json all_messages;

	do {
		json messages = GetJsonResponse(url);
		message_count = (int)messages.size();
		if (message_count > 0) {
			for (auto& m : messages)
			{
				all_messages.emplace_back(m);
			}
			auto last_message_id = messages[message_count - 1][OBF("id")].get<std::string>();
			url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages?limit=100&before=") + last_message_id;
		}
	} while (message_count == retrieve_count); // if we're asking for up to 100 messages and we get back 100, we'll check for more.
	return all_messages;
}

void FSecure::Discord::UpdateMessage(std::string const& message, std::string const& messageId)
{
	std::string url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages/") + messageId;
	json j;
	j[OBF("content")] = message;

	SendJsonRequest(url, j, Method::PATCH);
}

void FSecure::Discord::WriteReply(std::string const& text, std::string const& messageId)
{
	assert(text.size() <= 2'000);
	std::string url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages");

	json j;
	j[OBF("message_reference")][OBF("message_id")] = messageId;
	j[OBF("content")] = text;

	SendJsonRequest(url, j, Method::POST);
}

void FSecure::Discord::DeleteMessage(std::string const& messageId)
{
	std::string url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages/") + messageId;
	SendHttpRequest(url, ContentType::ApplicationJson, {}, Method::DEL);
}

void FSecure::Discord::DeleteChannel()
{
	std::string url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId;
	SendHttpRequest(url, ContentType::ApplicationJson, {}, Method::DEL);
}

void FSecure::Discord::DeleteMessages(std::vector<std::string> const& replyIds)
{
	if (replyIds.size() == 1) // The bulk delete method requires at least two messages so use alternative API
		DeleteMessage(replyIds[0]);
	else
	{
		std::string delete_url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages/bulk-delete");
		json j;
		j[OBF("messages")];

		for (auto& id : replyIds)
		{
			if ((j[OBF("messages")].size() > 1) and (j[OBF("messages")].size() % 100 == 0)) {
				std::string data = j.dump();
				SendHttpRequest(delete_url, ContentType::ApplicationJson, { std::make_move_iterator(data.begin()), std::make_move_iterator(data.end()) }, Method::POST);
				j[OBF("messages")] = {};
			}
			j[OBF("messages")].emplace_back(id);
		}

		if (j[OBF("messages")].size() != 0) {
			std::string data = j.dump();
			SendHttpRequest(delete_url, ContentType::ApplicationJson, { std::make_move_iterator(data.begin()), std::make_move_iterator(data.end()) }, Method::POST);
		}
	}
}

void FSecure::Discord::DeleteAllMessages()
{
	std::string delete_url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages/bulk-delete");
	std::string url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages?limit=100");
	int retrieve_count = 100;
	int message_count;

	do {
		json j;
		auto& messages = GetJsonResponse(url);
		message_count = (int)messages.size();

		if (message_count > 0) {
			for (auto& m : messages)
			{
				j[OBF("messages")].emplace_back(m[OBF("id")]);
			}
			std::string data = j.dump();
			SendHttpRequest(delete_url, ContentType::ApplicationJson, { std::make_move_iterator(data.begin()), std::make_move_iterator(data.end()) }, Method::POST);

			auto last_message_id = messages[message_count - 1][OBF("id")].get<std::string>();
			url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages?limit=100&before=") + last_message_id;
		}
	} while (message_count == retrieve_count); // if we're asking for up to 100 messages and we get back 100, we'll check for more.
}


FSecure::ByteVector FSecure::Discord::SendHttpRequest(std::string const& host, ContentType contentType, std::vector<uint8_t> const& data, Method method) {
	return SendHttpRequest(host, GetContentType(contentType), data, method);
}


FSecure::ByteVector FSecure::Discord::SendHttpRequest(std::string const& host, std::wstring const& contentType, std::vector<uint8_t> const& data, Method method) {
	while (true) {
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request;
		request.m_Method = method;

		if (!data.empty()) {
			request.SetData(contentType, data);
		}

		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));
		request.SetHeader(Header::Authorization, OBF(L"Bot ") + ToWideString(this->m_Token));

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
			return resp.GetData();
		else if (resp.GetStatusCode() == StatusCode::NoContent)
			return {};
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests || resp.GetStatusCode() == StatusCode::Conflict)
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		else
			throw std::exception(OBF("[x] Non 200/201/429 HTTP Response\n"));
	}
}

json FSecure::Discord::SendJsonRequest(std::string const& url, json const& data, Method method) {

	if (data == NULL) {
		auto resp = json::parse(SendHttpRequest(url, ContentType::MultipartFormData, {}, method));
		return resp;
	}
	else {
		std::string j = data.dump();
		auto resp = json::parse(SendHttpRequest(url, ContentType::ApplicationJson, { std::make_move_iterator(j.begin()), std::make_move_iterator(j.end()) }, method));
		return resp;
	}
}

json FSecure::Discord::GetJsonResponse(std::string const& url)
{
	auto resp = json::parse(SendHttpRequest(url, ContentType::ApplicationJson, {}, Method::GET));
	return resp;
}

void FSecure::Discord::UploadFile(ByteView data, std::string const& messageId)
{
	std::string url = OBF("https://discord.com/api/v9/channels/") + this->m_channelId + OBF("/messages");

	json j;
	j[OBF("message_reference")][OBF("message_id")] = messageId;

	// Generating body
	std::string boundary = OBF("------WebKitFormBoundary") + Utils::GenerateRandomString(16); // Mimicking WebKit, generate random boundary string

	// Building the multipart body (prefix + attachment + suffix)
	std::vector<uint8_t> body;
	std::string bodyPrefix = OBF("\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"payload_json\"\r\n");
	bodyPrefix += OBF("Content-Type: application/json\r\n\r\n");
	bodyPrefix += j.dump();
	bodyPrefix += OBF("\r\n\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"file\"; filename=\"file.txt\"\r\n");
	bodyPrefix += OBF("Content-Type: application/octet-stream\r\n\r\n");

	body.insert(body.begin(), bodyPrefix.begin(), bodyPrefix.end()); // Insert the prefix
	body.insert(body.end(), data.begin(), data.end()); // Insert the attachment content
	std::string bodySuffix = OBF("\r\n");
	bodySuffix += OBF("--") + boundary + OBF("--") + OBF("\r\n");
	body.insert(body.end(), bodySuffix.begin(), bodySuffix.end()); // Insert the suffix

	std::string contentType = OBF("multipart/form-data; boundary=") + boundary;

	SendHttpRequest(url, ToWideString(contentType), body, Method::POST);
}


std::string FSecure::Discord::GetFile(std::string const& url)
{
	auto data = SendHttpRequest(url, ContentType::ApplicationOctetstream, {}, Method::GET);
	return { data.begin(), data.end() };
}


